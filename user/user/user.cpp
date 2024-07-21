#include "includes.h"
#include "../comm/comm.h"

namespace dll
{
	auto get_nt_headers(const std::uintptr_t image_base) -> IMAGE_NT_HEADERS*
	{
		const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*> (image_base);

		return reinterpret_cast<IMAGE_NT_HEADERS*> (image_base + dos_header->e_lfanew);
	}
}

namespace rwx
{
	_declspec(noinline) auto rva_va(ULONGLONG RVA, PIMAGE_NT_HEADERS nt_header, PVOID LocalImage) -> PVOID
	{

		PIMAGE_SECTION_HEADER pFirstSect = IMAGE_FIRST_SECTION(nt_header);
		for (PIMAGE_SECTION_HEADER pSection = pFirstSect; pSection < pFirstSect + nt_header->FileHeader.NumberOfSections; pSection++)
		{
			if (RVA >= pSection->VirtualAddress && RVA < pSection->VirtualAddress + pSection->Misc.VirtualSize)
			{
				return (PUCHAR)LocalImage + pSection->PointerToRawData + (RVA - pSection->VirtualAddress);
			}
		}
		return NULL;
	}

	_declspec(noinline) auto TranslateRawSection(PIMAGE_NT_HEADERS nt, DWORD rva) -> PIMAGE_SECTION_HEADER
	{
		auto section = IMAGE_FIRST_SECTION(nt);
		for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
			if (rva >= section->VirtualAddress && rva < section->VirtualAddress + section->Misc.VirtualSize) {
				return section;
			}
		}
		return NULL;
	}

	_declspec(noinline) auto TranslateRaw(PBYTE base, PIMAGE_NT_HEADERS nt, DWORD rva) -> PVOID
	{
		auto section = TranslateRawSection(nt, rva);
		if (!section) {
			return NULL;
		}

		return base + section->PointerToRawData + (rva - section->VirtualAddress);
	}

	_declspec(noinline) auto resolve_free_function(LPCSTR ModName, LPCSTR ModFunc) -> ULONGLONG
	{
		HMODULE hModule = LoadLibraryExA(ModName, NULL, DONT_RESOLVE_DLL_REFERENCES);

		ULONGLONG FuncOffset = (ULONGLONG)GetProcAddress(hModule, ModFunc);

		FuncOffset -= (ULONGLONG)hModule;

		FreeLibrary(hModule);

		return FuncOffset;
	}

	_declspec(noinline) auto relocation(PBYTE pRemoteImg, PBYTE pLocalImg, PIMAGE_NT_HEADERS nt_header) -> bool
	{
		auto& baseRelocDir = nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
		if (!baseRelocDir.VirtualAddress) return false;

		auto reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(TranslateRaw(pLocalImg, nt_header, baseRelocDir.VirtualAddress));
		if (!reloc) return false;

		for (auto currentSize = 0UL; currentSize < baseRelocDir.Size; ) {
			auto relocCount = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			auto relocData = reinterpret_cast<PWORD>(reinterpret_cast<PBYTE>(reloc) + sizeof(IMAGE_BASE_RELOCATION));
			auto relocBase = reinterpret_cast<PBYTE>(TranslateRaw(pLocalImg, nt_header, reloc->VirtualAddress));

			for (auto i = 0UL; i < relocCount; ++i, ++relocData) {
				auto data = *relocData;
				auto type = data >> 12;
				auto offset = data & 0xFFF;

				if (type == IMAGE_REL_BASED_DIR64) {
					*reinterpret_cast<PBYTE*>(relocBase + offset) += (pRemoteImg - reinterpret_cast<PBYTE>(nt_header->OptionalHeader.ImageBase));
				}
			}

			currentSize += reloc->SizeOfBlock;
			reloc = reinterpret_cast<PIMAGE_BASE_RELOCATION>(relocData);
		}

		return TRUE;
	}

	_declspec(noinline) auto write_sections(PVOID pModuleBase, PVOID LocalImage, PIMAGE_NT_HEADERS NtHead) -> bool
	{
		auto section = IMAGE_FIRST_SECTION(NtHead);
		for (auto i = 0; i < NtHead->FileHeader.NumberOfSections; ++i, ++section) {
			auto sectionSize = min(section->SizeOfRawData, section->Misc.VirtualSize);
			if (!sectionSize) {
				continue;
			}

			auto mappedSection = (ULONGLONG)pModuleBase + section->VirtualAddress;
			auto mappedSectionBuffer = (PVOID)((ULONGLONG)LocalImage + section->PointerToRawData);

			comm::write_memory((const uintptr_t)mappedSection, mappedSectionBuffer, sectionSize);
		}

		return true;
	}


	_declspec(noinline) auto imports(PVOID pLocalImg, PIMAGE_NT_HEADERS NtHead) -> bool
	{
		PIMAGE_IMPORT_DESCRIPTOR ImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)rva_va(NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, NtHead, pLocalImg);

		if (!NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !NtHead->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size) \
			return true;

		LPSTR ModuleName = NULL;
		while ((ModuleName = (LPSTR)rva_va(ImportDesc->Name, NtHead, pLocalImg)))
		{
			uintptr_t BaseImage = (uintptr_t)LoadLibraryA(ModuleName);

			if (!BaseImage)
				return false;

			PIMAGE_THUNK_DATA IhData = (PIMAGE_THUNK_DATA)rva_va(ImportDesc->FirstThunk, NtHead, pLocalImg);

			while (IhData->u1.AddressOfData)
			{
				if (IhData->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					IhData->u1.Function = BaseImage + resolve_free_function(ModuleName, (LPCSTR)(IhData->u1.Ordinal & 0xFFFF));

				else
				{
					IMAGE_IMPORT_BY_NAME* IBN = (PIMAGE_IMPORT_BY_NAME)rva_va(IhData->u1.AddressOfData, NtHead, pLocalImg);
					IhData->u1.Function = BaseImage + resolve_free_function(ModuleName, (LPCSTR)IBN->Name);
				} IhData++;

			} ImportDesc++;

		}

		return true;
	}
}

namespace thread
{
	typedef struct _CLIENT_ID_N
	{
		HANDLE UniqueProcess;
		HANDLE UniqueThread;
	} CLIENT_ID_N;

	typedef struct _THREAD_BASIC_INFORMATION
	{
		NTSTATUS ExitStatus;
		PVOID TebBaseAddress;
		CLIENT_ID_N ClientId;
		KAFFINITY AffinityMask;
		LONG Priority;
		LONG BasePriority;
	} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

	std::vector<ULONG> WalkProcessThreads(ULONG ProcessId)
	{
		std::vector<ULONG> ThreadIds{};
		THREADENTRY32 TE32;

		HANDLE Handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
		if (Handle == INVALID_HANDLE_VALUE)
			return {};

		TE32.dwSize = sizeof(THREADENTRY32);
		if (!Thread32First(Handle, &TE32))
		{
			CloseHandle(Handle);
			return {};
		}

		do
		{
			if (TE32.th32OwnerProcessID == ProcessId)
			{
				ThreadIds.push_back(TE32.th32ThreadID);
			}
		} while (Thread32Next(Handle, &TE32));

		CloseHandle(Handle);

		return ThreadIds;
	}

	PVOID get_last_thread_stack(int pid)
	{
		std::vector<PVOID> ThreadStacks{};

		typedef NTSTATUS(NTAPI* _NtQueryInformationThread) (
			HANDLE ThreadHandle,
			ULONG ThreadInformationClass,
			PVOID ThreadInformation,
			ULONG ThreadInformationLength,
			PULONG ReturnLength
			);
		_NtQueryInformationThread NtQueryInformationThread = (_NtQueryInformationThread)GetProcAddress(LoadLibraryW(L"ntdll.dll"), "NtQueryInformationThread");

		std::vector<ULONG> ThreadIds = WalkProcessThreads(pid);
		for (ULONG ThreadId : ThreadIds)
		{
			THREAD_BASIC_INFORMATION TBI;
			NT_TIB TIB;

			HANDLE Handle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, ThreadId);
			NtQueryInformationThread(Handle, 0x0, &TBI, sizeof(THREAD_BASIC_INFORMATION), NULL);
			comm::read_memory((uintptr_t)TBI.TebBaseAddress, &TIB, sizeof(TIB));

			ThreadStacks.push_back(TIB.StackLimit);
		}

		PVOID LastThreadStack = 0;
		for (UINT i = 0; i < ThreadStacks.size(); i++)
		{
			if (ThreadStacks[i] > LastThreadStack)
				LastThreadStack = ThreadStacks[i];
		}

		ULONG qm_region_size = 0;

		uintptr_t out_qm_nigger;
		comm::query((uintptr_t)LastThreadStack, &out_qm_nigger, NULL, &qm_region_size);

		return (PVOID)((ULONGLONG)out_qm_nigger + qm_region_size);
	}
}

namespace process
{
	auto get_process_id(std::wstring name) -> int
	{
		const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

		PROCESSENTRY32 entry{ };
		entry.dwSize = sizeof(PROCESSENTRY32);

		Process32First(snapshot, &entry);
		do
		{
			if (!name.compare(entry.szExeFile))
			{
				return entry.th32ProcessID;
			}

		} while (Process32Next(snapshot, &entry));

		return 0;
	}

	auto read_file_to_bytes(const std::string filename) -> std::vector<uint8_t>
	{
		std::ifstream stream(filename, std::ios::binary);

		std::vector<uint8_t> buffer{ };

		buffer.assign((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

		stream.close();

		return buffer;
	}
}

namespace inj
{
	uint8_t remote_loader_shellcode[] = {
				0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x39,
				0xFF, 0x90, 0x39, 0xC0, 0x90, 0x48, 0x89, 0x44,
				0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x83,
				0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24,
				0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48,
				0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40, 0x08,
				0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0,
				0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44,
				0x24, 0x20, 0x48, 0x8B, 0x48, 0x10, 0xFF, 0x54,
				0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7,
				0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4,
				0x38, 0xC3, 0x48, 0x39, 0xC0, 0x90, 0xCC
	};

	struct payload_data
	{
		int32_t status;
		uintptr_t dll_main;
		uintptr_t a1;
		uint32_t a2;
		uintptr_t a3;
	};

	typedef struct _remote_dll
	{
		INT status;
		uintptr_t dll_main_address;
		HINSTANCE dll_base;
	} remote_dll, * premote_dll;
}

static auto inject(int process_id, uintptr_t fortnite_module, uintptr_t discord_module, void* dll_buffer) -> bool
{
	auto dll_header = dll::get_nt_headers(uintptr_t(dll_buffer));
	if (!dll_header) return false;

	auto loader_size = sizeof(inj::remote_loader_shellcode) + sizeof(inj::payload_data);
	if (!loader_size) return false;

	auto allocation_base = uintptr_t(thread::get_last_thread_stack(process_id));
	if (!allocation_base) return false;

	allocation_base = comm::allocate(allocation_base, dll_header->OptionalHeader.SizeOfImage + loader_size);
	if (!allocation_base) return false;

	auto relocation_success = rwx::relocation(PBYTE(allocation_base), reinterpret_cast<PBYTE>(dll_buffer), dll_header);
	if (!relocation_success) return false;

	auto imports_success = rwx::imports(reinterpret_cast<PVOID>(dll_buffer), dll_header);
	if (!imports_success) return false;

	bool sections_success = rwx::write_sections(PVOID(allocation_base), reinterpret_cast<PVOID>(dll_buffer), dll_header);
	if (!sections_success) return false;

	auto ldr_mdl = uintptr_t(0x0);
	auto ldr_address = uintptr_t(allocation_base + dll_header->OptionalHeader.SizeOfImage);
	auto ldr_data_ptr = uintptr_t(ldr_address + sizeof(inj::remote_loader_shellcode));

	memcpy(inj::remote_loader_shellcode + 0x6, &ldr_data_ptr, sizeof(uintptr_t));

	inj::payload_data ldr;
	ldr.status = 0; //LOADER_STATUS_EXPIRED
	ldr.dll_main = (decltype(ldr.dll_main))(allocation_base + dll_header->OptionalHeader.AddressOfEntryPoint);
	ldr.a1 = fortnite_module;

	bool data_success = comm::write_memory(ldr_data_ptr, &ldr, sizeof(ldr));
	if (!data_success)
	{
		comm::free(allocation_base);

		return false;
	}

	bool shellcode_success = comm::write_memory(ldr_address, inj::remote_loader_shellcode, sizeof(inj::remote_loader_shellcode));
	if (!shellcode_success)
	{
		comm::free(allocation_base);

		return false;
	}

	auto present_address = discord_module + discord_module;
	auto old_pointer = comm::swap_virtual_pointer(present_address, ldr_address);

	int count = 0;

	do
	{
		if (!comm::read_memory(ldr_data_ptr, &ldr, sizeof(inj::payload_data)))
		{
			count++;

			if (count >= 8)
			{
				break;
			}
		}
	} while (ldr.status != 2); //LOADER_STATUS_EXECUTE

	printf("\n[+] Received response from dllmain");

	comm::swap_virtual_pointer(present_address, old_pointer);

	Sleep(2000);

	comm::free(ldr_address);
	comm::remove_vad(allocation_base);

	VirtualFree(reinterpret_cast<PVOID>(dll_buffer), 0x0, MEM_RELEASE);

	ldr_mdl = 0x0;
	ldr_address = 0x0;
	present_address = 0x0;
	old_pointer = 0x0;
	ldr_data_ptr = 0x0;

	printf("\n[+] Cleaned up");

	return true;
}

int main()
{
	SetConsoleTitleA("Injector");
	printf("Injecting!\n");

	int process_id = process::get_process_id(L"FortniteClient-Win64-Shipping.exe");
	if (!process_id)
	{
		printf("\n[-] Failed to find FortniteClient-Win64-Shipping.exe");
		Sleep(-1);
	}
	printf("ProcessID: %i\n", process_id);

	if (!comm::initialize(process_id))
	{
		printf("\n[-] Failed to initialize the driver, target pid: %d", (int)process_id);
		Sleep(-1);
	}

	auto dll = process::read_file_to_bytes("cheat.dll");
	if (!dll.data())
	{
		printf("\n[-] Failed to read our dll: cheat.dll");
		Sleep(-1);
	}

	auto fortnite_module = comm::get_base();
	if (!fortnite_module)
	{
		printf("\n[-] Failed to find fortnite module");
		Sleep(-1);
	}

	auto discord_module = comm::get_module_base("DiscordHook64.dll");
	if (!discord_module)
	{
		printf("\n[-] Failed to find discord module");
		Sleep(-1);
	}

	printf("\n[+] FortniteClient-Win64-Shipping.exe : 0x%p", (void*)fortnite_module);
	printf("\n[+] DiscordHook64.dll : 0x%p", (void*)discord_module);
	printf("\n[+] cheat.dll (size): %d", (int)dll.size());
	Sleep(1500);

	printf("\n[-] Injecting...");

	if (!inject(process_id, fortnite_module, discord_module, dll.data()))
	{
		printf("\n[-] Failed to inject");
		Sleep(-1);
	}

	printf("\n[+] Injected successfully!");
	Sleep(-1);

	return 1;

	