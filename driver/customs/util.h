#pragma once

namespace customs
{
	namespace util
	{
		auto get_kernel_image(const char* module_name) -> PVOID
		{
			auto addr = PVOID(0);
			auto bytes = ULONG(0);

			auto status = imports::zw_query_system_information(SystemModuleInformation, NULL, bytes, &bytes);
			if (!bytes) return NULL;

			auto modules = (PSYSTEM_MODULE_INFORMATION)imports::ex_allocate_pool(NonPagedPool, bytes);

			status = imports::zw_query_system_information(SystemModuleInformation, modules, bytes, &bytes);
			if (!NT_SUCCESS(status)) return NULL;

			for (ULONG i = 0; i < modules->NumberOfModules; i++)
			{
				SYSTEM_MODULE m = modules->Modules[i];

				if (kstrstr((char*)((PCHAR)m.FullPathName), module_name))
				{
					addr = m.ImageBase;
					break;
				}
			}

			if (modules) ExFreePool(modules);
			if (addr <= NULL) return NULL;

			return addr;
		}

		auto relative_address(PVOID instruction, ULONG offsetoffset, ULONG instructionsize) -> PVOID
		{
			ULONG_PTR Instr = (ULONG_PTR)instruction;

			LONG RipOffset = *(PLONG)(Instr + offsetoffset);
			PVOID ResolvedAddr = (PVOID)(Instr + instructionsize + RipOffset);

			return ResolvedAddr;
		}

		auto get_ntoskrnl() -> PVOID
		{
			typedef unsigned char uint8_t;

			auto Idt_base = reinterpret_cast<uintptr_t>(KeGetPcr()->IdtBase);
			auto align_page = *reinterpret_cast<uintptr_t*>(Idt_base + 4) >> 0xc << 0xc;

			for (; align_page; align_page -= PAGE_SIZE)
			{
				for (int index = 0; index < PAGE_SIZE - 0x7; index++)
				{
					auto current_address = static_cast<intptr_t>(align_page) + index;

					if (*reinterpret_cast<uint8_t*>(current_address) == 0x48
						&& *reinterpret_cast<uint8_t*>(current_address + 1) == 0x8D
						&& *reinterpret_cast<uint8_t*>(current_address + 2) == 0x1D
						&& *reinterpret_cast<uint8_t*>(current_address + 6) == 0xFF) 
					{
						PVOID Ntosbase = relative_address((PVOID)current_address, 3, 7);
						if (!((UINT64)Ntosbase & 0xfff))
						{
							return (PVOID)Ntosbase;
						}
					}
				}
			}
			return NULL;
		}

		auto write_protected_address(void* address, void* buffer, SIZE_T size, bool Restore) -> BOOLEAN
		{
			NTSTATUS Status = { STATUS_SUCCESS };
			
			auto Mdl = imports::io_allocate_mdl(address, size, FALSE, FALSE, NULL);
			imports::mm_probe_and_lock_pages(Mdl, KernelMode, IoReadAccess);
			auto Mapping = imports::mm_map_locked_pages_specify_cache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);

			Status = imports::mm_protect_mdl_system_address(Mdl, PAGE_READWRITE);
			if (Status != STATUS_SUCCESS)
			{
				imports::mm_unmap_locked_pages(Mapping, Mdl);
				imports::mm_unlock_pages(Mdl);
				imports::io_free_mdl(Mdl);
			}

			kmemcpy(Mapping, buffer, size);

			if (Restore)
			{
				Status = imports::mm_protect_mdl_system_address(Mdl, PAGE_READONLY);
				if (Status != STATUS_SUCCESS)
				{
					imports::mm_unmap_locked_pages(Mapping, Mdl);
					imports::mm_unlock_pages(Mdl);
					imports::io_free_mdl(Mdl);
				}
			}

			imports::mm_unmap_locked_pages(Mapping, Mdl);
			imports::mm_unlock_pages(Mdl);
			imports::io_free_mdl(Mdl);

			return Status;
		}
	}
}