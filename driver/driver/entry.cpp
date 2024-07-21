#include <driver/includes.h>

auto null_pfn(PMDL mdl) -> status
{
	PPFN_NUMBER mdl_pages = MmGetMdlPfnArray(mdl);
	if (!mdl_pages)
	{
		return status::failure;
	}

	ULONG mdl_page_count = ADDRESS_AND_SIZE_TO_SPAN_PAGES(MmGetMdlVirtualAddress(mdl), MmGetMdlByteCount(mdl));
	ULONG null_pfn = 0x0;

	MM_COPY_ADDRESS source_address = { 0 };
	source_address.VirtualAddress = &null_pfn;

	for (ULONG i = 0; i < mdl_page_count; i++)
	{
		size_t bytes = 0;
		imports::mm_copy_memory(&mdl_pages[i], source_address, sizeof(ULONG), MM_COPY_MEMORY_VIRTUAL, &bytes);
	}

	return status::success;
}

auto set_vad() -> status
{
	//mi_allocate_vad
	uintptr_t faddr = pattern::find_pattern((uintptr_t)ntoskrnl, "\x44\x8D\x42\x02\xE8\x00\x00\x00\x00\x48\x89\x43\x08", "xxxxx????xxxx");
	if (!faddr) return status::failure;

	faddr += 4;
	faddr = rva(faddr, 5);

	imports::mi_allocate_vad = (decltype(imports::mi_allocate_vad))faddr;

	//mi_insert_vad_charges
	faddr = pattern::find_pattern((uintptr_t)ntoskrnl, "\xE8\x00\x00\x00\x00\x8B\xF0\x85\xC0\x0F\x88\x00\x00\x00\x00\x48\x8B\xD3", "x????xxxxxx????xxx");
	if (!ntoskrnl) return status::failure;

	faddr = rva(faddr, 5);

	imports::mi_insert_vad_charges = (decltype(imports::mi_insert_vad_charges))faddr;

	//mi_insert_vad
	faddr = pattern::find_pattern((uintptr_t)ntoskrnl, "\xE8\x00\x00\x00\x00\x8B\x5B\x30", "x????xxx");
	if (!ntoskrnl) return status::failure;

	faddr = rva(faddr, 5);

	imports::mi_insert_vad = (decltype(imports::mi_insert_vad))faddr;

	return status::success;
}

auto entry_point(uintptr_t mdl, imports::m_imported imports) -> NTSTATUS
{
	imports::imported = imports;

	//if (null_pfn(reinterpret_cast<PMDL>(mdl)) != status::success)
	//	return status::failure;

	if (ioctl::define_modules() != status::success)
		return status::failure;

	//if (set_vad() != status::success)
	//	return status::failure;

	if (ioctl::initialize() != status::success)
		return status::failure;

	return status::success;
}