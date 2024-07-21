#pragma once

namespace features
{
	auto allocate_memory(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		uintptr_t start = data->address;
		uintptr_t end = start + data->size;

		auto o_process = customs::attach_process((uintptr_t)process);

		MEMORY_BASIC_INFORMATION mbi;
		if (imports::zw_query_virtual_memory(ZwCurrentProcess(), (PVOID)start, MemoryBasicInformation, &mbi, sizeof(mbi), 0) != status::success)
		{
			customs::attach_process(o_process);
			imports::obf_dereference_object(process);

			return status::failure;
		}

		PMMVAD_SHORT vad = imports::mi_allocate_vad(start, end, 1);
		if (!vad)
		{
			customs::attach_process(o_process);
			imports::obf_dereference_object(process);

			data->address = 0;

			return status::failure;
		}

		PMMVAD_FLAGS flags = (PMMVAD_FLAGS)&vad->u.LongFlags;
		flags->Protection = MM_EXECUTE_READWRITE;
		flags->NoChange = 0;

		if (imports::mi_insert_vad_charges(vad, process) != status::success)
		{
			customs::attach_process(o_process);
			imports::obf_dereference_object(process);

			imports::ex_free_pool_with_tag(vad, NULL);

			data->address = 0;

			return status::failure;
		}

		imports::mi_insert_vad(vad, process);

		customs::attach_process(o_process);
		imports::obf_dereference_object(process);

		data->address = start;

		return status::success;
	}

	auto query_memory(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		auto o_process = customs::attach_process((uintptr_t)process);

		MEMORY_BASIC_INFORMATION mbi;
		imports::zw_query_virtual_memory(ZwCurrentProcess(), (PVOID)data->address, MemoryBasicInformation, &mbi, sizeof(mbi), 0);

		customs::attach_process(o_process);
		imports::obf_dereference_object(process);

		data->address_3 = (uintptr_t)mbi.BaseAddress;
		data->protection = mbi.Protect;
		data->size = mbi.RegionSize;

		return status::success;
	}

	auto free_memory(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		//auto o_process = customs::attach_process((uintptr_t)process);

		SIZE_T size = 0;
		PVOID address = (PVOID)data->address;
		imports::zw_free_virtual_memory(ZwCurrentProcess(), &address, &size, MEM_RELEASE);

		//customs::attach_process(o_process);
		imports::obf_dereference_object(process);

		return status::success;
	}

	auto swap_virtual(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		auto o_process = customs::attach_process((uintptr_t)process);

		uintptr_t old = 0;
		*(void**)&old = InterlockedExchangePointer((void**)data->address, (void*)data->address_2);

		customs::attach_process((uintptr_t)o_process);
		imports::obf_dereference_object(process);

		if (!old)
		{
			return status::failure;
		}

		data->address_3 = old;

		return status::success;
	}

	auto scan_signature(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		auto o_process = customs::attach_process((uintptr_t)process);

		auto address = pattern::find_pattern(data->address, data->signature);

		if (!address)
		{
			customs::attach_process(o_process);
			imports::obf_dereference_object(process);

			return status::failure;
		}

		customs::attach_process(o_process);
		imports::obf_dereference_object(process);

		data->address_2 = address;

		return status::success;
	}

	auto remove_node_fn(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		PMMVAD_SHORT vad_short = NULL;
		PMM_AVL_TABLE table = (PMM_AVL_TABLE)((PUCHAR)process + 0x7D8);

		customs::find_vad(process, data->address, &vad_short);
		imports::rtl_avl_remove_node(table, reinterpret_cast<PMMADDRESS_NODE>(vad_short));

		imports::obf_dereference_object(process);

		return status::success;
	}

	auto get_module_base(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		ANSI_STRING ansi_name;
		imports::rtl_init_ansi_string(&ansi_name, data->name);

		UNICODE_STRING compare_name;
		imports::rtl_ansi_string_to_unicode_string(&compare_name, &ansi_name, TRUE);

		auto o_process = customs::attach_process((uintptr_t)process);

		PPEB pPeb = imports::ps_get_process_peb(process);

		if (pPeb)
		{
			PPEB_LDR_DATA pLdr = (PPEB_LDR_DATA)pPeb->Ldr;

			if (pLdr)
			{
				for (PLIST_ENTRY listEntry = (PLIST_ENTRY)pLdr->ModuleListLoadOrder.Flink;
					listEntry != &pLdr->ModuleListLoadOrder;
					listEntry = (PLIST_ENTRY)listEntry->Flink) {

					PLDR_DATA_TABLE_ENTRY pEntry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

					if (imports::rtl_compare_unicode_string(&pEntry->BaseDllName, &compare_name, TRUE) == 0)
					{
						data->address_2 = (uintptr_t)pEntry->DllBase;
						break;
					}
				}
			}
		}

		customs::attach_process(o_process);

		imports::rtl_free_unicode_string(&compare_name);
		imports::obf_dereference_object(process);

		return status::success;
	}
}