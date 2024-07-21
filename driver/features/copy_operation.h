#pragma once

namespace features
{
	static auto get_base_address(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		auto base = reinterpret_cast<ULONGLONG>(imports::ps_get_process_section_base_address(process));
		if (!base)
		{
			imports::obf_dereference_object(process);

			return status::failure;
		}

		data->address = base;

		imports::obf_dereference_object(process);

		return status::success;
	}

	static auto read_memory(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		SIZE_T bytes = 0;
		if (imports::mm_copy_virtual_memory(process, (void*)data->address, imports::io_get_current_process(), (void*)data->buffer, data->size, UserMode, &bytes) != status::success || bytes != data->size)
		{
			data->result = status::failure;

			imports::obf_dereference_object(process);

			return status::failure;
		}

		data->result = status::success;

		imports::obf_dereference_object(process);

		return status::success;
	}

	static auto write_memory(pinvoke_data data) -> status
	{
		auto process = PEPROCESS();
		imports::ps_lookup_process_by_process_id((HANDLE)data->process_id, &process);

		SIZE_T bytes = 0;
		if (imports::mm_copy_virtual_memory(imports::io_get_current_process(), (void*)data->buffer, process, (void*)data->address, data->size, UserMode, &bytes) != status::success || bytes != data->size)
		{
			data->result = status::failure;

			imports::obf_dereference_object(process);

			return status::failure;
		}

		data->result = status::success;

		imports::obf_dereference_object(process);

		return status::success;
	}
}