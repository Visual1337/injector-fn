#pragma once
#include "interface.h"

typedef struct _IO_STATUS_BLOCK {
	union {
		NTSTATUS Status;
		PVOID    Pointer;
	};
	ULONG_PTR Information;
} IO_STATUS_BLOCK, * PIO_STATUS_BLOCK;

typedef
VOID
(NTAPI* PIO_APC_ROUTINE) (
	IN PVOID ApcContext,
	IN PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG Reserved
	);

extern "C" __int64 nt_device_io_control_file(
	HANDLE FileHandle,
	HANDLE Event,
	PIO_APC_ROUTINE
	ApcRoutine,
	PVOID ApcContext,
	PIO_STATUS_BLOCK IoStatusBlock,
	ULONG IoControlCode,
	PVOID InputBuffer,
	ULONG InputBufferLength,
	PVOID OutputBuffer,
	ULONG OutputBufferLength);

namespace comm
{
	static auto handle = HANDLE();
	static auto process_id = INT32();

	static auto initialize(INT32 process_id) -> bool
	{
		comm::handle = CreateFileA("\\\\.\\\{db4406e4-6860-4084-8162-99a9c8dd182d}", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if ((comm::handle == INVALID_HANDLE_VALUE))
			return false;

		comm::process_id = process_id;

		return true;
	}

	static auto get_base() -> uintptr_t
	{
		auto request = invoke_data();

		request.code = code_base;
		request.process_id = process_id;

		IO_STATUS_BLOCK block;
		nt_device_io_control_file( handle, nullptr, nullptr, nullptr, &block, ioctl_base, &request, sizeof(request), &request, sizeof(request));

		return (uintptr_t)request.address;
	}

	static auto read_memory(uintptr_t address, void* buffer, int size) -> bool
	{
		auto request = invoke_data();

		request.code = code_read;
		request.process_id = process_id;
		request.address = (ULONGLONG)address;
		request.buffer = (ULONGLONG)buffer;
		request.size = size;

		IO_STATUS_BLOCK block;
		nt_device_io_control_file(handle, nullptr, nullptr, nullptr, &block, ioctl_read, &request, sizeof(request), &request, sizeof(request));

		return request.result == status::success;
	}

	template <typename read_type>
	static auto read(uintptr_t address) -> read_type
	{
		read_type buffer{ };
		read_memory(address, &buffer, sizeof(read_type));

		return buffer;
	}

	static auto write_memory(uintptr_t address, void* buffer, int size) -> bool
	{
		auto request = invoke_data();

		request.code = code_write;
		request.process_id = process_id;
		request.address = (ULONGLONG)address;
		request.buffer = (ULONGLONG)buffer;
		request.size = size;

		IO_STATUS_BLOCK block;
		nt_device_io_control_file(handle, nullptr, nullptr, nullptr, &block, ioctl_write, &request, sizeof(request), &request, sizeof(request));

		return request.result == status::success;
	}

	template <typename write_type>
	static auto write(uintptr_t address, write_type value)
	{
		write_memory(address, &value, sizeof(write_type));
	}

	static auto allocate(uintptr_t start, int32_t size) -> uintptr_t
	{
		auto request = invoke_data();

		request.code = code_allocate;
		request.process_id = process_id;
		request.address = start;
		request.size = size;

		IO_STATUS_BLOCK block;
		nt_device_io_control_file(handle, nullptr, nullptr, nullptr, &block, ioctl_allocate, &request, sizeof(request), &request, sizeof(request));

		return (uintptr_t)request.address;
	}

	static auto free(uintptr_t address) -> void
	{
		auto request = invoke_data();

		request.code = code_free;
		request.process_id = process_id;
		request.address = address;

		IO_STATUS_BLOCK block;
		nt_device_io_control_file(handle, nullptr, nullptr, nullptr, &block, ioctl_free, &request, sizeof(request), &request, sizeof(request));
	}

	static auto swap_virtual_pointer(uintptr_t src, uintptr_t dst) -> uintptr_t
	{
		auto request = invoke_data();

		//address		= src
		//address_2		= dst
		//address_3		= old

		request.code = code_swap;
		request.process_id = process_id;
		request.address = src;
		request.address_2 = dst;

		IO_STATUS_BLOCK block;
		nt_device_io_control_file(handle, nullptr, nullptr, nullptr, &block, ioctl_swap, &request, sizeof(request), &request, sizeof(request));

		return request.address_3;
	}

	static auto query(uintptr_t address, uintptr_t* page_base, int32_t* page_protection, ULONG* page_size) -> void
	{
		auto request = invoke_data();

		request.code = code_query;
		request.process_id = process_id;
		request.address = address;

		IO_STATUS_BLOCK block;
		nt_device_io_control_file(handle, nullptr, nullptr, nullptr, &block, ioctl_query, &request, sizeof(request), &request, sizeof(request));

		if (page_base)
			*page_base = request.address_3;

		if (page_protection)
			*page_protection = request.protection;

		if (page_size)
			*page_size = request.size;
	}

	static auto scan_sig(uintptr_t module_address, std::string sig) -> uintptr_t
	{
		auto request = invoke_data();

		request.code = code_pattern;
		request.process_id = process_id;
		request.address = module_address;

		memset(request.signature, 0, sizeof(char) * 260);
		strcpy_s(request.signature, sig.c_str());

		IO_STATUS_BLOCK block;
		nt_device_io_control_file(handle, nullptr, nullptr, nullptr, &block, ioctl_pattern, &request, sizeof(request), &request, sizeof(request));

		return request.address_2;
	}

	static auto remove_vad(uintptr_t address) -> void
	{
		auto request = invoke_data();

		request.code = code_remove_node;
		request.process_id = process_id;
		request.address = address;

		IO_STATUS_BLOCK block;
		nt_device_io_control_file(handle, nullptr, nullptr, nullptr, &block, ioctl_remove_node, &request, sizeof(request), &request, sizeof(request));
	}

	static auto get_module_base(const char* module_name) -> uintptr_t
	{
		auto request = invoke_data();

		request.code = code_module;
		request.process_id = process_id;
		request.name = module_name;

		IO_STATUS_BLOCK block;
		nt_device_io_control_file(handle, nullptr, nullptr, nullptr, &block, ioctl_module, &request, sizeof(request), &request, sizeof(request));

		return request.address_2;
	}
}