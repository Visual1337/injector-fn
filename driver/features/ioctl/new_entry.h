#pragma once

#include <features/copy_operation.h>
#include <features/memory_operation.h>
#include "interface.h"

#define code_base 0x370
#define code_read 0x371
#define code_write 0x372
#define code_remove_node 0x373
#define code_free 0x374
#define code_pattern 0x375
#define code_allocate 0x376
#define code_swap 0x377
#define code_query 0x378
#define code_module 0x379

#define ioctl_base CTL_CODE(FILE_DEVICE_UNKNOWN, code_base, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_read CTL_CODE(FILE_DEVICE_UNKNOWN, code_read, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_write CTL_CODE(FILE_DEVICE_UNKNOWN, code_write, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_remove_node CTL_CODE(FILE_DEVICE_UNKNOWN, code_remove_node, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_free CTL_CODE(FILE_DEVICE_UNKNOWN, code_free, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_pattern CTL_CODE(FILE_DEVICE_UNKNOWN, code_pattern, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_allocate CTL_CODE(FILE_DEVICE_UNKNOWN, code_allocate, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_swap CTL_CODE(FILE_DEVICE_UNKNOWN, code_swap, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_query CTL_CODE(FILE_DEVICE_UNKNOWN, code_query, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define ioctl_module CTL_CODE(FILE_DEVICE_UNKNOWN, code_module, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

namespace ioctl
{
	auto io_dispatch(PDEVICE_OBJECT device_object, PIRP irp) -> NTSTATUS
	{
		UNREFERENCED_PARAMETER(device_object);

		auto invoke_buffer = reinterpret_cast<pinvoke_data>(irp->AssociatedIrp.SystemBuffer);

		switch (invoke_buffer->code)
		{
		case code_base:
		{
			irp->IoStatus.Status = features::get_base_address(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		case code_read:
		{
			irp->IoStatus.Status = features::read_memory(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		case code_write:
		{
			irp->IoStatus.Status = features::write_memory(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		case code_allocate:
		{
			irp->IoStatus.Status = features::allocate_memory(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		case code_free: //testing
		{
			irp->IoStatus.Status = features::free_memory(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		case code_swap:
		{
			irp->IoStatus.Status = features::swap_virtual(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		case code_query:
		{
			irp->IoStatus.Status = features::query_memory(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		case code_pattern:
		{
			irp->IoStatus.Status = features::scan_signature(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		case code_remove_node: //testing
		{
			irp->IoStatus.Status = features::remove_node_fn(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		case code_module:
		{
			irp->IoStatus.Status = features::get_module_base(invoke_buffer);
			irp->IoStatus.Information = sizeof(invoke_data);

			break;
		}
		}

		irp->IoStatus.Status = status::success;
		imports::iof_complete_request(irp, IO_NO_INCREMENT);

		return irp->IoStatus.Status;
	}

	auto io_close(PDEVICE_OBJECT, PIRP Irp) -> NTSTATUS
	{
		Irp->IoStatus.Status = status::success;
		Irp->IoStatus.Information = 0;

		imports::iof_complete_request(Irp, IO_NO_INCREMENT);
		return status::success;
	}

	auto new_entry_point(PDRIVER_OBJECT driver_obj, PUNICODE_STRING registry_path) -> NTSTATUS
	{
		UNREFERENCED_PARAMETER(registry_path);

		//since new_entry_point is already called by now, we can re-use our shellcode in the cave for our io dispatch (yay!)
		*(void**)&shellcode[3] = reinterpret_cast<void*>(&io_dispatch);
		util::write_protected_address((void*)cave_address, shellcode, sizeof(shellcode), TRUE);

		//writing a second shellcode right behind the first (and reused) one (for CREATE_CLOSE)
		*(void**)&shellcode[3] = reinterpret_cast<void*>(&io_close);
		util::write_protected_address((void*)(cave_address + sizeof(shellcode)), shellcode, sizeof(shellcode), TRUE);

		//initialize ioctl device names
		UNICODE_STRING device, dos_device;
		imports::rtl_init_unicode_string(&device, L"\\Device\\Wampus");
		imports::rtl_init_unicode_string(&dos_device, L"\\DosDevices\\Wampus");

		//initialize ioctl device
		PDEVICE_OBJECT device_object = nullptr;
		imports::io_create_device(driver_obj, 0, &device, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &device_object);

		SetFlag(driver_obj->Flags, DO_BUFFERED_IO);

		//define ioctl functions
		driver_obj->MajorFunction[IRP_MJ_CREATE] = reinterpret_cast<PDRIVER_DISPATCH>(cave_address + sizeof(shellcode)); //second shellcode
		driver_obj->MajorFunction[IRP_MJ_CLOSE] = reinterpret_cast<PDRIVER_DISPATCH>(cave_address + sizeof(shellcode)); //second shellcode (same as above)
		driver_obj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = reinterpret_cast<PDRIVER_DISPATCH>(cave_address); //first shellcode
		driver_obj->DriverUnload = nullptr; //no unload function :P

		ClearFlag(device_object->Flags, DO_DIRECT_IO);
		ClearFlag(device_object->Flags, DO_DEVICE_INITIALIZING);

		//finally link the driver
		imports::io_create_symbolic_link(&dos_device, &device);

		return status::success;
	}

	auto define_modules() -> status
	{
		ntoskrnl = util::get_ntoskrnl();
		if (!ntoskrnl) return status::failure;

		base = util::get_kernel_image("HDAudBus.sys");
		if (!base) return status::failure;

		win32kbase = util::get_kernel_image("win32kbase.sys");
		if (!win32kbase) return status::failure;

		win32kfull = util::get_kernel_image("win32kfull.sys");
		if (!win32kfull) return status::failure;

		return status::success;
	}

	auto initialize() -> status
	{
		cave_address = uintptr_t(base) + 0x11865 + 0x5;

		//pass new entry point address into shellcode
		*(void**)&shellcode[3] = reinterpret_cast<void*>(new_entry_point);

		//write shellcode to code cave
		util::write_protected_address((void*)cave_address, shellcode, sizeof(shellcode), true);

		//create driver (init address = written shellcode address)
		imports::io_create_driver(NULL, reinterpret_cast<PDRIVER_INITIALIZE>(cave_address));

		return status::success;
	}
}