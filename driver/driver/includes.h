#pragma once

#include <intrin.h>
#include <ntifs.h>
#include <ntddk.h>
#include <IntSafe.h>
#include <ntimage.h>
#include <ntdef.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <wdm.h>

#include <customs/structs.h>
#include <customs/imports.h>
#include <customs/customs.h>
#include <customs/pattern_scan.h>
#include <customs/util.h>

/*
nop
mov rax, 0xDEADBEEFCAFEBABE
jmp rax
*/
BYTE shellcode[] = { 0x90, 0x48, 0xB8, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0xFF, 0xE0 };

uintptr_t cave_address;

PVOID base, ntoskrnl, win32kbase, win32kfull;

using namespace customs;

#include <features/ioctl/interface.h>
#include <features/ioctl/new_entry.h>