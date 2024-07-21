#pragma once

#include <iostream>
#include <vector>
#include <fstream>
#include <windows.h>
#include <tlhelp32.h>

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

#include <comm/interface.h>
#include <comm/comm.h>