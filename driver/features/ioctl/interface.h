#pragma once

typedef struct _invoke_data
{
	INT32 code;
	INT32 process_id;
	INT32 protection;

	ULONGLONG address;
	ULONGLONG address_2;
	ULONGLONG address_3;
	ULONGLONG buffer;
	SIZE_T size;

	char signature[260];
	const char* name;

	status result = status::failure;
} invoke_data, * pinvoke_data;