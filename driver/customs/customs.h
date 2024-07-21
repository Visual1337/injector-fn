#pragma once

namespace customs
{
	enum status : int
	{
		success = STATUS_SUCCESS,
		failure = STATUS_UNSUCCESSFUL
	};

	auto attach_process(uintptr_t process) -> uintptr_t
	{
		auto current_thread = (uintptr_t)imports::ke_get_current_thread();
		if (!current_thread)
			return 0;

		auto apc_state = *(uintptr_t*)(current_thread + 0x98);
		auto old_process = *(uintptr_t*)(apc_state + 0x20);
		*(uintptr_t*)(apc_state + 0x20) = process;

		auto dir_table_base = *(uintptr_t*)(process + 0x28);
		__writecr3(dir_table_base);

		return old_process;
	}

	auto mi_find_node_or_parent(IN PMM_AVL_TABLE table, ULONG_PTR starting_vpn, PMMADDRESS_NODE* node_or_parent) -> TABLE_SEARCH_RESULT
	{
		PMMADDRESS_NODE child;
		PMMADDRESS_NODE node_to_examine;
		PMMVAD_SHORT    vpn_compare;
		ULONG_PTR       start_vpn;
		ULONG_PTR       end_vpn;

		if (table->NumberGenericTableElements == 0)
			return TableEmptyTree;

		node_to_examine = (PMMADDRESS_NODE)(table->BalancedRoot);

		for (;;)
		{
			vpn_compare = (PMMVAD_SHORT)node_to_examine;
			start_vpn = vpn_compare->StartingVpn;
			end_vpn = vpn_compare->EndingVpn;

			if (starting_vpn < start_vpn)
			{
				child = node_to_examine->LeftChild;
				if (child != NULL)
				{
					node_to_examine = child;
				}
				else
				{
					*node_or_parent = node_to_examine;
					return TableInsertAsLeft;
				}
			}
			else if (starting_vpn <= end_vpn)
			{
				*node_or_parent = node_to_examine;
				return TableFoundNode;
			}
			else
			{
				child = node_to_examine->RightChild;
				if (child != NULL)
				{
					node_to_examine = child;
				}
				else
				{
					*node_or_parent = node_to_examine;
					return TableInsertAsRight;
				}
			}
		};
	}

	auto find_vad(PEPROCESS process, ULONG_PTR address, PMMVAD_SHORT* result) -> NTSTATUS
	{
		NTSTATUS status = STATUS_SUCCESS;
		ULONG_PTR vpn_start = address >> PAGE_SHIFT;

		ASSERT(process != NULL && result != NULL);
		if (process == NULL || result == NULL)
			return STATUS_INVALID_PARAMETER;

		PMM_AVL_TABLE table = (PMM_AVL_TABLE)((PUCHAR)process + 0x7D8);
		PMM_AVL_NODE node = (table->BalancedRoot);

		if (mi_find_node_or_parent(table, vpn_start, &node) == TableFoundNode)
		{
			*result = (PMMVAD_SHORT)node;
		}
		else
		{
			status = STATUS_NOT_FOUND;
		}

		return status;
	}

	INT klower(int c)
	{
		if (c >= 'A' && c <= 'Z')
			return c + 'a' - 'A';
		else
			return c;
	}

	INT kwcscmp(const wchar_t* s1, const wchar_t* s2)
	{
		while (*s1 == *s2++)
			if (*s1++ == '\0')
				return (0);

		return (*(const unsigned int*)s1 - *(const unsigned int*)--s2);
	}

	CHAR* kLowerStr(CHAR* Str)
	{
		for (CHAR* S = Str; *S; ++S)
		{
			*S = (CHAR)klower(*S);
		}
		return Str;
	}

	SIZE_T kstrlen(const char* str)
	{
		const char* s;
		for (s = str; *s; ++s);
		return (s - str);
	}

	INT kstrncmp(const char* s1, const char* s2, size_t n)
	{
		if (n == 0)
			return (0);
		do {
			if (*s1 != *s2++)
				return (*(unsigned char*)s1 - *(unsigned char*)--s2);
			if (*s1++ == 0)
				break;
		} while (--n != 0);
		return (0);
	}

	INT kstrcmp(const char* s1, const char* s2)
	{
		while (*s1 == *s2++)
			if (*s1++ == 0)
				return (0);
		return (*(unsigned char*)s1 - *(unsigned char*)--s2);
	}

	CHAR* kstrstr(const char* s, const char* find)
	{
		char c, sc;
		size_t len;
		if ((c = *find++) != 0)
		{
			len = kstrlen(find);
			do
			{
				do
				{
					if ((sc = *s++) == 0)
					{
						return (NULL);
					}
				} while (sc != c);
			} while (kstrncmp(s, find, len) != 0);
			s--;
		}
		return ((char*)s);
	}

	INT kmemcmp(const void* s1, const void* s2, size_t n)
	{
		const unsigned char* p1 = (const unsigned char*)s1;
		const unsigned char* end1 = p1 + n;
		const unsigned char* p2 = (const unsigned char*)s2;
		int                   d = 0;
		for (;;) {
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
			if (d || p1 >= end1) break;
			d = (int)*p1++ - (int)*p2++;
		}
		return d;
	}

	INT kMemcmp(const void* str1, const void* str2, size_t count)
	{
		register const unsigned char* s1 = (const unsigned char*)str1;
		register const unsigned char* s2 = (const unsigned char*)str2;
		while (count-- > 0)
		{
			if (*s1++ != *s2++)
				return s1[-1] < s2[-1] ? -1 : 1;
		}
		return 0;
	}


	VOID* kmemcpy(void* dest, const void* src, size_t len)
	{
		char* d = (char*)dest;
		const char* s = (const char*)src;
		while (len--)
			*d++ = *s++;
		return dest;
	}

	VOID* kmemset(void* dest, UINT8 c, size_t count)
	{
		size_t blockIdx;
		size_t blocks = count >> 3;
		size_t bytesLeft = count - (blocks << 3);
		UINT64 cUll =
			c
			| (((UINT64)c) << 8)
			| (((UINT64)c) << 16)
			| (((UINT64)c) << 24)
			| (((UINT64)c) << 32)
			| (((UINT64)c) << 40)
			| (((UINT64)c) << 48)
			| (((UINT64)c) << 56);

		UINT64* destPtr8 = (UINT64*)dest;
		for (blockIdx = 0; blockIdx < blocks; blockIdx++) destPtr8[blockIdx] = cUll;

		if (!bytesLeft) return dest;

		blocks = bytesLeft >> 2;
		bytesLeft = bytesLeft - (blocks << 2);

		UINT32* destPtr4 = (UINT32*)&destPtr8[blockIdx];
		for (blockIdx = 0; blockIdx < blocks; blockIdx++) destPtr4[blockIdx] = (UINT32)cUll;

		if (!bytesLeft) return dest;

		blocks = bytesLeft >> 1;
		bytesLeft = bytesLeft - (blocks << 1);

		UINT16* destPtr2 = (UINT16*)&destPtr4[blockIdx];
		for (blockIdx = 0; blockIdx < blocks; blockIdx++) destPtr2[blockIdx] = (UINT16)cUll;

		if (!bytesLeft) return dest;

		UINT8* destPtr1 = (UINT8*)&destPtr2[blockIdx];
		for (blockIdx = 0; blockIdx < bytesLeft; blockIdx++) destPtr1[blockIdx] = (UINT8)cUll;

		return dest;
	}
}