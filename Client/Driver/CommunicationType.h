#pragma once
#include <minwindef.h>
#include "../Define/IA32.h"
#include "../Define/VAD.h"

CONST ULONG DATA_UNIQUE = 0x8392;

typedef struct _READ_MEMORY {
	HANDLE ProcessId;
	DWORD64 Address;
	ULONG Size;
	PVOID pOut;
} READ_MEMORY, * PREAD_MEMORY;

typedef struct _WRITE_MEMORY {
	HANDLE ProcessId;
	DWORD64 Address;
	ULONG Size;
	PVOID pSrc;
} WRITE_MEMORY, * PWRITE_MEMORY;

typedef struct _PROTECT_MEMORY {
	HANDLE ProcessId;
	PVOID Address;
	DWORD Size;
	PVOID InOutProtect;
} PROTECT_MEMORY, * PPROTECT_MEMORY;

typedef struct _ALLOC_MEMORY {
	HANDLE ProcessId;
	PVOID pOut;
	DWORD Size;
	DWORD Protect;
} ALLOC_MEMORY, * PALLOC_MEMORY;

typedef struct _FREE_MEMORY {
	HANDLE ProcessId;
	PVOID Address;
} FREE_MEMORY, * PFREE_MEMORY;

typedef struct _GET_PTE {
	HANDLE ProcessId;
	PVOID Address;
	PVOID pOut;
} GET_PTE, * PGET_PTE;

typedef struct _SET_PTE {
	HANDLE ProcessId;
	PVOID Address;
	PTE_64 Pte;
} SET_PTE, * PSET_PTE;

typedef struct _QUERY_VIRTUAL_MEMORY {
	HANDLE ProcessId;
	PVOID Address;
	PVOID pOut;
} QUERY_VIRTUAL_MEMORY, * PQUERY_VIRTUAL_MEMORY;

typedef struct _GET_VAD_FLAGS {
	HANDLE ProcessId;
	PVOID Address;
	PVOID pOut;
} GET_VAD_FLAGS, * PGET_VAD_FLAGS;

typedef struct _SET_VAD_FLAGS {
	HANDLE ProcessId;
	PVOID Address;
	MMVAD_FLAGS VADFlags;
} SET_VAD_FLAGS, * PSET_VAD_FLAGS;

typedef struct _REMOVE_VAD {
	HANDLE ProcessId;
	PVOID Address;
} REMOVE_VAD, * PREMOVE_VAD;

typedef struct _ALLOCATE_VAD {
	HANDLE ProcessId;
	PVOID Address;
	ULONGLONG Size;
	ULONG Protection;
} ALLOCATE_VAD, * PALLOCATE_VAD;

typedef enum _REQUEST_TYPE {
	REQUEST_READ_MEMORY,
	REQUEST_WRITE_MEMORY,
	REQUEST_PROTECT_MEMORY,
	REQUEST_ALLOC_MEMORY,
	REQUEST_FREE_MEMORY,
	REQUEST_GET_PTE,
	REQUEST_SET_PTE,
	REQUEST_QUERY_VIRTUAL_MEMORY,
	REQUEST_GET_VAD_FLAGS,
	REQUEST_SET_VAD_FLAGS,
	REQUEST_REMOVE_VAD_NODE,
	REQUEST_ALLOC_VAD
} REQUEST_TYPE;

typedef struct _REQUEST_DATA {
	DWORD Unique;
	REQUEST_TYPE Type;
	PVOID Arguments;
} REQUEST_DATA, * PREQUEST_DATA;
