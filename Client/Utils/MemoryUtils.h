#pragma once
#include <Windows.h>
#include "../Define/IA32.h"

namespace MemoryUtils {
	PVOID
		GetDllFromFile(
			LPCSTR DllPath
		);

	VOID
		GetProcessIdAndThreadIdFromWindowClass(
			LPCSTR WindowClassName,
			PDWORD pProcessId,
			PDWORD pThreadId
		);

	PVOID
		RVA_VA(
			ULONGLONG RVA,
			PIMAGE_NT_HEADERS NtHead,
			PVOID LocalImage
		);

	BOOL
		FlipExecutableBitForMemoryRegion(
			HANDLE ProcessId,
			PVOID Address,
			LONGLONG ExecuteDisable
		);

	PVOID
		GetLastThreadStack(
			ULONG ProcessId
		);
}
