#include <Windows.h>

namespace Hijack {
	BOOL
		CallViaSetWindowsHookEx(
			DWORD ProcessId,
			DWORD ThreadId,
			PVOID DllBase,
			PIMAGE_NT_HEADERS NtHeader
		);
}
