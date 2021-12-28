#include <Windows.h>
#include <stdio.h>
#include "Hijack.h"
#include "../Driver/Driver.h"

BYTE RemoteCallDllMain[92] = {
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
	0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
	0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
	0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
}; DWORD ShellDataOffset = 0x6;

typedef struct _MAIN_STRUCT {
	INT Status;
	uintptr_t FnDllMain;
	HINSTANCE DllBase;
} MAIN_STRUCT, * PMAIN_STRUCT;

BOOL
Hijack::CallViaSetWindowsHookEx(
	DWORD ProcessId,
	DWORD ThreadId,
	PVOID DllBase,
	PIMAGE_NT_HEADERS NtHeader
) {
	HMODULE NtDll = LoadLibraryW(L"ntdll.dll");

	PVOID AllocShellCode = NULL;
	Driver::API::AllocMemory((HANDLE)ProcessId, &AllocShellCode, 0x1000, PAGE_EXECUTE_READWRITE);

	DWORD ShellSize = sizeof(RemoteCallDllMain) + sizeof(MAIN_STRUCT);
	PVOID AllocLocal = VirtualAlloc(NULL, ShellSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	RtlCopyMemory(AllocLocal, &RemoteCallDllMain, sizeof(RemoteCallDllMain));
	ULONGLONG ShellData = (ULONGLONG)AllocShellCode + sizeof(RemoteCallDllMain);
	*(ULONGLONG*)((ULONGLONG)AllocLocal + ShellDataOffset) = ShellData;
	
	PMAIN_STRUCT MainData = (PMAIN_STRUCT)((ULONGLONG)AllocLocal + sizeof(RemoteCallDllMain));
	MainData->DllBase = (HINSTANCE)DllBase;
	MainData->FnDllMain = ((ULONGLONG)DllBase + NtHeader->OptionalHeader.AddressOfEntryPoint);
	Driver::API::WriteMemory((HANDLE)ProcessId, (DWORD64)AllocShellCode, ShellSize, AllocLocal);

	HHOOK hHook = SetWindowsHookEx(WH_GETMESSAGE, (HOOKPROC)AllocShellCode, NtDll, ThreadId);
	while (MainData->Status != 2) {
		PostThreadMessage(ThreadId, WM_NULL, 0, 0);
		Sleep(10);
		Driver::API::ReadMemory((HANDLE)ProcessId, (PVOID)ShellData, sizeof(MAIN_STRUCT), (PVOID)MainData);
	}
	UnhookWindowsHookEx(hHook);

	BYTE ZeroShell[116ui64] = { 0 };
	Driver::API::WriteMemory((HANDLE)ProcessId, (DWORD64)AllocShellCode, 116ui64, ZeroShell);

	Driver::API::FreeMemory((HANDLE)ProcessId, AllocShellCode);
	VirtualFree(AllocLocal, 0, MEM_RELEASE);

	return TRUE;
}
