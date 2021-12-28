#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include "MemoryUtils.h"
#include "../Driver/Driver.h"

using std::vector;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PVOID TebBaseAddress;
    CLIENT_ID ClientId;
    KAFFINITY AffinityMask;
    LONG Priority;
    LONG BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef NTSTATUS(NTAPI* _NtQueryInformationThread) (
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
);

PVOID
MemoryUtils::GetDllFromFile(
    LPCSTR DllPath
) {
    HANDLE hDll = CreateFileA(DllPath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDll == INVALID_HANDLE_VALUE)
        return NULL;

    DWORD DllFileSize = GetFileSize(hDll, NULL);
    PVOID DllBuffer = VirtualAlloc(NULL, DllFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!ReadFile(hDll, DllBuffer, DllFileSize, NULL, FALSE)) {
        VirtualFree(DllBuffer, 0, MEM_RELEASE);
        goto Exit;
    }

Exit:
    CloseHandle(hDll);
    return DllBuffer;
}

VOID
MemoryUtils::GetProcessIdAndThreadIdFromWindowClass(
    LPCSTR WindowClassName,
    PDWORD pProcessId,
    PDWORD pThreadId
) {
    *pProcessId = 0;
    while (!*pProcessId) {
        *pThreadId = GetWindowThreadProcessId(FindWindowA(WindowClassName, NULL), pProcessId);
        Sleep(20);
    }
}

PVOID
MemoryUtils::RVA_VA(
    ULONGLONG RVA,
    PIMAGE_NT_HEADERS NtHead,
    PVOID LocalImage
) {
    PIMAGE_SECTION_HEADER pFirstSect = IMAGE_FIRST_SECTION(NtHead);
    for (PIMAGE_SECTION_HEADER pSection = pFirstSect; pSection < pFirstSect + NtHead->FileHeader.NumberOfSections; pSection++)
        if (RVA >= pSection->VirtualAddress && RVA < pSection->VirtualAddress + pSection->Misc.VirtualSize)
            return (PUCHAR)LocalImage + pSection->PointerToRawData + (RVA - pSection->VirtualAddress);

    return NULL;
}

BOOL
MemoryUtils::FlipExecutableBitForMemoryRegion(
    HANDLE ProcessId,
    PVOID Address,
    LONGLONG ExecuteDisable
) {
    MEMORY_BASIC_INFORMATION MBI{};
    Driver::API::QueryVirtualMemory(ProcessId, Address, &MBI);

    for (
        ULONGLONG i = reinterpret_cast<ULONGLONG>(MBI.BaseAddress);
        i < (reinterpret_cast<ULONGLONG>(MBI.BaseAddress) + MBI.RegionSize);
        i += 0x1000
        ) {
        PTE_64 PTE{};
        Driver::API::GetPte(ProcessId, reinterpret_cast<PVOID>(i), &PTE);
        PTE.ExecuteDisable = ExecuteDisable;
        Driver::API::SetPte(ProcessId, reinterpret_cast<PVOID>(i), PTE);
    }

    return TRUE;
}

vector<ULONG> 
WalkProcessThreads(
    ULONG ProcessId
) {
    vector<ULONG> ThreadIds{};
    THREADENTRY32 TE32;

    HANDLE Handle = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (Handle == INVALID_HANDLE_VALUE) {
        return {};
    }

    TE32.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(Handle, &TE32)) {
        CloseHandle(Handle);
        return {};
    }

    do {
        if (TE32.th32OwnerProcessID == ProcessId) {
            ThreadIds.push_back(TE32.th32ThreadID);
        }
    } while (Thread32Next(Handle, &TE32));

    CloseHandle(Handle);
    return ThreadIds;
}

PVOID
MemoryUtils::GetLastThreadStack(
    ULONG ProcessId
) {
    vector<PVOID> ThreadStacks{};
    
    _NtQueryInformationThread NtQueryInformationThread = (_NtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");

    vector<ULONG> ThreadIds = WalkProcessThreads(ProcessId);
    for (ULONG ThreadId : ThreadIds) {
        THREAD_BASIC_INFORMATION TBI;
        NT_TIB TIB;

        HANDLE Handle = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, ThreadId);
        NtQueryInformationThread(Handle, 0x0, &TBI, sizeof(THREAD_BASIC_INFORMATION), NULL);
        Driver::API::ReadMemory((HANDLE)ProcessId, TBI.TebBaseAddress, sizeof(TIB), &TIB);

        ThreadStacks.push_back(TIB.StackLimit);
    }

    PVOID LastThreadStack = 0;
    for (UINT i = 0; i < ThreadStacks.size(); i++) {
        if (ThreadStacks[i] > LastThreadStack)
            LastThreadStack = ThreadStacks[i];
    }

    MEMORY_BASIC_INFORMATION MBI{};
    Driver::API::QueryVirtualMemory((HANDLE)ProcessId, LastThreadStack, &MBI);

    return (PVOID)((ULONGLONG)MBI.BaseAddress + MBI.RegionSize);
}
