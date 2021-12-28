#include "Hide.h"
#include "../Utils/MemoryUtils.h"
#include "../Library/skCrypter.h"
#include "../Define/Patterns.h"

#define MM_UNLOADED_DRIVERS_SIZE 50

typedef struct _PIDDBCACHE_ENTRY {
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16];
} PIDDBCACHE_ENTRY, * PPIDDBCACHE_ENTRY;

typedef struct _MM_UNLOADED_DRIVER {
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, * PMM_UNLOADED_DRIVER;

PERESOURCE
GetPsLoaded() {
	PCHAR base = (PCHAR)MemoryUtils::GetKernelBase();

	auto cMmGetSystemRoutineAddress = reinterpret_cast<decltype(&MmGetSystemRoutineAddress)>(MemoryUtils::GetExportedFunction((ULONGLONG)base, "MmGetSystemRoutineAddress"));

	ERESOURCE PsLoadedModuleResource;
	UNICODE_STRING routineName = RTL_CONSTANT_STRING(L"PsLoadedModuleResource");
	auto cPsLoadedModuleResource = reinterpret_cast<decltype(&PsLoadedModuleResource)>(cMmGetSystemRoutineAddress(&routineName));

	return cPsLoadedModuleResource;
}

PMM_UNLOADED_DRIVER
GetMmuAddress() {
	PCHAR base = (PCHAR)MemoryUtils::GetKernelBase();

	auto MmuPattern = skCrypt(MMU_PATTERN);
	auto MmuMask = skCrypt(MMU_MASK);
	PVOID MmUnloadedDriversInstr = MemoryUtils::FindPatternImage(base, MmuPattern, MmuMask);
	MmuPattern.clear();
	MmuMask.clear();

	if (MmUnloadedDriversInstr == NULL)
		return { };

	return *(PMM_UNLOADED_DRIVER*)MemoryUtils::ResolveRelativeAddress(MmUnloadedDriversInstr, 3, 7);
}

PULONG
GetMmlAddress() {
	PCHAR Base = (PCHAR)MemoryUtils::GetKernelBase();

	auto MmlPattern = skCrypt(MML_PATTERN);
	auto MmlMask = skCrypt(MML_MASK);
	PVOID mmlastunloadeddriverinst = MemoryUtils::FindPatternImage(Base, MmlPattern, MmlMask);
	MmlPattern.clear();
	MmlMask.clear();

	if (mmlastunloadeddriverinst == NULL)
		return { };

	return (PULONG)MemoryUtils::ResolveRelativeAddress(mmlastunloadeddriverinst, 2, 6);
}

BOOL
VerifyMmu() {
	return (GetMmuAddress() != NULL && GetMmlAddress() != NULL);
}

BOOL
IsUnloadEmpty(
	PMM_UNLOADED_DRIVER Entry
) {
	if (Entry->Name.MaximumLength == 0 || Entry->Name.Length == 0 || Entry->Name.Buffer == NULL)
		return TRUE;

	return FALSE;
}

BOOL
IsMmuFilled() {
	for (ULONG Idx = 0; Idx < MM_UNLOADED_DRIVERS_SIZE; ++Idx) {
		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Idx];
		if (IsUnloadEmpty(Entry))
			return FALSE;
	}
	return TRUE;
}

BOOL
CleanMmu(
	UNICODE_STRING DriverName
) {
	auto ps_loaded = GetPsLoaded();

	ExAcquireResourceExclusiveLite(ps_loaded, TRUE);

	BOOLEAN Modified = FALSE;
	BOOLEAN Filled = IsMmuFilled();

	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index) {
		PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
		if (IsUnloadEmpty(Entry)) {
			continue;
		}
		BOOL empty = IsUnloadEmpty(Entry);
		if (Modified) {
			PMM_UNLOADED_DRIVER PrevEntry = &GetMmuAddress()[Index - 1];
			RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));

			if (Index == MM_UNLOADED_DRIVERS_SIZE - 1) {
				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			}
		}
		else if (RtlEqualUnicodeString(&DriverName, &Entry->Name, TRUE)) {
			PVOID BufferPool = Entry->Name.Buffer;
			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			ExFreePoolWithTag(BufferPool, 'TDmM');

			*GetMmlAddress() = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *GetMmlAddress()) - 1;
			Modified = TRUE;
		}
	}

	if (Modified) {
		ULONG64 PreviousTime = 0;

		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index) {
			PMM_UNLOADED_DRIVER Entry = &GetMmuAddress()[Index];
			if (IsUnloadEmpty(Entry)) {
				continue;
			}

			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime) {
				Entry->UnloadTime = PreviousTime - MemoryUtils::RandomNumber();
			}

			PreviousTime = Entry->UnloadTime;
		}

		CleanMmu(DriverName);
	}

	ExReleaseResourceLite(ps_loaded);

	return Modified;
}

PERESOURCE
GetPiDDBLock() {
	PCHAR base = (PCHAR)MemoryUtils::GetKernelBase();

	auto PiDDBLockPattern = skCrypt(PIDDB_LOCK_PATTERN);
	auto PiDDBLockMask = skCrypt(PIDDB_LOCK_MASK);
	PERESOURCE PiDDBLock = (PERESOURCE)MemoryUtils::FindPatternImage(base, PiDDBLockPattern, PiDDBLockMask);
	PiDDBLockPattern.clear();
	PiDDBLockMask.clear();

	PiDDBLock = (PERESOURCE)MemoryUtils::ResolveRelativeAddress((PVOID)PiDDBLock, 3, 7);
	if (!PiDDBLock) {
		return 0;
	}

	return PiDDBLock;
}

PRTL_AVL_TABLE
GetPiDDBTable() {
	PCHAR base = (PCHAR)MemoryUtils::GetKernelBase();

	auto PiDDBTablePattern = skCrypt(PIDDB_TABLE_PATTERN);
	auto PiDDBTableMask = skCrypt(PIDDB_TABLE_MASK);
	PRTL_AVL_TABLE PiDDBCacheTable = (PRTL_AVL_TABLE)MemoryUtils::FindPatternImage(base, PiDDBTablePattern, PiDDBTableMask);
	PiDDBTablePattern.clear();
	PiDDBTableMask.clear();

	PiDDBCacheTable = (PRTL_AVL_TABLE)MemoryUtils::ResolveRelativeAddress((PVOID)PiDDBCacheTable, 6, 10);

	if (!PiDDBCacheTable) {
		return 0;
	}

	return PiDDBCacheTable;
}

BOOL
VerifyPiDDB() {
	return (GetPiDDBLock() != 0 && GetPiDDBTable() != 0);
}

BOOL
CleanPiDDB(
	UNICODE_STRING DriverName
) {
	PERESOURCE PiDDBLock = GetPiDDBLock();
	PRTL_AVL_TABLE PiDDBCacheTable = GetPiDDBTable();
	PiDDBCacheTable->TableContext = (PVOID)1;

	PIDDBCACHE_ENTRY LookupEntry = { 0 };
	LookupEntry.DriverName = DriverName;

	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

	PPIDDBCACHE_ENTRY pFoundEntry = (PPIDDBCACHE_ENTRY)RtlLookupElementGenericTableAvl(PiDDBCacheTable, &LookupEntry);
	if (pFoundEntry == NULL) {
		ExReleaseResourceLite(PiDDBLock);
		return FALSE;
	}

	RemoveEntryList(&pFoundEntry->List);
	RtlDeleteElementGenericTableAvl(PiDDBCacheTable, pFoundEntry);

	ExReleaseResourceLite(PiDDBLock);

	return TRUE;
}

BOOL
CleanKernelHashBucketList(
	UNICODE_STRING DriverName
) {
	auto CIDLLString = skCrypt("ci.dll");
	CONST PVOID CIDLLBase = MemoryUtils::GetKernelModuleBase(CIDLLString);
	CIDLLString.clear();

	if (!CIDLLBase) {
		return FALSE;
	}

	auto KernelBucketHashPattern = skCrypt(CI_DLL_KERNEL_HASH_BUCKET_PATTERN);
	auto KernelBucketHashMask = skCrypt(CI_DLL_KERNEL_HASH_BUCKET_MASK);
	CONST PVOID SignatureAddress = MemoryUtils::FindPatternImage((PCHAR)CIDLLBase, KernelBucketHashPattern, KernelBucketHashMask);
	KernelBucketHashPattern.clear();
	KernelBucketHashMask.clear();
	if (!SignatureAddress) {
		return FALSE;
	}

	CONST ULONGLONG* g_KernelHashBucketList = (ULONGLONG*)MemoryUtils::ResolveRelativeAddress(SignatureAddress, 3, 7);
	if (!g_KernelHashBucketList) {
		return FALSE;
	}

	LARGE_INTEGER Time{};
	KeQuerySystemTimePrecise(&Time);

	BOOL Status = FALSE;
	for (ULONGLONG i = *g_KernelHashBucketList; i; i = *(ULONGLONG*)i) {
		CONST PWCHAR wsName = PWCH(i + 0x48);
		if (wcsstr(wsName, DriverName.Buffer)) {
			PUCHAR Hash = PUCHAR(i + 0x18);
			for (UINT j = 0; j < 20; j++)
				Hash[j] = UCHAR(RtlRandomEx(&Time.LowPart) % 255);

			Status = TRUE;
		}
	}

	return Status;
}

BOOL
DeleteRegistryKey(
	UNICODE_STRING RegistryPath
) {
	HANDLE KeyHandle;
	OBJECT_ATTRIBUTES KeyAttributes;

	InitializeObjectAttributes(&KeyAttributes, &RegistryPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS(ZwOpenKey(&KeyHandle, KEY_ALL_ACCESS, &KeyAttributes))) {
		return FALSE;
	}

	if (!NT_SUCCESS(ZwDeleteKey(KeyHandle))) {
		return FALSE;
	}

	return TRUE;
}

BOOL
DeleteFile(
	UNICODE_STRING FilePath
) {
	OBJECT_ATTRIBUTES FileAttributes;
	InitializeObjectAttributes(&FileAttributes, &FilePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	if (!NT_SUCCESS(ZwDeleteFile(&FileAttributes))) {
		return FALSE;
	}

	return TRUE;
}

NTSTATUS
Hide::Mapper(
	UNICODE_STRING DriverName
) {
	NTSTATUS Status = STATUS_SUCCESS;
	if (VerifyPiDDB()) {
		if (!CleanPiDDB(DriverName)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to clean PiDDB");
			Status = STATUS_UNSUCCESSFUL;
		}
		else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Successfully cleaned PiDDB");
		}
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to find PiDDB");
		Status = STATUS_UNSUCCESSFUL;
	}

	if (VerifyMmu()) {
		if (!CleanMmu(DriverName)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to clean MMU");
			Status = STATUS_UNSUCCESSFUL;
		}
		else {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Successfully cleaned MMU");
		}
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to find MMU");
		Status = STATUS_UNSUCCESSFUL;
	}

	if (CleanKernelHashBucketList(DriverName)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Successfully cleaned g_KernelHashBucketList");
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Failed to clean g_KernelHashBucketList");
	}

	//if (!DeleteRegistryKey(RTL_CONSTANT_STRING(L"\\Registry\\Machine\\SYSTEM\\CurrentControlSet\\Services\\mapper"))) {
	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Registry key deletion failed");
	//}

	//if (!DeleteFile(RTL_CONSTANT_STRING(L"\\SystemRoot\\System32\\mapper.sys))) {
	//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "File deletion failed");
	//}

	return Status;
}