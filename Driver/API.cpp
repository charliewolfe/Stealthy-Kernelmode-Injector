#include <intrin.h>
#include "API.h"
#include "Utils/MemoryUtils.h"
#include "Define/NT.h"
#include "Define/Patterns.h"

PMMVAD_SHORT(*MiAllocateVad)(UINT_PTR start, UINT_PTR end, LOGICAL deletable) = NULL;
NTSTATUS(*MiInsertVadCharges)(PMMVAD_SHORT vad, PEPROCESS process) = NULL;
VOID(*MiInsertVad)(PMMVAD_SHORT vad, PEPROCESS process) = NULL;

NTSTATUS
API::ReadMemory(
	CONST PREAD_MEMORY Message
) {
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process = NULL;

	Status = PsLookupProcessByProcessId(Message->ProcessId, &Process);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	SIZE_T Result = 0;

	__try {

		Status = MmCopyVirtualMemory(
			Process,
			(PVOID)Message->Address,
			PsGetCurrentProcess(),
			(PVOID)Message->pOut,
			Message->Size,
			KernelMode,
			&Result
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

		Status = GetExceptionCode();
	}

	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS
API::WriteMemory(
	CONST PWRITE_MEMORY Message
) {
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS Process = NULL;

	Status = PsLookupProcessByProcessId(Message->ProcessId, &Process);

	if (!NT_SUCCESS(Status)) {
		return Status;
	}

	SIZE_T Result = 0;

	__try {
		Status = MmCopyVirtualMemory(
			PsGetCurrentProcess(),
			(PVOID)Message->pSrc,
			Process,
			(PVOID)Message->Address,
			Message->Size,
			KernelMode,
			&Result
		);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		Status = GetExceptionCode();
	}

	ObDereferenceObject(Process);

	return Status;
}

NTSTATUS
API::ProtectMemory(
	CONST PPROTECT_MEMORY Message
) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Message->ProcessId, &Process);
	if (NT_SUCCESS(Status)) {
		DWORD Protect = NULL;
		SIZE_T ReturnSize = NULL;
		if (MemoryUtils::SafeCopy(&Protect, Message->InOutProtect, sizeof(Protect))) {
			SIZE_T Size = Message->Size;

			KeAttachProcess(Process);
			Status = ZwProtectVirtualMemory(NtCurrentProcess(), &Message->Address, &Size, Protect, &Protect);
			KeDetachProcess();

			MemoryUtils::SafeCopy(Message->InOutProtect, &Protect, sizeof(Protect));
		}
		else {
			Status = STATUS_ACCESS_VIOLATION;
		}

		ObDereferenceObject(Process);
	}

	return Status;
}

NTSTATUS
API::AllocMemory(
	CONST PALLOC_MEMORY Message
) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Message->ProcessId, &Process);
	if (NT_SUCCESS(Status)) {
		PVOID Address = NULL;
		SIZE_T size = Message->Size;

		KeAttachProcess(Process);
		ZwAllocateVirtualMemory(NtCurrentProcess(), &Address, 0, &size, MEM_COMMIT | MEM_RESERVE, Message->Protect);
		KeDetachProcess();

		MemoryUtils::SafeCopy(Message->pOut, &Address, sizeof(Address));

		ObDereferenceObject(Process);
	}

	return Status;
}

NTSTATUS
API::FreeMemory(
	CONST PFREE_MEMORY Message
) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Message->ProcessId, &Process);
	if (NT_SUCCESS(Status)) {
		SIZE_T Size = 0;

		KeAttachProcess(Process);
		ZwFreeVirtualMemory(NtCurrentProcess(), &Message->Address, &Size, MEM_RELEASE);
		KeDetachProcess();

		ObDereferenceObject(Process);
	}

	return Status;
}

NTSTATUS
API::GetPte(
	CONST PGET_PTE Message
) {
	PTE_64 PTEToCopy{};
	PEPROCESS Process = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Message->ProcessId, &Process))) {
		KAPC_STATE state;
		KeStackAttachProcess(Process, &state);

		CR3 cr3{};
		cr3.Flags = __readcr3();
		PTE_64* pte = (PTE_64*)MemoryUtils::GetPte(Message->Address, cr3);
		if (pte) {
			PTEToCopy.Present = pte->Present;
			PTEToCopy.Write = pte->Write;
			PTEToCopy.Supervisor = pte->Supervisor;
			PTEToCopy.PageLevelWriteThrough = pte->PageLevelWriteThrough;
			PTEToCopy.PageLevelCacheDisable = pte->PageLevelCacheDisable;
			PTEToCopy.Accessed = pte->Accessed;
			PTEToCopy.Dirty = pte->Dirty;
			PTEToCopy.Pat = pte->Pat;
			PTEToCopy.Global = pte->Global;
			PTEToCopy.CopyOnWrite = pte->CopyOnWrite;
			PTEToCopy.Unused = pte->Unused;
			PTEToCopy.Write1 = pte->Write1;
			PTEToCopy.PageFrameNumber = pte->PageFrameNumber;
			PTEToCopy.Reserved1 = pte->Reserved1;
			PTEToCopy.Ignored2 = pte->Ignored2;
			PTEToCopy.ProtectionKey = pte->ProtectionKey;
			PTEToCopy.ExecuteDisable = pte->ExecuteDisable;
			PTEToCopy.Flags = pte->Flags;
		}
		KeUnstackDetachProcess(&state);
		MemoryUtils::SafeCopy(Message->pOut, &PTEToCopy, sizeof(PTE_64));
	}

	ObDereferenceObject(Process);

	return STATUS_SUCCESS;
}

NTSTATUS
API::SetPte(
	CONST PSET_PTE Message
) {
	PEPROCESS Process = NULL;
	if (NT_SUCCESS(PsLookupProcessByProcessId(Message->ProcessId, &Process))) {
		KeAttachProcess(Process);
		CR3 cr3{};
		cr3.Flags = __readcr3();
		PTE_64* pte = (PTE_64*)MemoryUtils::GetPte(Message->Address, cr3);
		if (pte) {
			if (pte->Present) {
				pte->Present = Message->Pte.Present;
				pte->Write = Message->Pte.Write;
				pte->Supervisor = Message->Pte.Supervisor;
				pte->PageLevelWriteThrough = Message->Pte.PageLevelWriteThrough;
				pte->PageLevelCacheDisable = Message->Pte.PageLevelCacheDisable;
				pte->Accessed = Message->Pte.Accessed;
				pte->Dirty = Message->Pte.Dirty;
				pte->Pat = Message->Pte.Pat;
				pte->Global = Message->Pte.Global;
				pte->CopyOnWrite = Message->Pte.Global;
				pte->Unused = Message->Pte.Unused;
				pte->Write1 = Message->Pte.Write1;
				pte->PageFrameNumber = Message->Pte.PageFrameNumber;
				pte->Reserved1 = Message->Pte.Reserved1;
				pte->Ignored2 = Message->Pte.Ignored2;
				pte->ProtectionKey = Message->Pte.ProtectionKey;
				pte->ExecuteDisable = Message->Pte.ExecuteDisable;
				pte->Flags = Message->Pte.Flags;
			}
		}
		KeDetachProcess();
	}

	ObDereferenceObject(Process);

	return STATUS_SUCCESS;
}

NTSTATUS
API::QueryVirtualMemory(
	CONST PQUERY_VIRTUAL_MEMORY Message
) {
	PEPROCESS Process = NULL;
	if (!NT_SUCCESS(PsLookupProcessByProcessId(Message->ProcessId, &Process))) {
		return STATUS_UNSUCCESSFUL;
	}
	MEMORY_BASIC_INFORMATION Mbi;

	KeAttachProcess(Process);
	ZwQueryVirtualMemory(NtCurrentProcess(), Message->Address, MemoryBasicInformation, &Mbi, sizeof(Mbi), NULL);
	KeDetachProcess();

	MemoryUtils::SafeCopy(Message->pOut, &Mbi, sizeof(Mbi));

	return STATUS_SUCCESS;
}

NTSTATUS
API::GetVADFlags(
	CONST PGET_VAD_FLAGS Message
) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Message->ProcessId, &Process);
	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}

	PMMVAD_SHORT pVadShort = NULL;
	Status = MemoryUtils::FindVAD(Process, (ULONGLONG)Message->Address, &pVadShort);

	if (NT_SUCCESS(Status)) {
		MemoryUtils::SafeCopy(Message->pOut, &pVadShort->u.VadFlags, sizeof(MMVAD_FLAGS));
	}

	ObDereferenceObject(Process);
	return Status;
}

NTSTATUS
API::SetVADFlags(
	CONST PSET_VAD_FLAGS Message
) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Message->ProcessId, &Process);
	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}

	PMMVAD_SHORT pVadShort = NULL;
	Status = MemoryUtils::FindVAD(Process, (ULONGLONG)Message->Address, &pVadShort);

	if (NT_SUCCESS(Status)) {
		pVadShort->u.VadFlags.Lock = Message->VADFlags.Lock;
		pVadShort->u.VadFlags.LockContended = Message->VADFlags.LockContended;
		pVadShort->u.VadFlags.DeleteInProgress = Message->VADFlags.DeleteInProgress;
		pVadShort->u.VadFlags.NoChange = Message->VADFlags.NoChange;
		pVadShort->u.VadFlags.VadType = Message->VADFlags.VadType;
		pVadShort->u.VadFlags.Protection = Message->VADFlags.Protection;
		pVadShort->u.VadFlags.PreferredNode = Message->VADFlags.PreferredNode;
		pVadShort->u.VadFlags.PageSize = Message->VADFlags.PageSize;
		pVadShort->u.VadFlags.PrivateMemory = Message->VADFlags.PrivateMemory;
	}

	ObDereferenceObject(Process);
	return Status;
}

NTSTATUS
API::RemoveVADNode(
	CONST PREMOVE_VAD Message
) {
	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Message->ProcessId, &Process);
	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}

	PMM_AVL_TABLE pTable = (PMM_AVL_TABLE)((PUCHAR)Process + 0x7d8);

	PMMVAD_SHORT pVadShort = NULL;
	Status = MemoryUtils::FindVAD(Process, (ULONGLONG)Message->Address, &pVadShort);

	RtlAvlRemoveNode(pTable, reinterpret_cast<PMMADDRESS_NODE>(pVadShort));

	return STATUS_SUCCESS;
}

NTSTATUS
API::AllocateVad(
	CONST PALLOCATE_VAD Message
) {

	if (!MiAllocateVad) {
		MiAllocateVad = (PMMVAD_SHORT(*)(UINT_PTR, UINT_PTR, LOGICAL))MemoryUtils::FindPatternImage((PCHAR)MemoryUtils::GetKernelBase(), MI_ALLOCATE_VAD_PATTERN, MI_ALLOCATE_VAD_MASK);
		if (!MiAllocateVad) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "MiAllocateVad not found");
			return STATUS_UNSUCCESSFUL;
		}
	}

	if (!MiInsertVadCharges) {
		MiInsertVadCharges = (NTSTATUS(*)(PMMVAD_SHORT, PEPROCESS))MemoryUtils::FindPatternImage((PCHAR)MemoryUtils::GetKernelBase(), MI_INSERT_VAD_CHANGES_PATTERN, MI_INSERT_VAD_CHANGES_MASK);
		if (!MiInsertVadCharges) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "MiInsertVadCharges not found");
			return STATUS_UNSUCCESSFUL;
		}
	}

	if (!MiInsertVad) {
		MiInsertVad = (VOID(*)(PMMVAD_SHORT, PEPROCESS))MemoryUtils::FindPatternImage((PCHAR)MemoryUtils::GetKernelBase(), MI_INSERT_VAD_PATTERN, MI_INSERT_VAD_MASK);
		if (!MiInsertVad) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "MiInsertVad not found");
			return STATUS_UNSUCCESSFUL;
		}
	}

	PEPROCESS Process = NULL;
	NTSTATUS Status = PsLookupProcessByProcessId((HANDLE)Message->ProcessId, &Process);
	if (!NT_SUCCESS(Status)) {
		ObDereferenceObject(Process);
		return STATUS_UNSUCCESSFUL;
	}

	ULONGLONG Start = (ULONGLONG)Message->Address;
	ULONGLONG End = (ULONGLONG)Message->Address + Message->Size;

	KeAttachProcess(Process);

	MEMORY_BASIC_INFORMATION MBI{};
	if (!NT_SUCCESS(ZwQueryVirtualMemory(NtCurrentProcess(), (PVOID)Start, MemoryBasicInformation, &MBI, sizeof(MBI), NULL))) {
		return STATUS_UNSUCCESSFUL;
	}

	PMMVAD_SHORT VAD = MiAllocateVad(Start, End, TRUE);
	if (!VAD) {
		return STATUS_UNSUCCESSFUL;
	}

	PMMVAD_FLAGS Flags = (PMMVAD_FLAGS)&VAD->u.LongFlags;
	Flags->Protection = (6);
	Flags->NoChange = 0;

	if (!NT_SUCCESS(MiInsertVadCharges(VAD, Process))) {
		ExFreePool(VAD);
		return STATUS_UNSUCCESSFUL;
	}

	MiInsertVad(VAD, Process);

	KeDetachProcess();

	ObDereferenceObject(Process);

	return STATUS_SUCCESS;
}
