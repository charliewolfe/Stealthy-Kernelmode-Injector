#pragma once
#include <Windows.h>
#include "CommunicationType.h"
#include "../Define/VAD.h"

#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

namespace Driver {
	NTSTATUS
		Initialize();

	namespace API {

		NTSTATUS
			ReadMemory(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address,
				IN CONST ULONG Size,
				OUT CONST PVOID pOut
			);

		NTSTATUS
			WriteMemory(
				IN CONST HANDLE ProcessId,
				IN CONST DWORD64 Address,
				IN CONST ULONG Size,
				IN CONST PVOID pSrc
			);

		NTSTATUS
			ProtectMemory(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address,
				IN CONST DWORD Size,
				IN OUT CONST PVOID pInOutProtect
			);

		NTSTATUS
			AllocMemory(
				IN CONST HANDLE ProcessId,
				OUT CONST PVOID pOut,
				IN CONST DWORD Size,
				IN CONST DWORD Protect
			);

		NTSTATUS
			FreeMemory(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address
			);

		NTSTATUS
			GetPte(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address,
				OUT CONST PVOID pOut
			);

		NTSTATUS
			SetPte(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address,
				IN CONST PTE_64 Pte
			);

		NTSTATUS
			QueryVirtualMemory(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address,
				OUT CONST PVOID pOut
			);

		NTSTATUS
			GetVADFlags(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address,
				OUT CONST PVOID pOut
			);

		NTSTATUS
			SetVADFlags(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address,
				IN CONST MMVAD_FLAGS VADFlags
			);

		NTSTATUS
			RemoveVADNode(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address
			);

		NTSTATUS
			AllocateVAD(
				IN CONST HANDLE ProcessId,
				IN CONST PVOID Address,
				IN CONST ULONGLONG Size
			);
	}
}