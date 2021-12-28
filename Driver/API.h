#pragma once
#include <ntifs.h>
#include <minwindef.h>
#include "Communication/CommunicationType.h"

namespace API {

	NTSTATUS
		ReadMemory(
			CONST PREAD_MEMORY Message
		);

	NTSTATUS
		WriteMemory(
			CONST PWRITE_MEMORY Message
		);

	NTSTATUS
		ProtectMemory(
			CONST PPROTECT_MEMORY Message
		);

	NTSTATUS
		AllocMemory(
			CONST PALLOC_MEMORY Message
		);

	NTSTATUS
		FreeMemory(
			CONST PFREE_MEMORY Message
		);

	NTSTATUS
		GetPte(
			CONST PGET_PTE Message
		);

	NTSTATUS
		SetPte(
			CONST PSET_PTE Message
		);

	NTSTATUS
		QueryVirtualMemory(
			CONST PQUERY_VIRTUAL_MEMORY Message
		);

	NTSTATUS
		GetVADFlags(
			CONST PGET_VAD_FLAGS Message
		);

	NTSTATUS
		SetVADFlags(
			CONST PSET_VAD_FLAGS Message
		);

	NTSTATUS
		RemoveVADNode(
			CONST PREMOVE_VAD Message
		);

	NTSTATUS
		AllocateVad(
			CONST PALLOCATE_VAD Message
		);
}
