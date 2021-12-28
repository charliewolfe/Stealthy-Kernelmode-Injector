#pragma once
#include <ntifs.h>
#include <minwindef.h>
#include "../Define/IA32.h"
#include "../Define/NT.h"

namespace MemoryUtils {
	PVOID
		GetKernelBase();

	PVOID
		GetKernelModuleBase(
			CHAR* ModuleName
		);

	BOOL
		SafeCopy(
			PVOID Dest,
			PVOID Src,
			SIZE_T Size
		);

	NTSTATUS
		FindVAD(
			IN PEPROCESS pProcess,
			IN ULONG_PTR address,
			OUT PMMVAD_SHORT* pResult
		);

	PT_ENTRY_64*
		GetPte(
			PVOID VirtualAddress,
			CR3 HostCr3
		);

	ULONGLONG
		GetExportedFunction(
			CONST ULONGLONG Mod,
			CONST CHAR* Name
		);

	PVOID
		FindPatternImage(
			PCHAR Base,
			PCHAR Pattern,
			PCHAR Mask
		);

	PVOID
		ResolveRelativeAddress(
			PVOID Instruction,
			ULONG OffsetOffset,
			ULONG InstructionSize
		);

	UCHAR
		RandomNumber();
}
