#include "MemoryUtils.h"
#include "../Define/NT.h"
#include "../Define/CRT.h"

PVOID
MemoryUtils::GetKernelBase() {
	PVOID KernelBase = NULL;

	ULONG size = NULL;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return KernelBase;
	}

	PSYSTEM_MODULE_INFORMATION Modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, size);
	if (!Modules) {
		return KernelBase;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, Modules, size, 0))) {
		ExFreePool(Modules);
		return KernelBase;
	}

	if (Modules->NumberOfModules > 0) {
		KernelBase = Modules->Modules[0].ImageBase;
	}

	ExFreePool(Modules);
	return KernelBase;
}

PVOID
MemoryUtils::GetKernelModuleBase(
	CHAR* ModuleName
) {
	PVOID ModuleBase = NULL;

	ULONG size = NULL;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, 0, &size);
	if (STATUS_INFO_LENGTH_MISMATCH != status) {
		return ModuleBase;
	}

	PSYSTEM_MODULE_INFORMATION Modules = (PSYSTEM_MODULE_INFORMATION)ExAllocatePool(NonPagedPool, size);
	if (!Modules) {
		return ModuleBase;
	}

	if (!NT_SUCCESS(status = ZwQuerySystemInformation(SystemModuleInformation, Modules, size, 0))) {
		ExFreePool(Modules);
		return ModuleBase;
	}

	for (UINT i = 0; i < Modules->NumberOfModules; i++) {
		CHAR* CurrentModuleName = reinterpret_cast<CHAR*>(Modules->Modules[i].FullPathName);
		if (stristr(CurrentModuleName, ModuleName)) {
			ModuleBase = Modules->Modules[i].ImageBase;
			break;
		}
	}

	ExFreePool(Modules);
	return ModuleBase;

}

BOOL
MemoryUtils::SafeCopy(
	PVOID Dest,
	PVOID Src,
	SIZE_T Size
) {
	SIZE_T returnSize = 0;
	if (NT_SUCCESS(MmCopyVirtualMemory(PsGetCurrentProcess(), Src, PsGetCurrentProcess(), Dest, Size, KernelMode, &returnSize)) && returnSize == Size) {
		return TRUE;
	}

	return FALSE;
}


TABLE_SEARCH_RESULT
MiFindNodeOrParent(
	IN PMM_AVL_TABLE Table,
	IN ULONG_PTR StartingVpn,
	OUT PMMADDRESS_NODE* NodeOrParent
) {
	PMMADDRESS_NODE Child;
	PMMADDRESS_NODE NodeToExamine;
	PMMVAD_SHORT    VpnCompare;
	ULONG_PTR       startVpn;
	ULONG_PTR       endVpn;

	if (Table->NumberGenericTableElements == 0) {
		return TableEmptyTree;
	}

	NodeToExamine = (PMMADDRESS_NODE)(Table->BalancedRoot);

	for (;;) {

		VpnCompare = (PMMVAD_SHORT)NodeToExamine;
		startVpn = VpnCompare->StartingVpn;
		endVpn = VpnCompare->EndingVpn;

#if defined( _WIN81_ ) || defined( _WIN10_ )
		startVpn |= (ULONG_PTR)VpnCompare->StartingVpnHigh << 32;
		endVpn |= (ULONG_PTR)VpnCompare->EndingVpnHigh << 32;
#endif  

		//
		// Compare the buffer with the key in the tree element.
		//

		if (StartingVpn < startVpn) {

			Child = NodeToExamine->LeftChild;

			if (Child != NULL) {
				NodeToExamine = Child;
			}
			else {

				//
				// Node is not in the tree.  Set the output
				// parameter to point to what would be its
				// parent and return which child it would be.
				//

				*NodeOrParent = NodeToExamine;
				return TableInsertAsLeft;
			}
		}
		else if (StartingVpn <= endVpn) {

			//
			// This is the node.
			//

			*NodeOrParent = NodeToExamine;
			return TableFoundNode;
		}
		else {

			Child = NodeToExamine->RightChild;

			if (Child != NULL) {
				NodeToExamine = Child;
			}
			else {

				//
				// Node is not in the tree.  Set the output
				// parameter to point to what would be its
				// parent and return which child it would be.
				//

				*NodeOrParent = NodeToExamine;
				return TableInsertAsRight;
			}
		}

	};
}

NTSTATUS
MemoryUtils::FindVAD(
	IN PEPROCESS pProcess,
	IN ULONG_PTR address,
	OUT PMMVAD_SHORT* pResult
) {
	NTSTATUS status = STATUS_SUCCESS;
	ULONG_PTR vpnStart = address >> PAGE_SHIFT;

	ASSERT(pProcess != NULL && pResult != NULL);
	if (pProcess == NULL || pResult == NULL)
		return STATUS_INVALID_PARAMETER;


	PMM_AVL_TABLE pTable = (PMM_AVL_TABLE)((PUCHAR)pProcess + 0x7d8);
	PMM_AVL_NODE pNode = (pTable->BalancedRoot);

	if (MiFindNodeOrParent(pTable, vpnStart, &pNode) == TableFoundNode) {
		*pResult = (PMMVAD_SHORT)pNode;
	}
	else {
		status = STATUS_NOT_FOUND;
	}

	return status;
}

PT_ENTRY_64* MemoryUtils::GetPte(
	PVOID VirtualAddress,
	CR3 HostCr3
) {
	ADDRESS_TRANSLATION_HELPER helper;
	UINT32 level;
	PT_ENTRY_64* finalEntry;
	PML4E_64* pml4;
	PML4E_64* pml4e;
	PDPTE_64* pdpt;
	PDPTE_64* pdpte;
	PDE_64* pd;
	PDE_64* pde;
	PTE_64* pt;
	PTE_64* pte;

	helper.AsUInt64 = (UINT64)VirtualAddress;

	PHYSICAL_ADDRESS    addr;

	addr.QuadPart = HostCr3.AddressOfPageDirectory << PAGE_SHIFT;

	pml4 = (PML4E_64*)MmGetVirtualForPhysical(addr);

	pml4e = &pml4[helper.AsIndex.Pml4];

	if (pml4e->Present == FALSE) {
		finalEntry = (PT_ENTRY_64*)pml4e;
		goto Exit;
	}

	addr.QuadPart = pml4e->PageFrameNumber << PAGE_SHIFT;

	pdpt = (PDPTE_64*)MmGetVirtualForPhysical(addr);

	pdpte = &pdpt[helper.AsIndex.Pdpt];

	if ((pdpte->Present == FALSE) || (pdpte->LargePage != FALSE)) {
		finalEntry = (PT_ENTRY_64*)pdpte;
		goto Exit;
	}

	addr.QuadPart = pdpte->PageFrameNumber << PAGE_SHIFT;

	pd = (PDE_64*)MmGetVirtualForPhysical(addr);

	pde = &pd[helper.AsIndex.Pd];

	if ((pde->Present == FALSE) || (pde->LargePage != FALSE)) {
		finalEntry = (PT_ENTRY_64*)pde;
		goto Exit;
	}

	addr.QuadPart = pde->PageFrameNumber << PAGE_SHIFT;

	pt = (PTE_64*)MmGetVirtualForPhysical(addr);

	pte = &pt[helper.AsIndex.Pt];

	finalEntry = (PT_ENTRY_64*)pte;
	return  (PT_ENTRY_64*)pte;

Exit:
	return finalEntry;
}

ULONGLONG
MemoryUtils::GetExportedFunction(
	CONST ULONGLONG mod,
	CONST CHAR* name
) {
	const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(mod);
	const auto nt_headers = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<ULONGLONG>(dos_header) + dos_header->e_lfanew);

	const auto data_directory = nt_headers->OptionalHeader.DataDirectory[0];
	const auto export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(mod + data_directory.VirtualAddress);

	const auto address_of_names = reinterpret_cast<ULONG*>(mod + export_directory->AddressOfNames);

	for (size_t i = 0; i < export_directory->NumberOfNames; i++)
	{
		const auto function_name = reinterpret_cast<const char*>(mod + address_of_names[i]);

		if (!_stricmp(function_name, name))
		{
			const auto name_ordinal = reinterpret_cast<unsigned short*>(mod + export_directory->AddressOfNameOrdinals)[i];

			const auto function_rva = mod + reinterpret_cast<ULONG*>(mod + export_directory->AddressOfFunctions)[name_ordinal];
			return function_rva;
		}
	}

	return 0;
}

BOOL
CheckMask(
	PCHAR Base,
	PCHAR Pattern,
	PCHAR Mask
) {
	for (; *Mask; ++Base, ++Pattern, ++Mask) {
		if (*Mask == 'x' && *Base != *Pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID
FindPattern(
	PCHAR Base,
	DWORD Length,
	PCHAR Pattern,
	PCHAR Mask
) {
	Length -= (DWORD)strlen(Mask);
	for (DWORD i = 0; i <= Length; ++i) {
		PVOID Addr = &Base[i];
		if (CheckMask((PCHAR)Addr, Pattern, Mask)) {
			return Addr;
		}
	}

	return 0;
}

PVOID
MemoryUtils::FindPatternImage(
	PCHAR Base,
	PCHAR Pattern,
	PCHAR Mask
) {
	PVOID Match = 0;

	PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);
	for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER Section = &Sections[i];
		if (*(PINT)Section->Name == 'EGAP' || memcmp(Section->Name, ".text", 5) == 0) {
			Match = FindPattern(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);
			if (Match) {
				break;
			}
		}
	}

	return Match;
}

DWORD
GetUserDirectoryTableBaseOffset() {
	RTL_OSVERSIONINFOW ver = { 0 };
	RtlGetVersion(&ver);

	switch (ver.dwBuildNumber)
	{
	case WINDOWS_1803:
		return 0x0278;
		break;
	case WINDOWS_1809:
		return 0x0278;
		break;
	case WINDOWS_1903:
		return 0x0280;
		break;
	case WINDOWS_1909:
		return 0x0280;
		break;
	case WINDOWS_2004:
		return 0x0388;
		break;
	case WINDOWS_20H2:
		return 0x0388;
		break;
	case WINDOWS_21H1:
		return 0x0388;
		break;
	default:
		return 0x0388;
	}
}

PVOID
MemoryUtils::ResolveRelativeAddress(
	PVOID Instruction,
	ULONG OffsetOffset,
	ULONG InstructionSize
) {
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

UCHAR
MemoryUtils::RandomNumber() {
	PVOID Base = MemoryUtils::GetKernelBase();

	auto cMmGetSystemRoutineAddress = reinterpret_cast<decltype(&MmGetSystemRoutineAddress)>(MemoryUtils::GetExportedFunction((ULONGLONG)Base, "MmGetSystemRoutineAddress"));

	UNICODE_STRING RoutineName = RTL_CONSTANT_STRING(L"RtlRandom");
	auto cRtlRandom = reinterpret_cast<decltype(&RtlRandom)>(cMmGetSystemRoutineAddress(&RoutineName));

	ULONG Seed = 1234765;
	ULONG Rand = cRtlRandom(&Seed) % 100;

	UCHAR RandInt = 0;

	if (Rand >= 101 || Rand <= -1)
		RandInt = 72;

	return (UCHAR)(Rand);
}
