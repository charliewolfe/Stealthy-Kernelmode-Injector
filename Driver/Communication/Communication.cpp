#include "Communication.h"
#include "CommunicationType.h"
#include "../Utils/MemoryUtils.h"
#include "../API.h"
#include "../Define/Patterns.h"
#include "../Library/skCrypter.h"

#define DATA_UNIQUE (0x8392)
#define RELATIVE_ADDR(addr, size) ((PVOID)((PBYTE)(addr) + *(PINT)((PBYTE)(addr) + ((size) - (INT)sizeof(INT))) + (size)))

INT64(NTAPI* EnumerateDebuggingDevicesOriginal)(PVOID, PVOID);
INT64(__fastcall* HvlpQueryApicIdAndNumaNodeOriginal)(PVOID, PVOID, PVOID);
INT64(__fastcall* HvlpQueryProcessorNodeOriginal)(PVOID, PVOID, PVOID);

INT64 NTAPI
hkHvlpQueryApicIdAndNumaNode(
	PREQUEST_DATA Data,
	PINT64 Status,
	PVOID a3
) {
	REQUEST_DATA SafeData = { 0 };
	if (!MemoryUtils::SafeCopy(&SafeData, Data, sizeof(SafeData)) || SafeData.Unique != DATA_UNIQUE) {
		return EnumerateDebuggingDevicesOriginal(Data, Status);
	}

	switch (SafeData.Type) {
	case REQUEST_READ_MEMORY: {
		READ_MEMORY Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::ReadMemory(&Args);
		return 0;
	}

	case REQUEST_WRITE_MEMORY: {
		WRITE_MEMORY Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::WriteMemory(&Args);
		return 0;
	}

	case REQUEST_PROTECT_MEMORY: {
		PROTECT_MEMORY Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::ProtectMemory(&Args);
		return 0;
	}

	case REQUEST_ALLOC_MEMORY: {
		ALLOC_MEMORY Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::AllocMemory(&Args);
		return 0;
	}

	case REQUEST_FREE_MEMORY: {
		FREE_MEMORY Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::FreeMemory(&Args);
		return 0;
	}

	case REQUEST_GET_PTE: {
		GET_PTE Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::GetPte(&Args);
		return 0;
	}

	case REQUEST_SET_PTE: {
		SET_PTE Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::SetPte(&Args);
		return 0;
	}

	case REQUEST_QUERY_VIRTUAL_MEMORY: {
		QUERY_VIRTUAL_MEMORY Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::QueryVirtualMemory(&Args);
		return 0;
	}

	case REQUEST_GET_VAD_FLAGS: {
		GET_VAD_FLAGS Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::GetVADFlags(&Args);
		return 0;
	}

	case REQUEST_SET_VAD_FLAGS: {
		SET_VAD_FLAGS Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::SetVADFlags(&Args);
		return 0;
	}

	case REQUEST_REMOVE_VAD_NODE: {
		REMOVE_VAD Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::RemoveVADNode(&Args);
		return 0;
	}

	case REQUEST_ALLOC_VAD: {
		ALLOCATE_VAD Args;
		if (!MemoryUtils::SafeCopy(&Args, SafeData.Arguments, sizeof(Args))) {
			*Status = STATUS_ACCESS_VIOLATION;
			return 0;
		}
		*Status = API::AllocateVad(&Args);
		return 0;
	}
	}

	*Status = STATUS_NOT_IMPLEMENTED;
	return 0;
}

NTSTATUS
Communication::Initialize() {
	PCHAR Base = (PCHAR)MemoryUtils::GetKernelBase();

	auto xKdEnumerateDebuggingDevicesPattern = skCrypt(KD_ENUMERATE_DEBUGGING_DEVICES_PATTERN);
	auto xKdEnumerateDebuggingDevicesMask = skCrypt(KD_ENUMERATE_DEBUGGING_DEVICES_MASK);
	PBYTE FunctionAddress = (PBYTE)MemoryUtils::FindPatternImage(Base, xKdEnumerateDebuggingDevicesPattern, xKdEnumerateDebuggingDevicesMask);
	xKdEnumerateDebuggingDevicesPattern.clear();
	xKdEnumerateDebuggingDevicesMask.clear();
	if (!FunctionAddress) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "failed to get xKdEnumerateDebuggingDevices");
		return STATUS_UNSUCCESSFUL;
	}

	auto HvlpQueryApicIdAndNumaNodePattern = skCrypt(HVLP_QUERY_APIC_ID_AND_NUMA_NODE_PATTERN);
	auto HvlpQueryApicIdAndNumaNodeMask = skCrypt(HVLP_QUERY_APIC_ID_AND_NUMA_NODE_MASK);
	PBYTE HvlpQueryApicIdAndNumaNodeAddress = (PBYTE)MemoryUtils::FindPatternImage(Base, HvlpQueryApicIdAndNumaNodePattern, HvlpQueryApicIdAndNumaNodeMask);
	HvlpQueryApicIdAndNumaNodePattern.clear();
	HvlpQueryApicIdAndNumaNodeMask.clear();
	if (!HvlpQueryApicIdAndNumaNodeAddress) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "failed to get HvlpQueryApicIdAndNumaNodeAddress");
		return STATUS_UNSUCCESSFUL;
	}

	auto HvlpQueryApicIdAndNumaNodeCallPattern = skCrypt(HVLP_QUERY_APIC_ID_AND_NUMA_NODE_CALL_PATTERN);
	auto HvlpQueryApicIdAndNumaNodeCallMask = skCrypt(HVLP_QUERY_APIC_ID_AND_NUMA_NODE_CALL_MASK);
	PBYTE HvlpQueryApicIdAndNumaNodeCallAddress = (PBYTE)MemoryUtils::FindPatternImage(Base, HvlpQueryApicIdAndNumaNodeCallPattern, HvlpQueryApicIdAndNumaNodeCallMask);
	HvlpQueryApicIdAndNumaNodeCallPattern.clear();
	HvlpQueryApicIdAndNumaNodeCallMask.clear();
	if (!HvlpQueryApicIdAndNumaNodeAddress) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "failed to get HvlpQueryApicIdAndNumaNodeCallAddress");
		return STATUS_UNSUCCESSFUL;
	}

	*(PVOID*)&HvlpQueryApicIdAndNumaNodeOriginal = InterlockedExchangePointer((volatile PVOID*)RELATIVE_ADDR(HvlpQueryApicIdAndNumaNodeAddress, 7), (PVOID)hkHvlpQueryApicIdAndNumaNode);
	*(PVOID*)&EnumerateDebuggingDevicesOriginal = InterlockedExchangePointer((volatile PVOID*)RELATIVE_ADDR(FunctionAddress, 7), (PVOID)HvlpQueryApicIdAndNumaNodeCallAddress);

	return STATUS_SUCCESS;
}