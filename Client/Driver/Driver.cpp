#include <stdio.h>
#include <ntstatus.h>
#include "Driver.h"
#include "../Library/skCrypter.h"

PVOID(NTAPI* NtConvertBetweenAuxiliaryCounterAndPerformanceCounter)(PVOID, PVOID, PVOID, PVOID);

NTSTATUS
Driver::Initialize() {
	auto Module = LoadLibrary(skCrypt(L"ntdll.dll"));
	if (!Module) {
		return STATUS_UNSUCCESSFUL;
	}

	*reinterpret_cast<PVOID*>(&NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) = GetProcAddress(Module, skCrypt("NtConvertBetweenAuxiliaryCounterAndPerformanceCounter"));
	if (!NtConvertBetweenAuxiliaryCounterAndPerformanceCounter) {
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}

NTSTATUS
SendRequest(
	REQUEST_TYPE Type,
	PVOID Args,
	SIZE_T ArgsSize
) {
	REQUEST_DATA Request = { 0 };
	Request.Unique = DATA_UNIQUE;
	Request.Type = Type;
	Request.Arguments = Args;

	auto RequestPtr = &Request;

	auto Status = 0ULL;
	NtConvertBetweenAuxiliaryCounterAndPerformanceCounter(0, &RequestPtr, &Status, 0);
	return static_cast<NTSTATUS>(Status);
}

NTSTATUS
Driver::API::ReadMemory(
	IN CONST HANDLE Pid,
	IN CONST PVOID Address,
	IN CONST ULONG Size,
	OUT CONST PVOID pOut
) {
	READ_MEMORY Message;
	Message.ProcessId = Pid;
	Message.Address = (DWORD64)Address;
	Message.Size = Size;
	Message.pOut = pOut;

	return SendRequest(REQUEST_TYPE::REQUEST_READ_MEMORY, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::WriteMemory(
	IN CONST HANDLE Pid,
	IN CONST DWORD64 Ptr,
	IN CONST ULONG Size,
	IN CONST PVOID pSrc
) {
	WRITE_MEMORY Message;
	Message.ProcessId = Pid;
	Message.Address = Ptr;
	Message.Size = Size;
	Message.pSrc = pSrc;

	return SendRequest(REQUEST_TYPE::REQUEST_WRITE_MEMORY, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::ProtectMemory(
	IN CONST HANDLE ProcessId,
	IN CONST PVOID Address,
	IN CONST DWORD Size,
	IN OUT CONST PVOID pInOutProtect
) {
	PROTECT_MEMORY Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.Size = Size;
	Message.InOutProtect = pInOutProtect;

	return SendRequest(REQUEST_TYPE::REQUEST_PROTECT_MEMORY, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::AllocMemory(
	IN CONST HANDLE ProcessId,
	OUT CONST PVOID pOut,
	IN CONST DWORD Size,
	IN CONST DWORD Protect
) {
	ALLOC_MEMORY Message;
	Message.ProcessId = ProcessId;
	Message.pOut = pOut;
	Message.Size = Size;
	Message.Protect = Protect;

	return SendRequest(REQUEST_TYPE::REQUEST_ALLOC_MEMORY, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::FreeMemory(
	IN CONST HANDLE ProcessId,
	IN CONST PVOID Address
) {
	FREE_MEMORY Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;

	return SendRequest(REQUEST_TYPE::REQUEST_FREE_MEMORY, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::GetPte(
	IN CONST HANDLE ProcessId,
	IN CONST PVOID Address,
	OUT CONST PVOID pOut
) {
	GET_PTE Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.pOut = pOut;

	return SendRequest(REQUEST_TYPE::REQUEST_GET_PTE, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::SetPte(
	IN CONST HANDLE ProcessId,
	IN CONST PVOID Address,
	IN CONST PTE_64 Pte
) {
	SET_PTE Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.Pte = Pte;

	return SendRequest(REQUEST_TYPE::REQUEST_SET_PTE, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::QueryVirtualMemory(
	IN CONST HANDLE ProcessId,
	IN CONST PVOID Address,
	OUT CONST PVOID pOut
) {
	QUERY_VIRTUAL_MEMORY Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.pOut = pOut;

	return SendRequest(REQUEST_TYPE::REQUEST_QUERY_VIRTUAL_MEMORY, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::GetVADFlags(
	IN CONST HANDLE ProcessId,
	IN CONST PVOID Address,
	OUT CONST PVOID pOut
) {
	GET_VAD_FLAGS Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.pOut = pOut;

	return SendRequest(REQUEST_TYPE::REQUEST_GET_VAD_FLAGS, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::SetVADFlags(
	IN CONST HANDLE ProcessId,
	IN CONST PVOID Address,
	IN CONST MMVAD_FLAGS VADFlags
) {
	SET_VAD_FLAGS Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.VADFlags = VADFlags;

	return SendRequest(REQUEST_TYPE::REQUEST_SET_VAD_FLAGS, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::RemoveVADNode(
	IN CONST HANDLE ProcessId,
	IN CONST PVOID Address
) {
	REMOVE_VAD Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;

	return SendRequest(REQUEST_TYPE::REQUEST_REMOVE_VAD_NODE, &Message, sizeof(Message));
}

NTSTATUS
Driver::API::AllocateVAD(
	IN CONST HANDLE ProcessId,
	IN CONST PVOID Address,
	IN CONST ULONGLONG Size
) {
	ALLOCATE_VAD Message;
	Message.ProcessId = ProcessId;
	Message.Address = Address;
	Message.Size = Size;

	return SendRequest(REQUEST_TYPE::REQUEST_ALLOC_VAD, &Message, sizeof(Message));
}
