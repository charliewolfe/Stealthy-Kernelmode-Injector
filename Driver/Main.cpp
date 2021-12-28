#define _KERNEL_MODE

#include <ntifs.h>
#include "Communication/Communication.h"
#include "Hide/Hide.h"

VOID
TemporaryThread(
	PVOID StartContext
) {
	Communication::Initialize();

	// Change to the name of the driver used to map
	Hide::Mapper(RTL_CONSTANT_STRING(L"mapper.sys"));
}

NTSTATUS
DriverEntry(
	PDRIVER_OBJECT pDriverObject,
	PUNICODE_STRING pRegistryPath
) {
	UNREFERENCED_PARAMETER(pDriverObject);
	UNREFERENCED_PARAMETER(pRegistryPath);
	PAGED_CODE();

	HANDLE hTemporaryThread = NULL;
	if (!NT_SUCCESS(PsCreateSystemThread(
		&hTemporaryThread,
		GENERIC_ALL,
		NULL,
		NULL,
		NULL,
		TemporaryThread,
		NULL
	))) {
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}
