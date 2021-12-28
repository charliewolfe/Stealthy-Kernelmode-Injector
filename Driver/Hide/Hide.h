#pragma once
#include <ntifs.h>

namespace Hide {
	NTSTATUS
		Mapper(
			UNICODE_STRING DriverName
		);
}
