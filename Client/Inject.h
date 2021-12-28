#pragma once
#include <Windows.h>

namespace Inject {
	VOID
		Map(
			LPCSTR WindowClassName,
			LPCSTR DllPath,
			PCHAR SpoofPageProtection,
			PCHAR RemoveVADNode,
			PCHAR AllocateBehindThreadStack
		);
}