#include <stdio.h>
#include <Windows.h>
#include "Driver/Driver.h"
#include "Library/skCrypter.h"
#include "Inject.h"

INT main(
    INT Argc, 
    CHAR* Argv[]
) {
	if (Argc < 6) {
		printf("Usage: Client.exe <Window class name> <DLL> <Spoof page protection> <Remove VAD node> <Allocate behind thread stack>\n");
		printf("<Spoof Page Protection>:\n");
		printf("	0 - Do not spoof page protection\n");
		printf("	1 - Spoof page protection via PTE manipulation\n");
		printf("	2 - Spoof page protection via VAD manipulation\n");
		printf("\n<Remove VAD node>:\n");
		printf("	0 - Do not remove VAD node\n");
		printf("	1 - Remove VAD node\n");
		printf("\n<Allocate behind thread stack>:\n");
		printf("	0 - Randomly allocate memory\n");
		printf("	1 - Allocate memory behind thread stack");
		return 1;
	}

	if (!NT_SUCCESS(Driver::Initialize())) {
		auto Text = skCrypt("Driver is not loaded\n");
		printf(Text);
		Text.clear();
		Sleep(2000);
		return 1;
	}
	Inject::Map(Argv[1], Argv[2], Argv[3], Argv[4], Argv[5]);

    return 0;
}