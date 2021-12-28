#pragma once

// *** Listed versions are not comprehensive

// 1903, 1909, 20h1, 20h2, 21h1
// 48 8D 0D ? ? ? ? E8 ? ? ? ? 4C 8B 8C
#define PIDDB_LOCK_PATTERN "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C"
#define PIDDB_LOCK_MASK "xxx????x????xxx"

// 1903, 1909, 20h1, 20h2, 21h1
// 66 03 D2 48 8D 0D
#define PIDDB_TABLE_PATTERN "\x66\x03\xD2\x48\x8D\x0D"
#define PIDDB_TABLE_MASK "xxxxxx"

// 1903, 1909, 20h1, 20h2, 21h1
// 4C 8B 15 ? ? ? ? 4C 8B C9
#define MMU_PATTERN "\x4C\x8B\x15\x00\x00\x00\x00\x4C\x8B\xC9"
#define MMU_MASK "xxx????xxx"

// 1903, 1909, 20h1, 20h2, 21h1
// 8B 05 ? ? ? ? 83 F8 32
#define MML_PATTERN "\x8B\x05\x00\x00\x00\x00\x83\xF8\x32"
#define MML_MASK "xx????xxx"

// 1903, 1909, 20h1, 20h2, 21h1
// 4C 8D 35 ? ? ? ? E9 ? ? ? ? 8B 84 24
#define CI_DLL_KERNEL_HASH_BUCKET_PATTERN "\x4C\x8D\x35\x00\x00\x00\x00\xE9\x00\x00\x00\x00\x8B\x84\x24"
#define CI_DLL_KERNEL_HASH_BUCKET_MASK "xxx????x????xxx"

// 1903, 1909, 20h1, 20h2, 21h1
// 48 8B 05 ? ? ? ? E8 ? ? ? ? 8B C8 85 C0 78 40
#define KD_ENUMERATE_DEBUGGING_DEVICES_PATTERN "\x48\x8B\x05\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x8B\xC8\x85\xC0\x78\x40"
#define KD_ENUMERATE_DEBUGGING_DEVICES_MASK "xxx????x????xxxxxx"

// 1903, 1909, 20h1, 20h2, 21h1
// 48 8B 05 ? ? ? ? 45 33 C0 E8
#define HVLP_QUERY_APIC_ID_AND_NUMA_NODE_PATTERN "\x48\x8B\x05\x00\x00\x00\x00\x45\x33\xC0\xE8"
#define HVLP_QUERY_APIC_ID_AND_NUMA_NODE_MASK "xxx????xxxx"

// 1903, 1909, 20h1, 20h2, 21h1
// 48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20 83 0A FF
#define HVLP_QUERY_APIC_ID_AND_NUMA_NODE_CALL_PATTERN "\x48\x89\x5C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x20\x83\x0A\xFF"
#define HVLP_QUERY_APIC_ID_AND_NUMA_NODE_CALL_MASK "xxxx?xxxx?xxxxxxxx"

// 2004, 20h2
// 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 48 83 EC 30 48 8B E9 41 8B F8 B9 ? ? ? ? 48 8B F2 8B D1 41 B8 ? ? ? ?
#define MI_ALLOCATE_VAD_PATTERN "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x48\x83\xEC\x30\x48\x8B\xE9\x41\x8B\xF8\xB9\x00\x00\x00\x00\x48\x8B\xF2\x8B\xD1\x41\xB8\x00\x00\x00\x00"
#define MI_ALLOCATE_VAD_MASK "xxxx?xxxx?xxxx?xxxxxxxxxxxx????xxxxxxx????"

// 2004, 20h2
// 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC 20 8B 41 18 48 8B D9 44 0F B6 71 ? 45 33 E4
#define MI_INSERT_VAD_CHANGES_PATTERN "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x8B\x41\x18\x48\x8B\xD9\x44\x0F\xB6\x71\x00\x45\x33\xE4"
#define MI_INSERT_VAD_CHANGES_MASK "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxxxxxxxxx?xxx"

// 2004, 20h2
// 48 89 5C 24 ? 48 89 6C 24 ? 48 89 74 24 ? 57 41 54 41 55 41 56 41 57 48 83 EC 20 8B 41 1C 33 ED 0F B6 59 21
#define MI_INSERT_VAD_PATTERN "\x48\x89\x5C\x24\x00\x48\x89\x6C\x24\x00\x48\x89\x74\x24\x00\x57\x41\x54\x41\x55\x41\x56\x41\x57\x48\x83\xEC\x20\x8B\x41\x1C\x33\xED\x0F\xB6\x59\x21"
#define MI_INSERT_VAD_MASK "xxxx?xxxx?xxxx?xxxxxxxxxxxxxxxxxxxxxx"
