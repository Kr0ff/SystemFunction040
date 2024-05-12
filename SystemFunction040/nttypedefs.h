#pragma once
#include <windows.h>

#define RTL_ENCRYPT_MEMORY_SIZE 8

// https://doxygen.reactos.org/d3/dad/ksecdd_8h.html
// https://doxygen.reactos.org/d3/dad/ksecdd_8h_source.html
enum OptionFlags {
	RTL_ENCRYPT_OPTION_SAME_PROCESS = 0,
	RTL_ENCRYPT_OPTION_CROSS_PROCESS = 1,
	RTL_ENCRYPT_OPTION_SAME_LOGON = 2
};

// SystemFunction040 = RtlEncryptMemory
// https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlencryptmemory
// Below taken from https://source.winehq.org/WineAPI/SystemFunction040.html
typedef NTSTATUS(NTAPI* t_SystemFunction040)
(
	PVOID memory,
	ULONG length,
	ULONG flags
);

// https://source.winehq.org/WineAPI/advapi32.html
// https://source.winehq.org/WineAPI/SystemFunction041.html
// https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtldecryptmemory
typedef NTSTATUS(NTAPI* t_SystemFunction041)
(
	PVOID memory,
	ULONG length,
	ULONG flags
);

