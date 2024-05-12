#pragma once
#include <windows.h>
#include <tchar.h>

FARPROC GetNtApiAddress(const char *NTApiName) {

	HMODULE module = NULL;
	FARPROC address = NULL;

	module = GetModuleHandle(_T("ntdll.dll"));
	if (module == NULL) {
		return NULL;
	}

	address = GetProcAddress(module, NTApiName);
	if (address == NULL) {
		return NULL;
	}

	return address;
}