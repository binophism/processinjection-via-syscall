#include <Windows.h>
#include <tchar.h>
#include <TlHelp32.h>
#include "function signature.h"
int FindProcess(LPCWSTR arg_procname)
{
	HMODULE hKernel32 = LoadLibraryW(L"KERNEL32.DLL");
	CreateToolhelp32SnapshotEx pCreateToolhelp32Snapshot = (CreateToolhelp32SnapshotEx)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
	Process32FirstEx pProcess32First = (Process32FirstEx)GetProcAddress(hKernel32, "Process32FirstW");
	Process32NextEx pProcess32Next = (Process32NextEx)GetProcAddress(hKernel32, "Process32NextW");
	int PID = 0;

	PROCESSENTRY32 processEntry;
	processEntry.dwSize = sizeof(PROCESSENTRY32);
	HANDLE hSnapshotProcess = pCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (pProcess32First(hSnapshotProcess, &processEntry) == TRUE) {
		while (pProcess32Next(hSnapshotProcess, &processEntry) == TRUE) {
			if (wcscmp(processEntry.szExeFile, arg_procname) == 0) {
				PID = processEntry.th32ProcessID;
				break;
			}
		}
	}
	CloseHandle(hSnapshotProcess);
	return PID;
}
WCHAR* ascii_to_wide_str(CHAR* lpMultiByteStr)
{

	/* Get the required size */
	INT iNumChars = MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, NULL, 0);

	/* Allocate new wide string */

	SIZE_T Size = (1 + iNumChars) * sizeof(WCHAR);
	WCHAR* lpWideCharStr = (WCHAR*)(malloc(Size));

	if (lpWideCharStr) {
		SecureZeroMemory(lpWideCharStr, Size);
		/* Do the conversion */
		iNumChars = MultiByteToWideChar(CP_ACP, 0, lpMultiByteStr, -1, lpWideCharStr, iNumChars);
	}
	return lpWideCharStr;
}
BOOL cpuid_hypervisor_vendor()
{
	INT CPUInfo[4] = { -1 };
	CHAR szHypervisorVendor[0x40];
	WCHAR* pwszConverted;

	BOOL bResult = FALSE;

	const TCHAR* szBlacklistedHypervisors[] = {
		_T("KVMKVMKVM\0\0\0"),	/* KVM */
		_T("VMwareVMware"),		/* VMware */
		_T("XenVMMXenVMM"),		/* Xen */
		_T("prl hyperv  "),		/* Parallels */
		_T("VBoxVBoxVBox"),		/* VirtualBox */
	};
	WORD dwlength = sizeof(szBlacklistedHypervisors) / sizeof(szBlacklistedHypervisors[0]);

	// __cpuid with an InfoType argument of 0 returns the number of
	// valid Ids in CPUInfo[0] and the CPU identification string in
	// the other three array elements. The CPU identification string is
	// not in linear order. The code below arranges the information 
	// in a human readable form.
	__cpuid(CPUInfo, 0x40000000);
	memset(szHypervisorVendor, 0, sizeof(szHypervisorVendor));
	memcpy(szHypervisorVendor, CPUInfo + 1, 12);

	for (int i = 0; i < dwlength; i++)
	{
		pwszConverted = ascii_to_wide_str(szHypervisorVendor);
		if (pwszConverted) {

			bResult = (_tcscmp(pwszConverted, szBlacklistedHypervisors[i]) == 0);

			free(pwszConverted);

			if (bResult)
				return TRUE;
		}
	}

	return FALSE;
}