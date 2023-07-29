#pragma once
#include <Windows.h>
#include <TlHelp32.h>
typedef BOOL(WINAPI* CloseHandleEx)(HANDLE hObject);
typedef HANDLE(WINAPI* CreateToolhelp32SnapshotEx)(DWORD dwFlags, DWORD th32ProcessID);
typedef BOOL(WINAPI* Process32FirstEx)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
typedef BOOL(WINAPI* Process32NextEx)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);
int FindProcess(LPCWSTR arg_procname);
BOOL cpuid_hypervisor_vendor();
WCHAR* ascii_to_wide_str(CHAR* lpMultiByteStr);
