// MemoryLib.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "MEMDLL.h"

#include <Windows.h>
#include <Psapi.h>

MEMDLL_API BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege)
{
	LUID luid;
	if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
	{
		return FALSE;
	}

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)
	{
		return FALSE;
	}
	return TRUE;
}

MEMDLL_API bool setupPrivilege()
{
	HANDLE hProc = GetCurrentProcess();

	HANDLE hToken = NULL;
	if (!OpenProcessToken(hProc, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		return FALSE;
	}
	else {

		if (!SetPrivilege(hToken, SE_DEBUG_NAME)) {
			return FALSE;
		}
		return TRUE;
	}
}

MEMDLL_API char* getBaseName(HANDLE hProc)
{
	char fileName[MAX_PATH];
	if (!GetProcessImageFileNameA(hProc, fileName, MAX_PATH)) {
		return NULL;
	}
	else {
		return strrchr(fileName, '\\');
	}
}

MEMDLL_API HMODULE getBaseAddress(HANDLE hProc, char fileName[MAX_PATH])
{
	DWORD nMod;
	HMODULE hMods[1024];
	if (EnumProcessModules(hProc, hMods, sizeof(hMods), &nMod))
	{
		for (DWORD i = 0; i <= (nMod / sizeof(HMODULE)); i++)
		{
			char modName[MAX_PATH];
			if (GetModuleFileNameExA(hProc, hMods[i], modName, sizeof(modName) / sizeof(char))) {
				if (strcmp(fileName, strrchr(modName, '\\')) == 0) {
					return hMods[i];
				}
			}
		}
	}
	return NULL;
}

MEMDLL_API DWORD getPointerAddress(HANDLE hProc, DWORD offset, DWORD offsets[], int offsetLength)
{
	DWORD gameBaseAddr = (DWORD) (getBaseAddress(hProc, getBaseName(hProc)));
	if (!gameBaseAddr) {
		return NULL;
	}

	DWORD baseAddr;
	if (!ReadProcessMemory(hProc, (LPVOID)(gameBaseAddr + offset), &baseAddr, sizeof(baseAddr), NULL)) {
		return NULL;
	}

	DWORD ptrAddr = baseAddr;
	for (int i = 0; i < offsetLength; i++) {
		if (!ReadProcessMemory(hProc, (LPVOID)(ptrAddr + offsets[i]), &ptrAddr, sizeof(ptrAddr), NULL)) {
			return NULL;
		}
	}

	DWORD address = ptrAddr + offsets[offsetLength];
	if (!address) {
		return NULL;
	}
	return address;
}

MEMDLL_API HWND getWindow(LPCSTR appClass, LPCSTR appTitle) {
	HWND hWnd = FindWindowA(appClass, appTitle);
	if (!hWnd) {
		return NULL;
	}
	return hWnd;
}

MEMDLL_API DWORD getPID(HWND hWnd)
{
	DWORD pid;
	if (!GetWindowThreadProcessId(hWnd, &pid)) {
		return NULL;
	}
	return pid;
}

MEMDLL_API HANDLE getProcess(DWORD pid)
{
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (!hProc) {
		return NULL;
	}
	return hProc;
}

MEMDLL_API DWORD readDword(HANDLE hProc, DWORD_PTR address)
{
	DWORD result = 0;
	if (!ReadProcessMemory(hProc, (void*)address, &result, sizeof(result), NULL))
	{
		return NULL;
	}
	return result;
}

MEMDLL_API bool WriteDword(HANDLE hProc, DWORD_PTR address, DWORD value)
{
	if (!WriteProcessMemory(hProc, (void*)address, &value, sizeof(value), NULL))
	{
		return FALSE;
	}
	return TRUE;
}

MEMDLL_API SIZE_T IsArrayMatch(HANDLE proc, SIZE_T address, SIZE_T segmentSize, BYTE array[], SIZE_T arraySize)
{
	BYTE* procArray = new BYTE[segmentSize];

	if (!ReadProcessMemory(proc, (void*)address, procArray, segmentSize, NULL))
	{
		delete[] procArray;
		return NULL;
	}

	for (SIZE_T i = 0; i < segmentSize; i++)
	{
		if ((array[0] == procArray[i]) && ((i + arraySize) < segmentSize))
		{
			if (!memcmp(array, procArray + i, arraySize))
			{
				delete[] procArray;
				return address + i;
			}
		}
	}
	delete[] procArray;
	return NULL;
}

MEMDLL_API SIZE_T ScanSegments(HANDLE proc, BYTE array[], DWORD protectionFlags = 0)
{
	MEMORY_BASIC_INFORMATION meminfo;
	LPCVOID addr = 0;
	SIZE_T result = 0;

	while (VirtualQueryEx(proc, addr, &meminfo, sizeof(meminfo)))
	{

		if (protectionFlags == 0 || protectionFlags & meminfo.AllocationProtect)
		{
			result = IsArrayMatch(proc, (SIZE_T)meminfo.BaseAddress, meminfo.RegionSize, array, sizeof(array));
			if (result) {
				return result;
			}
			addr = (unsigned char*)meminfo.BaseAddress + meminfo.RegionSize;
		}
	}
	return NULL;
}