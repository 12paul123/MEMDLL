// The following ifdef block is the standard way of creating macros which make exporting
// from a DLL simpler. All files within this DLL are compiled with the MEMDLL_EXPORTS
// symbol defined on the command line. This symbol should not be defined on any project
// that uses this DLL. This way any other project whose source files include this file see
// MEMDLL_API functions as being imported from a DLL, whereas this DLL sees symbols
// defined with this macro as being exported.
#ifdef MEMDLL_EXPORTS
#define MEMDLL_API __declspec(dllexport)
#else
#define MEMDLL_API __declspec(dllimport)
#endif

extern "C"
{
	MEMDLL_API bool setupPrivilege();
	MEMDLL_API HWND getWindow(LPCSTR appClass, LPCSTR appTitle);
	MEMDLL_API DWORD getPID(HWND hWnd);
	MEMDLL_API HANDLE getProcess(DWORD pid);
	MEMDLL_API HMODULE getBaseAddress(HANDLE hProc, char fileName[MAX_PATH]);
	MEMDLL_API DWORD getPointerAddress(HANDLE hProc, DWORD offset, DWORD offsets[], int offsetLength);
	MEMDLL_API DWORD readDword(HANDLE hProc, DWORD_PTR address);
	MEMDLL_API bool WriteDword(HANDLE hProc, DWORD_PTR address, DWORD value);
	MEMDLL_API SIZE_T ScanSegments(HANDLE proc, BYTE array[], DWORD protectionFlags);
}
