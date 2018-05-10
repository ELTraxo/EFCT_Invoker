#include "CMemory.h"

HANDLE Memory::GetProcHandle(const wchar_t * szProcName)
{
	HANDLE hProc = NULL;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(hSnap, &pe32))
	{
		if (!wcscmp(szProcName, pe32.szExeFile))
		{
			hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
		}
		else
		{
			while (Process32Next(hSnap, &pe32))
			{
				if (!wcscmp(szProcName, pe32.szExeFile))
				{
					hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
					break;
				}
			}
		}
	}

	return hProc; //failed
}

bool Memory::HookEx(HANDLE hProc, void * pLocation, void * pHook, unsigned int uLen)
{
	//if there isn't enough space to place a hook, fail
	if (uLen < 5)
		return false;

	DWORD dwOld; // old protection
				 //if we can't change the protection to what we need, fail
	if (!VirtualProtectEx(hProc, pLocation, uLen, PAGE_EXECUTE_READWRITE, &dwOld))
		return false;

	uintptr_t iLocation = (uintptr_t)pLocation;
	uintptr_t iHook = (uintptr_t)pHook;

	DWORD iOffset = iHook - (iLocation + 5);

	char* buffer = new char[uLen]; //create a buffer
	memset(buffer, 0x90, uLen);
	buffer[0] = (char)0xE9; // 
	memcpy(&buffer[1], &iOffset, sizeof(DWORD));

	if (!WriteProcessMemory(hProc, pLocation, buffer, uLen, nullptr))
		return false;

	VirtualProtectEx(hProc, pLocation, uLen, dwOld, nullptr);

	delete[] buffer;
	return true;
}
