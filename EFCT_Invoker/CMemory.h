#pragma once
#include <Windows.h>
#include <TlHelp32.h>

class Memory
{
public:
	static HANDLE GetProcHandle(const wchar_t* szProcName);
	static bool HookEx(HANDLE hProc, void* pLocation, void* pHook, unsigned int uLen);
};

