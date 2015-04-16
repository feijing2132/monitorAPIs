// testHookProcess.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <stdio.h>
#include "Injectors.h"
using namespace std;

#ifndef INJECTORS_H_
#define INJECTORS_H_

#include <stdio.h>
#include <Windows.h>
#include "WindowsUtils.h"

#include <windows.h>
#include <stdio.h>
#include <fstream>
#include <stdlib.h>
#include <tlhelp32.h>

using namespace std;

int privileges(){
  HANDLE Token;
  TOKEN_PRIVILEGES tp;
  if(OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&Token))
  {
	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid);
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		if (AdjustTokenPrivileges(Token, 0, &tp, sizeof(tp), NULL, NULL)==0){
			return 1; //FAIL
		}else{
			return 0; //SUCCESS
		}
   }
   return 1;
}

int CheckOSVersion()
{
	/*
	* Windows XP = 1 (NT 5.0)
	* Windows Vista = 2 (NT 6.0)
	* Windows 7 = 3 (NT 6.1)
	* Windows 8 = 4 (NT 6.2)	 --> on Windows 8 CreateRemoteThread works perfectly!!
	*/
	OSVERSIONINFO osver;
	osver.dwOSVersionInfoSize = sizeof(osver);
	if (GetVersionEx(&osver))
	{
		if (!(osver.dwPlatformId == VER_PLATFORM_WIN32_NT))
			return 0;
		if (osver.dwMajorVersion == 5)
			return 1;
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 0)
			return 2;
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 1)
			return 3;
		if (osver.dwMajorVersion == 6 && osver.dwMinorVersion == 2)
			return 4;
	}
	return 0;
}

//TODO find better name
int bitset(){
	/*
	 * 32 bit = 32
	 * 64 bit = 64
	 * else = 0
	 */
	if (sizeof(void*) == 4)
		return 32;
	if (sizeof(void*) == 8)
		return 64;
	return 0;
}

/* NtCreateThreadEx helper */
typedef NTSTATUS (WINAPI *LPFUN_NtCreateThreadEx)
(
  OUT PHANDLE hThread,
  IN ACCESS_MASK DesiredAccess,
  IN LPVOID ObjectAttributes,
  IN HANDLE ProcessHandle,
  IN LPTHREAD_START_ROUTINE lpStartAddress,
  IN LPVOID lpParameter,
  IN BOOL CreateSuspended,
  IN DWORD StackZeroBits,
  IN DWORD SizeOfStackCommit,
  IN DWORD SizeOfStackReserve,
  OUT LPVOID lpBytesBuffer
);
struct NtCreateThreadExBuffer
{
  ULONG Size;
  ULONG Unknown1;
  ULONG Unknown2;
  PULONG Unknown3;
  ULONG Unknown4;
  ULONG Unknown5;
  ULONG Unknown6;
  PULONG Unknown7;
  ULONG Unknown8;
};
HANDLE NtCreateThreadEx(HANDLE process, LPTHREAD_START_ROUTINE Start, LPVOID lpParameter){
	HMODULE modNtDll = LoadLibrary("ntdll.dll");
	if(!modNtDll){
		printf("Error loading ntdll.dll\n");
		return 0;
	}
	LPFUN_NtCreateThreadEx funNtCreateThreadEx = (LPFUN_NtCreateThreadEx) GetProcAddress(modNtDll, "NtCreateThreadEx");
	if(!funNtCreateThreadEx){
	   printf("Error loading NtCreateThreadEx()\n");
	   return 0;
	}
	NtCreateThreadExBuffer ntbuffer;
	memset (&ntbuffer,0,sizeof(NtCreateThreadExBuffer));
	DWORD temp1 = 0;
	DWORD temp2 = 0;
	ntbuffer.Size = sizeof(NtCreateThreadExBuffer);
	ntbuffer.Unknown1 = 0x10003;
	ntbuffer.Unknown2 = 0x8;
	ntbuffer.Unknown3 = &temp2;
	ntbuffer.Unknown4 = 0;
	ntbuffer.Unknown5 = 0x10004;
	ntbuffer.Unknown6 = 4;
	ntbuffer.Unknown7 = &temp1;
   // ntbuffer.Unknown8 = 0;
	HANDLE hThread;
	NTSTATUS status = funNtCreateThreadEx(
						&hThread,
						0x1FFFFF,
						NULL,
						process,
						(LPTHREAD_START_ROUTINE) Start,
						lpParameter,
						FALSE, //start instantly
						0, //null
						0, //null
						0, //null
						&ntbuffer
						);
	return hThread;
}

BOOL isRemoteWow64(unsigned long pid){
	privileges();
	BOOL ret;
	HANDLE p = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	if(!p){
		throw exception("Can't open proccess");
	}
	IsWow64Process(p, &ret);
	CloseHandle(p);
	return ret;
}
BOOL amIWow64(){
	BOOL ret;
	IsWow64Process(GetCurrentProcess(), &ret);
	return ret;
}

DWORD injectDLLByRemoteThread(unsigned long pid, char* dllName){
	privileges();
	HANDLE p;
	p = OpenProcess(PROCESS_ALL_ACCESS,false,pid);
	if (p==NULL) return GetLastError();
	HMODULE hKernel32 = ::GetModuleHandle("Kernel32");
	LPVOID DataAddress = VirtualAllocEx(p, NULL, strlen(dllName) + 1, MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(p, DataAddress, dllName, strlen(dllName), NULL);

	// Use NtCreateThreadEx under vista and win7 if not x64 (TODO check dat)
	int tmp = CheckOSVersion();
	HANDLE thread;
	//doesn't seem to work under x64, hopefully CreateRemoteThread does
	if((tmp == 2 || tmp == 3) && bitset() != 64){
		thread = NtCreateThreadEx(p, (LPTHREAD_START_ROUTINE)GetProcAddress( hKernel32,"LoadLibraryA" ), DataAddress);
		printf("Use NtCreateThreadEx\n");
	}else{
		thread = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)GetProcAddress( hKernel32,"LoadLibraryA" ), DataAddress, 0, NULL);
		printf("Use CreateRemoteThread\n");
	}
	if (thread!=0){
		WaitForSingleObject(thread, INFINITE);
		VirtualFree(DataAddress, 0, MEM_RELEASE);
		CloseHandle(thread);
		CloseHandle(p);
	}else{
		printf("Error!\n");
	}
	return 0;
}


struct PARAMETERS{
	DWORD addr_proc;
	DWORD addr_mod;
	char txtMod[256];
	char txtFunc[256];
};
DWORD WINAPI _unloadHelper(PARAMETERS* pMem){
	typedef HMODULE (WINAPI *m_GetModuleHandleA)(LPCSTR lpModuleName);
	typedef FARPROC (WINAPI *m_GetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
	typedef void (*UNLOAD)(void);
	m_GetModuleHandleA i_GetModuleHandleA = (m_GetModuleHandleA)pMem->addr_mod;
	m_GetProcAddress i_GetProcAddress = (m_GetProcAddress)pMem->addr_proc;
	UNLOAD unload = (UNLOAD)i_GetProcAddress( i_GetModuleHandleA(pMem->txtMod), pMem->txtFunc);
	unload();
	return 0;
}
static DWORD USELESSS(){return 0;}
DWORD unloadRemoteLib(unsigned long pid, char* dllName){
	privileges();
	HANDLE p;
	p = OpenProcess(PROCESS_ALL_ACCESS,false,pid);
	if (p==NULL) return GetLastError();

	//TODO check nameSize
	PARAMETERS param;
	strcpy(param.txtMod, dllName);
	strcpy(param.txtFunc, "unload");
	param.addr_proc = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetProcAddress");
	param.addr_mod = (DWORD)GetProcAddress(GetModuleHandleA("kernel32.dll"), "GetModuleHandleA");

	DWORD size_myFunc = (PBYTE)USELESSS - (PBYTE)_unloadHelper;
	void *MyFuncAddress = VirtualAllocEx(p, NULL, size_myFunc, MEM_RESERVE|MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(p, MyFuncAddress, (void*)_unloadHelper, size_myFunc, NULL);
	void *DataAddress = VirtualAllocEx(p, NULL, sizeof(PARAMETERS), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(p, DataAddress, &param, sizeof(PARAMETERS), NULL);
	HANDLE thread = CreateRemoteThread(p, NULL, 0, (LPTHREAD_START_ROUTINE)MyFuncAddress, DataAddress, 0, NULL);
	if (thread!=0){
		WaitForSingleObject(thread, INFINITE);
		VirtualFree(DataAddress, 0, MEM_RELEASE);
		VirtualFree(MyFuncAddress, 0, MEM_RELEASE);
		CloseHandle(thread);
		CloseHandle(p);
		return 0;
	}
	return GetLastError();
}
#endif /* INJECTORS_H_ */

void usage(char *self){
	printf("USAGE: %s (-l|-u|-lu) ABSOULTE_DLL_NAME PID\n", self);
	printf("EXAMPLE 1 load library: %s -l d:/evil.dll 666\n", self);
	printf("EXAMPLE 2 unload library: %s -u d:/evil.dll 666\n", self);
	printf("EXAMPLE 3 load and unload after init: %s -lu d:/evil.dll 666\n\n", self);

	printf("To use the unload function the lib must export the following function: \n");
	printf("'extern \"C\" __declspec(dllexport) void unload()'\n");
	printf("Which unloads the lib. For example via this trick: \n");
	printf("'EXTERN_C IMAGE_DOS_HEADER __ImageBase;'\n");
	printf("'CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, &__ImageBase, 0, NULL);'\n");
}

int main(int argc, char** argv) {
	char *dll = "C:\\shared-Mac-mini-Porter\\monitorAPIs\\testHookProcess\\Debug\\fundll.dll";
	unsigned long pid = 8640;
	//if(argc != 4){
	//	usage(argv[0]);
	//	return 0;
	//}else
	{
		privileges();
		//dll = argv[2];
		//pid = atol(argv[3]);
		if( isRemoteWow64(pid) != amIWow64() ){
			printf("Local and remote app aren't compatible. Switch to x64 or x86 version\n");
			return 0;
		}

		/*if(strcmp(argv[1], "-l") == 0){
			printf("Inject status: %i\n", injectDLLByRemoteThread(pid, dll));
		}else if(strcmp(argv[1], "-u") == 0){
			printf("Remove status: %i\n", unloadRemoteLib(pid, dll));
		}else if(strcmp(argv[1], "-lu") == 0){*/
			printf("Inject status: %i\n", injectDLLByRemoteThread(pid, dll));
			printf("Remove status: %i\n", unloadRemoteLib(pid, dll));
		//}
	}
	return 0;
}