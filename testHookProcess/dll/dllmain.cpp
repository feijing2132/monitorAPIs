// dllmain.cpp : Implementation of DllMain.

#include "stdafx.h"
#include "resource.h"
#include "dll_i.h"
#include "dllmain.h"

#include "windows.h"
#include "process.h"
#include "tlhelp32.h"
#include "stdio.h"
//#define _WIN64
EXTERN_C IMAGE_DOS_HEADER __ImageBase;

extern "C" __declspec(dllexport) void unload() {
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, &__ImageBase, 0, NULL);
}

//#pragma comment(lib,"th32.lib")

PIMAGE_DOS_HEADER pDosHeader;
PIMAGE_NT_HEADERS pNTHeaders;
PIMAGE_OPTIONAL_HEADER    pOptHeader;
PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;
PIMAGE_THUNK_DATA        pThunkData;
PIMAGE_IMPORT_BY_NAME    pImportByName;
HMODULE hMod;


// 定义MessageBoxA函数原型
typedef int (WINAPI *PFNMESSAGEBOX)(HWND, LPCTSTR, LPCTSTR, UINT uType);
int WINAPI MessageBoxProxy(IN HWND hWnd, IN LPCTSTR lpText, IN LPCTSTR lpCaption, IN UINT uType);

int * addr = (int *)MessageBox;     //保存函数的入口地址
int * myaddr = (int *)MessageBoxProxy;


void ThreadProc(void *param);//线程函数

CdllModule _AtlModule;

// DLL Entry Point
extern "C" BOOL WINAPI DllMain(HINSTANCE hInstance, DWORD Reason, LPVOID lpReserved)
{
	//switch(Reason){
	//	case DLL_PROCESS_ATTACH:
	//	{
	//		char buffer[256];
	//		wsprintfA(buffer, "Injection into process %i successfull", GetCurrentProcessId());
	//		MessageBoxA(NULL, buffer, "InjectInfo", MB_OK);
	//	}
	//	return TRUE;
 //  	 case DLL_PROCESS_DETACH:
 //  	 {
	//		char buffer[256];
	//		wsprintfA(buffer, "Unloaded from process %i", GetCurrentProcessId());
	//		MessageBoxA(NULL, buffer, "InjectInfo", MB_OK);
 //  	 }
	//	return TRUE;
	//}

	    if(Reason==DLL_PROCESS_ATTACH)     
        _beginthread(ThreadProc,0,NULL);     

    return TRUE; 

}

void ThreadProc(void *param)
{
	//------------hook api----------------
	hMod = GetModuleHandle(NULL);

	pDosHeader = (PIMAGE_DOS_HEADER)hMod;
	pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE *)hMod + pDosHeader->e_lfanew);
	pOptHeader = (PIMAGE_OPTIONAL_HEADER)&(pNTHeaders->OptionalHeader);

	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE *)hMod + pOptHeader->DataDirectory[1].VirtualAddress);

	while(pImportDescriptor->FirstThunk)
	{
		char * dllname = (char *)((BYTE *)hMod + pImportDescriptor->Name);

		pThunkData = (PIMAGE_THUNK_DATA)((BYTE *)hMod + pImportDescriptor->OriginalFirstThunk);

		int no = 1;
		while(pThunkData->u1.Function)
		{
			char * funname = (char *)((BYTE *)hMod + (DWORD64)pThunkData->u1.AddressOfData + 2);
			PDWORD64 lpAddr = (DWORD64 *)((BYTE *)hMod + (DWORD64)pImportDescriptor->FirstThunk) +(no-1);

			//修改内存的部分
			if((*lpAddr) == (int)addr)
			{
				//修改内存页的属性
				DWORD dwOLD;
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQuery(lpAddr,&mbi,sizeof(mbi));
				VirtualProtect(lpAddr,sizeof(DWORD),PAGE_READWRITE,&dwOLD);

				WriteProcessMemory(GetCurrentProcess(), 
					lpAddr, &myaddr, sizeof(DWORD64), NULL);
				//恢复内存页的属性
				VirtualProtect(lpAddr,sizeof(DWORD64),dwOLD,0);
			}
			//---------
			no++;
			pThunkData++;
		}

		pImportDescriptor++;
	}
	//-------------------HOOK END-----------------
}

//new messagebox function
int WINAPI MessageBoxProxy(IN HWND hWnd, IN LPCTSTR lpText, IN LPCTSTR lpCaption, IN UINT uType)
{
	return       ((PFNMESSAGEBOX)addr)(NULL, L"gxter_test", L"gxter_title", 0);
	//这个地方可以写出对这个API函数的处理代码
}

