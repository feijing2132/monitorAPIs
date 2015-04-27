// dllmain.cpp : Implementation of DllMain.

#include "stdafx.h"
#include "resource.h"
#include "dll_i.h"
#include "dllmain.h"
#include <Winternl.h>
#include "windows.h"
#include "process.h"
#include "tlhelp32.h"
#include "stdio.h"
#include <iostream>
#include <string>
#include <psapi.h>

using namespace std;
//#include <afx.h>
//#define _WIN64
EXTERN_C IMAGE_DOS_HEADER __ImageBase;
TCHAR *MONITOR_FILE_TYPE = _T(".txt");

extern "C" __declspec(dllexport) void unload() {
	CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)FreeLibrary, &__ImageBase, 0, NULL);
}

//#include  <Psapi.h > 

#define        BUFSIZE                         512 
#pragma comment(lib, "psapi.lib" )
BOOL __stdcall GetFileNameFromHandle(HANDLE hFile, LPWSTR lpFileName, DWORD dwSize)
{
	BOOL bSuccess  =  FALSE;
	WCHAR pszFilename[MAX_PATH + 1 ];
	HANDLE hFileMap;

	DWORD dwFileSizeHi  =   0 ;
	DWORD dwFileSizeLo  =  ::GetFileSize(hFile,  & dwFileSizeHi); 

	if ( dwFileSizeLo ==   0   && dwFileSizeHi  ==  0  )
	{
		return  bSuccess;
	}

	hFileMap  =  ::CreateFileMappingW(hFile, 
		NULL, 
		PAGE_READONLY,
		0 , 
		1 ,
		NULL);

	if  (hFileMap) 
	{
		void *  pMem  = ::MapViewOfFile(hFileMap, FILE_MAP_READ,  0 ,  0,  1 );

		if  (pMem) 
		{
			if  (::GetMappedFileNameW(GetCurrentProcess(), 
				pMem, 
				pszFilename,
				MAX_PATH)) 
			{
				WCHAR szTemp[BUFSIZE];
				szTemp[ 0 ]  =  L'\0 ';

				if  (::GetLogicalDriveStringsW(BUFSIZE - 1 , szTemp)) 
				{
					WCHAR szName[MAX_PATH];
					WCHAR szDrive[3] =  L":";
					BOOL bFound  =  FALSE;
					WCHAR *  p  =  szTemp;

					do  
					{
						* szDrive  =   * p;

						if  (::QueryDosDeviceW(szDrive, szName, BUFSIZE))
						{
							UINT uNameLen  =  lstrlenW(szName);

							if  (uNameLen  <  MAX_PATH) 
							{
								bFound  =  ::_wcsnicmp(pszFilename, szName, 
									uNameLen)  ==   0 ;

								if  (bFound) 
								{
									WCHAR szTempFile[MAX_PATH];
									::wsprintfW(szTempFile,
										L"%s%s" ,
										szDrive,
										pszFilename+uNameLen);
									::lstrcpynW(pszFilename, szTempFile, MAX_PATH);
								}
							}
						}

						while  ( * p++ );
					}  while  ( ! bFound &&   * p); 
				}
			}
			::UnmapViewOfFile(pMem);
		} 

		::CloseHandle(hFileMap);
	}

	if (lpFileName)
	{
		::lstrcpynW(lpFileName,pszFilename,dwSize);
		bSuccess  =  TRUE;
	}

	return (bSuccess);
}

//#define BUFSIZE 512
//
//BOOL GetFileNameFromHandle(HANDLE hFile) 
//{
//	BOOL bSuccess = FALSE;
//	TCHAR pszFilename[MAX_PATH+1];
//
//	// Get the file size.
//	DWORD dwFileSizeHi = 0;
//	DWORD dwFileSizeLo = GetFileSize(hFile, &dwFileSizeHi); 
//
//	// Create a file mapping object.
//	HANDLE hFileMap = CreateFileMapping(hFile, 
//		NULL, 
//		PAGE_READONLY,
//		0, 
//		dwFileSizeLo,
//		NULL);
//
//	if (hFileMap) 
//	{
//		// Create a file mapping to get the file name.
//		void* pMem = MapViewOfFile(hFileMap, FILE_MAP_READ, 0, 0, 1);
//
//		if (pMem) 
//		{
//			if (GetMappedFileName (GetCurrentProcess(), 
//				pMem, 
//				pszFilename,
//				MAX_PATH)) 
//			{
//
//				// Translate path with device name to drive letters.
//				TCHAR szTemp[BUFSIZE];
//				szTemp[0] = '\0';
//
//				if (GetLogicalDriveStrings(BUFSIZE-1, szTemp)) 
//				{
//					TCHAR szName[MAX_PATH];
//					TCHAR szDrive[3] = TEXT(" :");
//					BOOL bFound = FALSE;
//					TCHAR* p = szTemp;
//
//					do 
//					{
//						// Copy the drive letter to the template string
//						*szDrive = *p;
//
//						// Look up each device name
//						if (QueryDosDevice(szDrive, szName, BUFSIZE))
//						{
//							UINT uNameLen = _tcslen(szName);
//
//							if (uNameLen < MAX_PATH) 
//							{
//								bFound = _tcsnicmp(pszFilename, szName, 
//									uNameLen) == 0;
//
//								if (bFound) 
//								{
//									// Reconstruct pszFilename using szTemp
//									// Replace device path with DOS path
//									TCHAR szTempFile[MAX_PATH];
//									_stprintf(szTempFile,
//										TEXT("%s%s"),
//										szDrive,
//										pszFilename+uNameLen);
//									_tcsncpy(pszFilename, szTempFile, MAX_PATH);
//								}
//							}
//						}
//
//						// Go to the next NULL character.
//						while (*p++);
//					} while (!bFound && *p); // end of string
//				}
//			}
//			bSuccess = TRUE;
//			UnmapViewOfFile(pMem);
//		} 
//
//		CloseHandle(hFileMap);
//	}
//	printf("File name is %s\n", pszFilename);
//	return(bSuccess);
//}

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
typedef __kernel_entry NTSTATUS (NTAPI *PFNNtOpenFile)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,ULONG ShareAccess,
    ULONG OpenOptions
    );
typedef __kernel_entry NTSTATUS (NTAPI *PFNNtCreateFile)(    OUT PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize OPTIONAL,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer OPTIONAL,
    ULONG EaLength);

typedef HANDLE (WINAPI *PFNCreateFile)( LPCTSTR lpFileName,
 DWORD dwDesiredAccess,
 DWORD dwShareMode,
 LPSECURITY_ATTRIBUTES lpSecurityAttributes,
 DWORD dwCreationDisposition,
 DWORD dwFlagsAndAttributes,
 HANDLE hTemplateFile
	);

typedef BOOL (WINAPI *PFNCLOSEHANDLE)(HANDLE);
//NTSTATUS
//NTAPI 
//NtOpenFile (
    //OUT PHANDLE FileHandle,
    //IN ACCESS_MASK DesiredAccess,
    //IN POBJECT_ATTRIBUTES ObjectAttributes,
    //OUT PIO_STATUS_BLOCK IoStatusBlock,
    //IN ULONG ShareAccess,
    //IN ULONG OpenOptions
    //);

//int
//WINAPI
//MessageBoxW(
//    __in_opt HWND hWnd,
//    __in_opt LPCWSTR lpText,
//    __in_opt LPCWSTR lpCaption,
//    __in UINT uType);
int WINAPI MessageBoxProxy(IN HWND hWnd, IN LPCTSTR lpText, IN LPCTSTR lpCaption, IN UINT uType);
__kernel_entry NTSTATUS NTAPI NtOpenFileProxy (
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN ULONG ShareAccess,
    IN ULONG OpenOptions
    );

__kernel_entry NTSTATUS NTAPI NtCreateFileProxy (
    OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength
    );


HANDLE WINAPI CreateFileProxy(
	IN LPCTSTR lpFileName,
	IN DWORD dwDesiredAccess,
	IN DWORD dwShareMode,
	IN LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	IN DWORD dwCreationDisposition,
	IN DWORD dwFlagsAndAttributes,
	IN HANDLE hTemplateFile
	);

BOOL
	WINAPI
	CloseHandleProxy(
	IN HANDLE hObject
	);

int * addr = (int *)MessageBox;     //保存函数的入口地址
int *addrNTOpenFile;// = (int *)NtOpenFile;
int *addrNTCreateFile;// = (int *)NtCreateFile;
int *addrCreateFile = (int *)CreateFile;
int *addrCloseHandle = (int *)CloseHandle;
//;
//MessageBox;
int * myaddr = (int *)MessageBoxProxy;
int * myaddrNTOpenFile = (int *)NtOpenFileProxy;
int * myaddrNTCreateFile = (int *)NtCreateFileProxy;
int * myaddrCreateFile = (int *)CreateFileProxy;
int * myaddrCloseHandle = (int *)CloseHandleProxy;

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
	HMODULE modNtDll = LoadLibrary(_T("ntdll.dll"));
	if(!modNtDll){
		printf("Error loading ntdll.dll\n");
	}
	addrNTOpenFile = (int *) GetProcAddress(modNtDll, "NtOpenFile");
	addrNTCreateFile = (int *) GetProcAddress(modNtDll, "NtCreateFile");

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
			//if((*lpAddr) == (int)addrNTOpenFile)
			//if((*lpAddr) == (int)addr)
			if((*lpAddr) == (int)addrCreateFile)
			{
				//修改内存页的属性
				DWORD dwOLD;
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQuery(lpAddr,&mbi,sizeof(mbi));
				VirtualProtect(lpAddr,sizeof(DWORD),PAGE_READWRITE,&dwOLD);

				WriteProcessMemory(GetCurrentProcess(), 
					lpAddr, &myaddrCreateFile, sizeof(DWORD64), NULL);
				//恢复内存页的属性
				VirtualProtect(lpAddr,sizeof(DWORD64),dwOLD,0);
			}
			else if((*lpAddr) == (int)addrCloseHandle)
			{
				//修改内存页的属性
				DWORD dwOLD;
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQuery(lpAddr,&mbi,sizeof(mbi));
				VirtualProtect(lpAddr,sizeof(DWORD),PAGE_READWRITE,&dwOLD);

				WriteProcessMemory(GetCurrentProcess(), 
					lpAddr, &myaddrCloseHandle, sizeof(DWORD64), NULL);
				//恢复内存页的属性
				VirtualProtect(lpAddr,sizeof(DWORD64),dwOLD,0);
			}
			else if((*lpAddr) == (int)addrNTCreateFile)
			{
				//修改内存页的属性
				DWORD dwOLD;
				MEMORY_BASIC_INFORMATION mbi;
				VirtualQuery(lpAddr,&mbi,sizeof(mbi));
				VirtualProtect(lpAddr,sizeof(DWORD),PAGE_READWRITE,&dwOLD);

				WriteProcessMemory(GetCurrentProcess(), 
					lpAddr, &myaddrNTCreateFile, sizeof(DWORD64), NULL);
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
	return ((PFNMESSAGEBOX)addr)(NULL, L"gxter_test", L"gxter_title", 0);
}

__kernel_entry NTSTATUS NTAPI NtCreateFileProxy (
 OUT PHANDLE FileHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    IN PLARGE_INTEGER AllocationSize OPTIONAL,
    IN ULONG FileAttributes,
    IN ULONG ShareAccess,
    IN ULONG CreateDisposition,
    IN ULONG CreateOptions,
    IN PVOID EaBuffer OPTIONAL,
    IN ULONG EaLength
	)
{
	MessageBox(NULL, L"NtCreateFileProxy", L"gxter_title", 0);
	return ((PFNNtCreateFile)addrNTCreateFile)( FileHandle,
    DesiredAccess,
    ObjectAttributes,
    IoStatusBlock,
     AllocationSize ,
    FileAttributes,
    ShareAccess,
    CreateDisposition,
    CreateOptions,
    EaBuffer ,
    EaLength
	);
}

__kernel_entry NTSTATUS NTAPI NtOpenFileProxy (
	OUT PHANDLE FileHandle,
	IN ACCESS_MASK DesiredAccess,
	IN POBJECT_ATTRIBUTES ObjectAttributes,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	IN ULONG ShareAccess,
	IN ULONG OpenOptions
	)
{
	MessageBox(NULL, L"NtOpenFileProxy", L"gxter_title", 0);
	return ((PFNNtOpenFile)addrNTOpenFile)(FileHandle,
		DesiredAccess,
		ObjectAttributes,
		IoStatusBlock,
		ShareAccess,
		OpenOptions
		);
}

HANDLE WINAPI CreateFileProxy(
	IN LPCTSTR lpFileName,
	IN DWORD dwDesiredAccess,
	IN DWORD dwShareMode,
	IN LPSECURITY_ATTRIBUTES lpSecurityAttributes,
	IN DWORD dwCreationDisposition,
	IN DWORD dwFlagsAndAttributes,
	IN HANDLE hTemplateFile
	)
{
	wstring fileName(lpFileName);
	if (fileName.find(MONITOR_FILE_TYPE) != std::string::npos)
	{
		MessageBox(NULL, lpFileName, L"Opening...", 0);
	}
	
	return ((PFNCreateFile)addrCreateFile)(lpFileName,
		dwDesiredAccess,
		dwShareMode,
		lpSecurityAttributes,
		dwCreationDisposition,
		dwFlagsAndAttributes,
		hTemplateFile
		);
}

BOOL
	WINAPI
	CloseHandleProxy(
	IN HANDLE hObject
	)
{
	WCHAR pszFilename[MAX_PATH + 1 ];
	BOOL ok = GetFileNameFromHandle(hObject, pszFilename, MAX_PATH);
	if (ok)
	{
		wstring fileName(pszFilename);
		if (fileName.find(MONITOR_FILE_TYPE) != std::string::npos)
		{
			MessageBox(NULL, pszFilename, L"Closing...", 0);
		}
	}

	return ((PFNCLOSEHANDLE)addrCloseHandle)(hObject);
}

