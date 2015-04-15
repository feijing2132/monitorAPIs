// testHookProcess.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "windows.h"
#include "tlhelp32.h"
#include <iostream>

using namespace std;
//#pragma comment(lib,"th32.lib")

 char *pkill="fundll.dll";           //DLL文件的路径

//这个路径很有意思，这个路径是相对于目标进程的，而不是自身进程。
//所以要嘛写成绝对路径，要嘛写成相对于目标进程的相对路径。
//如果写成相对于自身的路径就要麻烦了，本程序就找不到DLL文件了。 

char *prosess="test.exe";   //要注入的进程名(目标进程名)

void EnableDebugPrivilege(HANDLE processHandle);

char *lpBuffer = (char*) malloc(255);

typedef DWORD (WINAPI *PFNTCREATETHREADEX)  
	(   
	PHANDLE                 ThreadHandle,     
	ACCESS_MASK             DesiredAccess,    
	LPVOID                  ObjectAttributes,     
	HANDLE                  ProcessHandle,    
	LPTHREAD_START_ROUTINE  lpStartAddress,   
	LPVOID                  lpParameter,      
	BOOL                    CreateSuspended,      
	DWORD                   dwStackSize,      
	DWORD                   dw1,   
	DWORD                   dw2,   
	LPVOID                  Unknown   
	);    
BOOL IsVistaOrLater()  
{  
	OSVERSIONINFO osvi;  
	ZeroMemory(&osvi, sizeof(OSVERSIONINFO));  
	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);  
	GetVersionEx(&osvi);  
	if( osvi.dwMajorVersion >= 6 )  
		return TRUE;  
	return FALSE;  
}  

BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)  
{  
	HANDLE      hThread = NULL;  
	FARPROC     pFunc = NULL;  
	if( IsVistaOrLater() )    // Vista, 7, Server2008  
	{  
		pFunc = GetProcAddress(GetModuleHandle("ntdll.dll"), "NtCreateThreadEx");  
		if( pFunc == NULL )  
		{  
			printf("MyCreateRemoteThread() : GetProcAddress(\"NtCreateThreadEx\") 调用失败！错误代码: [%d]/n",  
				GetLastError());  
			return FALSE;  
		}  
		((PFNTCREATETHREADEX)pFunc)(&hThread,  
			0x1FFFFF,  
			NULL,  
			hProcess,  
			pThreadProc,  
			pRemoteBuf,  
			FALSE,  
			NULL,  
			NULL,  
			NULL,  
			NULL);  
		if( hThread == NULL )  
		{  
			printf("MyCreateRemoteThread() : NtCreateThreadEx() 调用失败！错误代码: [%d]/n", GetLastError());  
			return FALSE;  
		}  
	}  
	else                    // 2000, XP, Server2003  
	{  
		hThread = CreateRemoteThread(hProcess,   
			NULL,   
			0,   
			pThreadProc,   
			pRemoteBuf,   
			0,   
			NULL);  
		if( hThread == NULL )  
		{  
			printf("MyCreateRemoteThread() : CreateRemoteThread() 调用失败！错误代码: [%d]/n", GetLastError());  
			return FALSE;  
		}  
	}  
	if( WAIT_FAILED == WaitForSingleObject(hThread, INFINITE) )  
	{  
		printf("MyCreateRemoteThread() : WaitForSingleObject() 调用失败！错误代码: [%d]/n", GetLastError());  
		return FALSE;  
	}  
	return TRUE;  
}  

/**
 * 打印出错误信息。
 */
void PrintError(char* code)
{
    long err = GetLastError();
    if (err != ERROR_SUCCESS)
    {
        FormatMessage( FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, NULL, err, LANG_NEUTRAL, (LPTSTR) &lpBuffer, 0, NULL );
        *(lpBuffer + strlen(lpBuffer) - 2) = '\0';
        cout<<"Error("<<err<<":"<<lpBuffer<<") at "<<code<<endl;
    }
}

/**
 * 提升进程权限。
 */
void EnableDebugPrivilege(HANDLE processHandle)
{
    HANDLE hToken;
    LUID sedebugnameValue;
    TOKEN_PRIVILEGES tkp;
 
    if (!OpenProcessToken(processHandle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
    {   
        PrintError("OpenProcessToken");
        return;
    }
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue))
    {
        PrintError("LookupPrivilegeValue");
        CloseHandle(hToken);
        return;
    }
 
    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = sedebugnameValue;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
 
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof tkp, NULL, NULL))
    {
        PrintError("AdjustTokenPrivileges");
        CloseHandle(hToken);
    }
}

int main()
{
	HANDLE hSnap;
	HANDLE hkernel32;     //被注入进程的句柄
	PROCESSENTRY32 pe; 
	BOOL bNext;
	HANDLE hToken;
	TOKEN_PRIVILEGES tp;
	LUID Luid;
	LPVOID p;
	FARPROC pfn;

	// 设置当前进程权限。
	EnableDebugPrivilege(GetCurrentProcess());

	if (!OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&hToken))
	{
		return 1;
	}

	if (!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&Luid))
	{
		return 1;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = Luid;

	if (!AdjustTokenPrivileges(hToken,0,&tp,sizeof(TOKEN_PRIVILEGES),NULL,NULL))
	{
		return 1;
	}

	pe.dwSize = sizeof(pe);
	hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	bNext=Process32First(hSnap, &pe); 
	while(bNext) 
	{
		if(!stricmp(pe.szExeFile,prosess))           //--->>
		{
			hkernel32=OpenProcess(PROCESS_CREATE_THREAD|PROCESS_VM_WRITE|PROCESS_VM_OPERATION,1,pe.th32ProcessID);
			break;
		}
		bNext=Process32Next(hSnap, &pe); 
	}

	CloseHandle(hSnap);


	p=VirtualAllocEx(hkernel32,NULL,strlen(pkill),MEM_COMMIT,PAGE_READWRITE);
	bool ss= WriteProcessMemory(hkernel32,p,pkill,strlen(pkill),NULL);
	pfn=GetProcAddress(GetModuleHandle("kernel32.dll"),"LoadLibraryA");
	//CreateRemoteThread(hkernel32,NULL,0,(LPTHREAD_START_ROUTINE)pfn,p,NULL,0); 
	DWORD aa = GetLastError();
    //HANDLE obj = CreateRemoteThread(hkernel32, NULL, 0, (DWORD (__stdcall *)(void *))pfn, p, NULL, 0);

	DWORD dwID; 
	//HANDLE hThread = CreateRemoteThread(hkernel32, NULL, 0, (LPTHREAD_START_ROUTINE) LoadLibraryA, p, 0, &dwID);
	bool isOk = MyCreateRemoteThread(hkernel32, (LPTHREAD_START_ROUTINE) LoadLibraryA, p);
	//HANDLE hThread = CreateRemoteThreadEx(hkernel32, NULL, 0, (LPTHREAD_START_ROUTINE) LoadLibraryA, p, 0, &dwID); 
	PrintError("CreateRemoteThread");
	//cout<<dwID<<endl;

	DWORD aabb = GetLastError();
	system("PAUSE");
	return 0;
}