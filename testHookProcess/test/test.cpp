// test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


#include "stdio.h"
#include "windows.h"

int main()
{
	printf("test---\n");
	while(1)
	{
		getchar();
		MessageBox(NULL, L"ԭ����", L"09HookDemo", 0);
	}
	return 0;
}
