// lighting.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


//int _tmain(int argc, _TCHAR* argv[])
//{
//	return 0;
//}

#include <iostream>
#include "./Hook.h"

static Hook msgHook;

void callbackOne()
{
	//Grab the 2nd (zero-indexed) argument
	char* lpCaption = msgHook.getArg<char*>(2);
	std::cout << "lpCaption: " << lpCaption << std::endl;
	//Overwrite the 1st argument (again zero-indexed)
	msgHook.setArg(1, "New lpText");

	//Set new return value. If this was Hook::POST_CALL the value returned to the application would be 42.
	//but since this is PRE_CALL it will be overwritten
	msgHook.setReturnValue(42);
}

int main(int argc, char* argv[])
{
	//Hook ANSI MessageBox API call by calling our handler before the original function

	msgHook.setHook("MessageBoxA", "User32.dll", 4, Hook::PRE_CALL, callbackOne);
	std::cin.get();

	int res = MessageBoxA(NULL, "lpText", "lpCaption", MB_OKCANCEL);

	std::cout << "res: " << res << std::endl;

	std::cin.get();
	return 0;
}
