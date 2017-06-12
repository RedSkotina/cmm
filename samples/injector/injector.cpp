#include <iostream>
#include <string>
#include <cstring>

#include <easyhook.h>

int wmain( int argc, wchar_t *argv[ ], wchar_t *envp[ ] )  
{
	ULONG OutProcessId = 0;
	WCHAR* InEXEPath = L"..\\..\\target\\build\\target.exe";
	WCHAR* InCommandLine = L"";
	WCHAR* dllToInject = L".\\inject.dll";
	wprintf(L"Attempting to inject: %s\n\n", dllToInject);
    
    RhCreateAndInject(
        InEXEPath,
        InCommandLine,
        0,
        EASYHOOK_INJECT_DEFAULT,
        dllToInject,
        NULL,
        NULL,
        0,
        &OutProcessId); 


	if (OutProcessId == 0 )
	{
		//printf("RhCreateAndInject failed with error code = %d\n", nt);
		PWCHAR err = RtlGetLastErrorString();
		std::wcout << err << "\n";
	}
	else 
	{
		std::wcout << L"Library injected successfully.\n";
	}

	std::wcout << "Press Enter to exit";
	std::wstring input;
	std::getline(std::wcin, input);
	std::getline(std::wcin, input);
	return 0;
}