#include <iostream>
#include <string>
#include <cstring>

#include <easyhook.h>

int _tmain(int argc, _TCHAR* argv[])
{
	
	WCHAR* InEXEPath = L"..\\Debug\\target.exe";
	WCHAR* InCommandLine = L"";
	WCHAR* dllToInject = L"..\\inject.dll";
	wprintf(L"Attempting to inject: %s\n\n", dllToInject);

	// Inject dllToInject into the target process Id, passing 
	// freqOffset as the pass through data.
	NTSTATUS nt = RhInjectLibrary(
		processId,   // The process to inject into
		0,           // ThreadId to wake up upon injection
		EASYHOOK_INJECT_DEFAULT,
		dllToInject, // 32-bit
		NULL,		 // 64-bit not provided
		&freqOffset, // data to send to injected DLL entry point
		sizeof(DWORD)// size of data to send
	);
    
    EASYHOOK_NT_EXPORT exp =  RhCreateAndInject(
        InEXEPath,
        InCommandLine,
        EASYHOOK_INJECT_DEFAULT,
        dllToInject,
        NULL,
        PVOID InPassThruBuffer,
        ULONG InPassThruSize,
        ULONG* OutProcessId); 


	if (nt != 0)
	{
		printf("RhInjectLibrary failed with error code = %d\n", nt);
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