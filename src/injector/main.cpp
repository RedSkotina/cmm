
#include <windows.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <set>
#include <string>
using namespace	std;

#include "dokan.h"

//#define WIN10_ENABLE_LONG_PATH
#ifdef WIN10_ENABLE_LONG_PATH
//dirty but should be enough
#define DOKAN_MAX_PATH 32768
#else
#define DOKAN_MAX_PATH MAX_PATH
#endif // DEBUG

bool g_DebugMode = false;
BOOL g_HasSeSecurityPrivilege;

static void DbgPrint(LPCWSTR format, ...) {
	if (g_DebugMode) {
		const WCHAR *outputString;
		WCHAR *buffer = NULL;
		size_t length;
		va_list argp;

		va_start(argp, format);
		length = _vscwprintf(format, argp) + 1;
		buffer = _malloca(length * sizeof(WCHAR));
		if (buffer) {
			vswprintf_s(buffer, length, format, argp);
			outputString = buffer;
		}
		else {
			outputString = format;
		}
		if (g_UseStdErr)
			fputws(outputString, stderr);
		else
			OutputDebugStringW(outputString);
		if (buffer)
			_freea(buffer);
		va_end(argp);
		if (g_UseStdErr)
			fflush(stderr);
	}
}

static void GetFilePath(PWCHAR filePath, ULONG numberOfElements,
	LPCWSTR FileName) {
	wcsncpy_s(filePath, numberOfElements, RootDirectory, wcslen(RootDirectory));
	wcsncat_s(filePath, numberOfElements, FileName, wcslen(FileName));
}

static void PrintUserName(PDOKAN_FILE_INFO DokanFileInfo) {
	HANDLE handle;
	UCHAR buffer[1024];
	DWORD returnLength;
	WCHAR accountName[256];
	WCHAR domainName[256];
	DWORD accountLength = sizeof(accountName) / sizeof(WCHAR);
	DWORD domainLength = sizeof(domainName) / sizeof(WCHAR);
	PTOKEN_USER tokenUser;
	SID_NAME_USE snu;

	if (!g_DebugMode)
		return;

	handle = DokanOpenRequestorToken(DokanFileInfo);
	if (handle == INVALID_HANDLE_VALUE) {
		DbgPrint(L"  DokanOpenRequestorToken failed\n");
		return;
	}

	if (!GetTokenInformation(handle, TokenUser, buffer, sizeof(buffer),
		&returnLength)) {
		DbgPrint(L"  GetTokenInformaiton failed: %d\n", GetLastError());
		CloseHandle(handle);
		return;
	}

	CloseHandle(handle);

	tokenUser = (PTOKEN_USER)buffer;
	if (!LookupAccountSid(NULL, tokenUser->User.Sid, accountName, &accountLength,
		domainName, &domainLength, &snu)) {
		DbgPrint(L"  LookupAccountSid failed: %d\n", GetLastError());
		return;
	}

	DbgPrint(L"  AccountName: %s, DomainName: %s\n", accountName, domainName);
}

#define MirrorCheckFlag(val, flag)                                             \
  if (val & flag) {                                                            \
    DbgPrint(L"\t" L#flag L"\n");                                              \
  }

// ----------------------------------------------------------------------------

static NTSTATUS DOKAN_CALLBACK
PCreateFile(LPCWSTR FileName, PDOKAN_IO_SECURITY_CONTEXT SecurityContext,
	ACCESS_MASK DesiredAccess, ULONG FileAttributes,
	ULONG ShareAccess, ULONG CreateDisposition,
	ULONG CreateOptions, PDOKAN_FILE_INFO DokanFileInfo) {

	WCHAR filePath[DOKAN_MAX_PATH];
	HANDLE handle;
	DWORD fileAttr;
	NTSTATUS status = STATUS_SUCCESS;
	DWORD creationDisposition;
	DWORD fileAttributesAndFlags;
	DWORD error = 0;
	SECURITY_ATTRIBUTES securityAttrib;
	ACCESS_MASK genericDesiredAccess;

	securityAttrib.nLength = sizeof(securityAttrib);
	securityAttrib.lpSecurityDescriptor =
		SecurityContext->AccessState.SecurityDescriptor;
	securityAttrib.bInheritHandle = FALSE;

	DokanMapKernelToUserCreateFileFlags(
		FileAttributes, CreateOptions, CreateDisposition, &fileAttributesAndFlags,
		&creationDisposition);

	genericDesiredAccess = DokanMapStandardToGenericAccess(DesiredAccess);

	GetFilePath(filePath, DOKAN_MAX_PATH, FileName);

	DbgPrint(L"CreateFile : %s\n", filePath);

	PrintUserName(DokanFileInfo);

	/*
	if (ShareMode == 0 && AccessMode & FILE_WRITE_DATA)
	ShareMode = FILE_SHARE_WRITE;
	else if (ShareMode == 0)
	ShareMode = FILE_SHARE_READ;
	*/

	DbgPrint(L"\tShareMode = 0x%x\n", ShareAccess);

	MirrorCheckFlag(ShareAccess, FILE_SHARE_READ);
	MirrorCheckFlag(ShareAccess, FILE_SHARE_WRITE);
	MirrorCheckFlag(ShareAccess, FILE_SHARE_DELETE);

	DbgPrint(L"\tDesiredAccess = 0x%x\n", DesiredAccess);

	MirrorCheckFlag(DesiredAccess, GENERIC_READ);
	MirrorCheckFlag(DesiredAccess, GENERIC_WRITE);
	MirrorCheckFlag(DesiredAccess, GENERIC_EXECUTE);

	MirrorCheckFlag(DesiredAccess, DELETE);
	MirrorCheckFlag(DesiredAccess, FILE_READ_DATA);
	MirrorCheckFlag(DesiredAccess, FILE_READ_ATTRIBUTES);
	MirrorCheckFlag(DesiredAccess, FILE_READ_EA);
	MirrorCheckFlag(DesiredAccess, READ_CONTROL);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_DATA);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_ATTRIBUTES);
	MirrorCheckFlag(DesiredAccess, FILE_WRITE_EA);
	MirrorCheckFlag(DesiredAccess, FILE_APPEND_DATA);
	MirrorCheckFlag(DesiredAccess, WRITE_DAC);
	MirrorCheckFlag(DesiredAccess, WRITE_OWNER);
	MirrorCheckFlag(DesiredAccess, SYNCHRONIZE);
	MirrorCheckFlag(DesiredAccess, FILE_EXECUTE);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_READ);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_WRITE);
	MirrorCheckFlag(DesiredAccess, STANDARD_RIGHTS_EXECUTE);

	// When filePath is a directory, needs to change the flag so that the file can
	// be opened.
	fileAttr = GetFileAttributes(filePath);

	if (fileAttr != INVALID_FILE_ATTRIBUTES &&
		(fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
		!(CreateOptions & FILE_NON_DIRECTORY_FILE)) {
		DokanFileInfo->IsDirectory = TRUE;
		if (DesiredAccess & DELETE) {
			// Needed by FindFirstFile to see if directory is empty or not
			ShareAccess |= FILE_SHARE_READ;
		}
	}

	DbgPrint(L"\tFlagsAndAttributes = 0x%x\n", fileAttributesAndFlags);

	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ARCHIVE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_ENCRYPTED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_HIDDEN);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NORMAL);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_OFFLINE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_READONLY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_SYSTEM);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_ATTRIBUTE_TEMPORARY);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_WRITE_THROUGH);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OVERLAPPED);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_NO_BUFFERING);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_RANDOM_ACCESS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_SEQUENTIAL_SCAN);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_DELETE_ON_CLOSE);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_BACKUP_SEMANTICS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_POSIX_SEMANTICS);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_REPARSE_POINT);
	MirrorCheckFlag(fileAttributesAndFlags, FILE_FLAG_OPEN_NO_RECALL);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_ANONYMOUS);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IDENTIFICATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_IMPERSONATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_DELEGATION);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_CONTEXT_TRACKING);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_EFFECTIVE_ONLY);
	MirrorCheckFlag(fileAttributesAndFlags, SECURITY_SQOS_PRESENT);

	if (creationDisposition == CREATE_NEW) {
		DbgPrint(L"\tCREATE_NEW\n");
	}
	else if (creationDisposition == OPEN_ALWAYS) {
		DbgPrint(L"\tOPEN_ALWAYS\n");
	}
	else if (creationDisposition == CREATE_ALWAYS) {
		DbgPrint(L"\tCREATE_ALWAYS\n");
	}
	else if (creationDisposition == OPEN_EXISTING) {
		DbgPrint(L"\tOPEN_EXISTING\n");
	}
	else if (creationDisposition == TRUNCATE_EXISTING) {
		DbgPrint(L"\tTRUNCATE_EXISTING\n");
	}
	else {
		DbgPrint(L"\tUNKNOWN creationDisposition!\n");
	}

	if (DokanFileInfo->IsDirectory) {
		// It is a create directory request
		if (creationDisposition == CREATE_NEW) {
			if (!CreateDirectory(filePath, &securityAttrib)) {
				error = GetLastError();
				DbgPrint(L"\terror code = %d\n\n", error);
				status = DokanNtStatusFromWin32(error);
			}
		}
		else if (creationDisposition == OPEN_ALWAYS) {

			if (!CreateDirectory(filePath, &securityAttrib)) {

				error = GetLastError();

				if (error != ERROR_ALREADY_EXISTS) {
					DbgPrint(L"\terror code = %d\n\n", error);
					status = DokanNtStatusFromWin32(error);
				}
			}
		}
		if (status == STATUS_SUCCESS) {
			//Check first if we're trying to open a file as a directory.
			if (fileAttr != INVALID_FILE_ATTRIBUTES &&
				!(fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
				(CreateOptions & FILE_DIRECTORY_FILE)) {
				return STATUS_NOT_A_DIRECTORY;
			}

			// FILE_FLAG_BACKUP_SEMANTICS is required for opening directory handles
			handle =
				CreateFile(filePath, genericDesiredAccess, ShareAccess,
					&securityAttrib, OPEN_EXISTING,
					fileAttributesAndFlags | FILE_FLAG_BACKUP_SEMANTICS, NULL);

			if (handle == INVALID_HANDLE_VALUE) {
				error = GetLastError();
				DbgPrint(L"\terror code = %d\n\n", error);

				status = DokanNtStatusFromWin32(error);
			}
			else {
				DokanFileInfo->Context =
					(ULONG64)handle; // save the file handle in Context
			}
		}
	}
	else {
		// It is a create file request

		if (fileAttr != INVALID_FILE_ATTRIBUTES &&
			(fileAttr & FILE_ATTRIBUTE_DIRECTORY) &&
			CreateDisposition == FILE_CREATE)
			return STATUS_OBJECT_NAME_COLLISION; // File already exist because
												 // GetFileAttributes found it
		handle = CreateFile(
			filePath,
			genericDesiredAccess, // GENERIC_READ|GENERIC_WRITE|GENERIC_EXECUTE,
			ShareAccess,
			&securityAttrib, // security attribute
			creationDisposition,
			fileAttributesAndFlags, // |FILE_FLAG_NO_BUFFERING,
			NULL);                  // template file handle

		if (handle == INVALID_HANDLE_VALUE) {
			error = GetLastError();
			DbgPrint(L"\terror code = %d\n\n", error);

			status = DokanNtStatusFromWin32(error);
		}
		else {
			DokanFileInfo->Context =
				(ULONG64)handle; // save the file handle in Context

			if (creationDisposition == OPEN_ALWAYS ||
				creationDisposition == CREATE_ALWAYS) {
				error = GetLastError();
				if (error == ERROR_ALREADY_EXISTS) {
					DbgPrint(L"\tOpen an already existing file\n");
					// Open succeed but we need to inform the driver
					// that the file open and not created by returning STATUS_OBJECT_NAME_COLLISION
					return STATUS_OBJECT_NAME_COLLISION;
				}
			}
		}
	}

	DbgPrint(L"\n");
	return status;
}


int installHooks() {
	int status;
	PDOKAN_OPERATIONS dokanOperations =
		(PDOKAN_OPERATIONS)malloc(sizeof(DOKAN_OPERATIONS));
	if (dokanOperations == NULL) {
		return EXIT_FAILURE;
	}
	PDOKAN_OPTIONS dokanOptions = (PDOKAN_OPTIONS)malloc(sizeof(DOKAN_OPTIONS));
	if (dokanOptions == NULL) {
		free(dokanOperations);
		return EXIT_FAILURE;
	}

	ZeroMemory(dokanOptions, sizeof(DOKAN_OPTIONS));
	dokanOptions->Version = DOKAN_VERSION;
	dokanOptions->ThreadCount = 0; // use default

	gDebugMode = true;

	if (gDebugMode)
		dokanOptions->Options |= DOKAN_OPTION_DEBUG;

	// Add security name privilege. Required here to handle GetFileSecurity
	// properly.
	g_HasSeSecurityPrivilege = AddSeSecurityNamePrivilege();
	if (!g_HasSeSecurityPrivilege) {
		fwprintf(stderr, L"Failed to add security privilege to process\n");
		fwprintf(stderr,
			L"\t=> GetFileSecurity/SetFileSecurity may not work properly\n");
		fwprintf(stderr, L"\t=> Please restart union sample with administrator "
			L"rights to fix it\n");
	}

	wcscpy(gReadRootDirectory, L"bar");
	DbgPrint(L"ReadRootDirectory: %s\n", gWriteRootDirectory);
	wcscpy(gWriteRootDirectory, L"bar");
	DbgPrint(L"WriteRootDirectory: %s\n", gWriteRootDirectory);
	
	// install hooks
	ZeroMemory(dokanOperations, sizeof(DOKAN_OPERATIONS));
	dokanOperations->ZwCreateFile = MirrorCreateFile;
	dokanOperations->Cleanup = MirrorCleanup;
	dokanOperations->CloseFile = MirrorCloseFile;
	dokanOperations->ReadFile = MirrorReadFile;
	dokanOperations->WriteFile = MirrorWriteFile;
	dokanOperations->FlushFileBuffers = MirrorFlushFileBuffers;
	dokanOperations->GetFileInformation = MirrorGetFileInformation;
	dokanOperations->FindFiles = MirrorFindFiles;
	dokanOperations->FindFilesWithPattern = NULL;
	dokanOperations->SetFileAttributes = MirrorSetFileAttributes;
	dokanOperations->SetFileTime = MirrorSetFileTime;
	dokanOperations->DeleteFile = MirrorDeleteFile;
	dokanOperations->DeleteDirectory = MirrorDeleteDirectory;
	dokanOperations->MoveFile = MirrorMoveFile;
	dokanOperations->SetEndOfFile = MirrorSetEndOfFile;
	dokanOperations->SetAllocationSize = MirrorSetAllocationSize;
	dokanOperations->LockFile = MirrorLockFile;
	dokanOperations->UnlockFile = MirrorUnlockFile;
	dokanOperations->GetFileSecurity = MirrorGetFileSecurity;
	dokanOperations->SetFileSecurity = MirrorSetFileSecurity;
	dokanOperations->GetDiskFreeSpace = NULL; // MirrorDokanGetDiskFreeSpace;
	dokanOperations->GetVolumeInformation = MirrorGetVolumeInformation;
	dokanOperations->Unmounted = MirrorUnmounted;
	dokanOperations->FindStreams = MirrorFindStreams;
	dokanOperations->Mounted = MirrorMounted;


	status = DokanMain(dokanOptions, dokanOperations);
	switch (status) {
	case DOKAN_SUCCESS:
		fwprintf(stderr, L"Success\n");
		break;
	case DOKAN_ERROR:
		fprintf(stderr, "Error\n");
		break;
	case DOKAN_DRIVE_LETTER_ERROR:
		fprintf(stderr, "Bad Drive letter\n");
		break;
	case DOKAN_DRIVER_INSTALL_ERROR:
		fprintf(stderr, "Can't install driver\n");
		break;
	case DOKAN_START_ERROR:
		fprintf(stderr, "Driver	something wrong\n");
		break;
	case DOKAN_MOUNT_ERROR:
		fprintf(stderr, "Can't assign a	drive letter\n");
		break;
	default:
		fprintf(stderr, "Unknown error:	%d\n", status);
		break;
	}

	free(dokanOptions);
	free(dokanOperations);
	return 0;

}
int __cdecl wmain(ULONG argc, PWCHAR argv[]) {
	
	ULONG command;
	
	int res = installHooks();
	return res;

}


