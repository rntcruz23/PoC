// Xor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "windows.h"
#include "stdio.h"
#include <stdlib.h>
#include "time.h"

#define KEYSIZE 8

// Generate random bytes of size sSize
VOID GenerateRandomBytes(PBYTE pByte, SIZE_T sSize) {
	for (int i = 0; i < sSize; i++) {
		pByte[i] = (BYTE)rand() % 0xFF;
	}
}


// Print the input buffer as a hex char array
VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {
	printf("unsigned char %s[] = {", Name);
	for (int i = 0; i < Size; i++) {
		if (i % 16 == 0) {
			printf("\n\t");
		}
		if (i < Size - 1) {
			printf("0x%0.2X, ", Data[i]);
		}
		else {
			printf("0x%0.2X ", Data[i]);
		}
	}
	printf("};\n\n\n");
}

// Example invocation: Check the main function
VOID XorByInputKey(IN PBYTE pShellcode, IN SIZE_T sShellcodeSize, IN PBYTE bKey, IN SIZE_T sKeySize) {

	for (size_t i = 0, j = 0; i < sShellcodeSize; i++, j++) {
		// if end of the key, start again 
		pShellcode[i] = pShellcode[i] ^ bKey[j % sKeySize];

	}
}

char* Load(const char* filePath, int* fileSize) {
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

void Unload(char* filePath, char* text, int textSize) {
	FILE* filePointer;

	// Open the binary file in read mode
	fopen_s(&filePointer, filePath, "wb+");

	// Check if the file was successfully opened
	if (filePointer == NULL) {
#ifdef DEBUG
		fprintf(stderr, "[-] Error opening the file.\n");
#endif
		return; // Return NULL to indicate failure
	}
	fwrite(text, textSize, 1, filePointer);
	fclose(filePointer);
	return;
}

int main(int argc, char **argv)
{
	if (argc == 1) {
		printf("[-] Missing path to encrypt.\n");
		return -1;
	}

	BYTE pKey[KEYSIZE];
	srand(time(NULL));
	printf("[+] Generating random key, use the following key to decrypt\n");
	GenerateRandomBytes(pKey, KEYSIZE);
	PrintHexData("pKey", pKey, KEYSIZE);
	
	char *path = argv[1];
	int fileSize = 0;
	printf("[+] Reading payload file: %s\n", path);
	char* plainText = Load(path, &fileSize);

	printf("[+] Encrypting file %s\n", path);
	XorByInputKey(plainText, fileSize, pKey, KEYSIZE);
	printf("[+} Done encrypting %d bytee.\n", fileSize);

	char ext[] = "_enc";
	size_t new_size = (strlen(path) + sizeof(ext)) * sizeof(char);
	char* new_path = (char*)calloc(new_size, sizeof(char));
	strcpy_s(new_path, new_size, path);
	strcat_s(new_path, new_size, ext);

	printf("[+] Saving encrypted content to %s\n", new_path);
	Unload(new_path, plainText, fileSize);
}