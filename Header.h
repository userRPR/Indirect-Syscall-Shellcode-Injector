#include <Windows.h>


EXTERN_C NTSTATUS sysNtAllocateVirtualMemory(HANDLE ProcessHandle,    // Handle to the process in which to allocate the memory
    PVOID* BaseAddress,      // Pointer to the base address
    ULONG_PTR ZeroBits,      // Number of high-order address bits that must be zero in the base address of the section view
    PSIZE_T RegionSize,      // Pointer to the size of the region
    ULONG AllocationType,    // Type of allocation
    ULONG Protect            // Memory protection for the region of pages
);

EXTERN_C NTSTATUS sysNtWriteVirtualMemory(HANDLE ProcessHandle,     // Handle to the process in which to write the memory
    PVOID BaseAddress,        // Pointer to the base address
    PVOID Buffer,             // Buffer containing data to be written
    SIZE_T NumberOfBytesToWrite, // Number of bytes to be written
    PULONG NumberOfBytesWritten // Pointer to the variable that receives the number of bytes written
);

EXTERN_C NTSTATUS sysNtCreateThreadEx(PHANDLE ThreadHandle,        // Pointer to a variable that receives a handle to the new thread
    ACCESS_MASK DesiredAccess,   // Desired access to the thread
    PVOID ObjectAttributes,      // Pointer to an OBJECT_ATTRIBUTES structure that specifies the object's attributes
    HANDLE ProcessHandle,        // Handle to the process in which the thread is to be created
    PVOID lpStartAddress,        // Pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread
    PVOID lpParameter,           // Pointer to a variable to be passed to the thread
    ULONG Flags,                 // Flags that control the creation of the thread
    SIZE_T StackZeroBits,        // A pointer to a variable that specifies the number of high-order address bits that must be zero in the stack pointer
    SIZE_T SizeOfStackCommit,    // The size of the stack that must be committed at thread creation
    SIZE_T SizeOfStackReserve,   // The size of the stack that must be reserved at thread creation
    PVOID lpBytesBuffer          // Pointer to a variable that receives any output data from the system
);

EXTERN_C NTSTATUS sysWaitForSingleObject(HANDLE Handle,          // Handle to the object to be waited on
    BOOLEAN Alertable,      // If set to TRUE, the function returns when the system queues an I/O completion routine or APC for the thread
    PLARGE_INTEGER Timeout  // Pointer to a LARGE_INTEGER that specifies the absolute```c
    // or relative time at which the function should return, regardless of the state of the object
);

// functions to pass syscall instruction addresses into the assembly local variables for access
EXTERN_C void passAddrAVM(UINT_PTR addr);
EXTERN_C void passAddrWVM(UINT_PTR addr);
EXTERN_C void passAddrCTE(UINT_PTR addr);
EXTERN_C void passAddrWSO(UINT_PTR addr);

// functions to pass SSNs into the assembly local variables for access
EXTERN_C void passNumAVM(DWORD ssn);
EXTERN_C void passNumWVM(DWORD ssn);
EXTERN_C void passNumCTE(DWORD ssn);
EXTERN_C void passNumWSO(DWORD ssn);
