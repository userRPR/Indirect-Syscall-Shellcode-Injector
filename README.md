# Indirect-Syscall-Shellcode-Injector
Shellcode injector using indirect syscalls.

Reseaarched and created this for learning purposes, my next step is to either encode shellcode and add decode function or use custom shellcode to enhance AV evasion.

This code works by bypassing the Windows API wrapper functions for the functions used via indirect syscalls, eliminating the possibility for the functions to be hooked by EDR. Indirect syscalls were chosen over direct syscalls to remove a major IOC: syscalls taking place outside of ntdll. To accomplish this, a syscall instruction is replaced with a jump instruction to the address of the function's syscall instruction within ntdll.

# Disclaimers 
To be used for lawful security testing or educational purposes only.

# Resources/Credits
- https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls (helped with learning how to dynamically resolve SSNs and syscall addresses)
