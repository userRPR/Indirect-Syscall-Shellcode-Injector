# Indirect-Syscall-Shellcode-Injector
Shellcode injector using indirect syscalls.

Researched and created this for learning purposes, my next step is to either encode shellcode or use custom shellcode to enhance AV evasion. Currently, the bytecode in the program opens calc.exe as a POC.

This code uses indirect syscalls to bypass EDR hooking. Indirect syscalls were chosen over direct syscalls to remove a major IOC: syscalls taking place outside of ntdll. To accomplish this, a syscall instruction is replaced with a jump instruction to the address of the function's syscall instruction within ntdll. 

I used the method outlined in this article https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls to dynamically resolve SSNs and syscall addresses.

# Disclaimers 
To be used for lawful security testing or educational purposes only.

# Resources/Credits
- https://redops.at/en/blog/direct-syscalls-vs-indirect-syscalls
- https://0xdarkvortex.dev/hiding-in-plainsight/ (outlines IOCs of indirect syscalls and what can be done to solve them)
