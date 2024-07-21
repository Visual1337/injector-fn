.code 

nt_device_io_control_file PROC

	mov r10, rcx
	mov eax, 7
	syscall
	ret

nt_device_io_control_file ENDP

END