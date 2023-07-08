.686
.XMM 
.MODEL flat, c 
ASSUME fs:_DATA 

.data

.code

EXTERN SW2_GetSyscallNumber: PROC

WhisperMain PROC
    pop eax                        ; Remove return address from CALL instruction
    call SW2_GetSyscallNumber      ; Resolve function hash into syscall number
    add esp, 4                     ; Restore ESP
    mov ecx, fs:[0c0h]
    test ecx, ecx
    jne _wow64
    lea edx, [esp+4h]
    INT 02eh
    ret
_wow64:
    xor ecx, ecx
    lea edx, [esp+4h]
    call dword ptr fs:[0c0h]
    ret
WhisperMain ENDP

NtOpenProcess PROC
    push 00EAF0D23h
    call WhisperMain
NtOpenProcess ENDP

NtAllocateVirtualMemory PROC
    push 0001172D8h
    call WhisperMain
NtAllocateVirtualMemory ENDP

NtWriteVirtualMemory PROC
    push 019970F19h
    call WhisperMain
NtWriteVirtualMemory ENDP

NtCreateThreadEx PROC
    push 0B0AA9C71h
    call WhisperMain
NtCreateThreadEx ENDP

end