.intel_syntax noprefix

.text
.global _NtOpenProcess
.global _NtAllocateVirtualMemory
.global _NtWriteVirtualMemory
.global _NtCreateThreadEx

.global _WhisperMain

_WhisperMain:
    pop eax                        # Remove return address from CALL instruction
    call _SW2_GetSyscallNumber     # Resolve function hash into syscall number
    add esp, 4                     # Restore ESP
    mov ecx, dword ptr fs:0xc0
    test ecx, ecx
    jne _wow64
    lea edx, dword ptr [esp+0x04]
    INT 0x02e
    ret
_wow64:
    xor ecx, ecx
    lea edx, dword ptr [esp+0x04]
    call dword ptr fs:0xc0
    ret

_NtOpenProcess:
    push 0x0EAF0D23
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0x001172D8
    call _WhisperMain

_NtWriteVirtualMemory:
    push 0x19970F19
    call _WhisperMain

_NtCreateThreadEx:
    push 0xB0AA9C71
    call _WhisperMain

