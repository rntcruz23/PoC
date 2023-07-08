[SECTION .data]

global _NtOpenProcess
global _NtAllocateVirtualMemory
global _NtWriteVirtualMemory
global _NtCreateThreadEx

global _WhisperMain
extern _SW2_GetSyscallNumber

[SECTION .text]

BITS 32
DEFAULT REL

_WhisperMain:
    pop eax                        ; Remove return address from CALL instruction
    call _SW2_GetSyscallNumber     ; Resolve function hash into syscall number
    add esp, 4                     ; Restore ESP
    mov ecx, [fs:0c0h]
    test ecx, ecx
    jne _wow64
    lea edx, [esp+4h]
    INT 02eh
    ret
_wow64:
    xor ecx, ecx
    lea edx, [esp+4h]
    call dword [fs:0c0h]
    ret

_NtOpenProcess:
    push 00EAF0D23h
    call _WhisperMain

_NtAllocateVirtualMemory:
    push 0001172D8h
    call _WhisperMain

_NtWriteVirtualMemory:
    push 019970F19h
    call _WhisperMain

_NtCreateThreadEx:
    push 0B0AA9C71h
    call _WhisperMain

