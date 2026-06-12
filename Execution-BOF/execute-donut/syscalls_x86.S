.intel_syntax noprefix

.global _NtAllocateVirtualMemory
.global _NtWriteVirtualMemory
.global _NtProtectVirtualMemory
.global _NtQueueApcThread
.global _NtResumeThread
.global _NtOpenProcess
.global _NtCreateThreadEx

.section .text

_NtAllocateVirtualMemory:
    mov eax, [_ssnAllocateVirtualMemory]
    call _DoSyscall
    ret 24

_NtWriteVirtualMemory:
    mov eax, [_ssnWriteVirtualMemory]
    call _DoSyscall
    ret 20

_NtProtectVirtualMemory:
    mov eax, [_ssnProtectVirtualMemory]
    call _DoSyscall
    ret 20

_NtQueueApcThread:
    mov eax, [_ssnQueueApcThread]
    call _DoSyscall
    ret 20

_NtResumeThread:
    mov eax, [_ssnResumeThread]
    call _DoSyscall
    ret 8

_NtOpenProcess:
    mov eax, [_ssnOpenProcess]
    call _DoSyscall
    ret 16

_NtCreateThreadEx:
    mov eax, [_ssnCreateThreadEx]
    call _DoSyscall
    ret 44

_DoSyscall:
    mov edx, esp
    sysenter
    ret
