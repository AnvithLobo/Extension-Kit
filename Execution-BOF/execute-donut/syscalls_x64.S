.intel_syntax noprefix

.global NtAllocateVirtualMemory
.global NtWriteVirtualMemory
.global NtProtectVirtualMemory
.global NtQueueApcThread
.global NtResumeThread
.global NtOpenProcess
.global NtCreateThreadEx

.section .text

NtAllocateVirtualMemory:
    mov r10, rcx
    mov rax, [rip + ssnAllocateVirtualMemory]
    syscall
    ret

NtWriteVirtualMemory:
    mov r10, rcx
    mov rax, [rip + ssnWriteVirtualMemory]
    syscall
    ret

NtProtectVirtualMemory:
    mov r10, rcx
    mov rax, [rip + ssnProtectVirtualMemory]
    syscall
    ret

NtQueueApcThread:
    mov r10, rcx
    mov rax, [rip + ssnQueueApcThread]
    syscall
    ret

NtResumeThread:
    mov r10, rcx
    mov rax, [rip + ssnResumeThread]
    syscall
    ret

NtOpenProcess:
    mov r10, rcx
    mov rax, [rip + ssnOpenProcess]
    syscall
    ret

NtCreateThreadEx:
    mov r10, rcx
    mov rax, [rip + ssnCreateThreadEx]
    syscall
    ret
