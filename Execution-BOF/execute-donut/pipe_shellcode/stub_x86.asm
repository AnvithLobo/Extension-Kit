[BITS 32]

global _start

section .text

_start:
    ; Stack Alignment (16-byte)
    and esp, 0xFFFFFFF0
    
    pushad
    pushfd

    ; Calculate Delta Offset
    call get_delta
get_delta:
    pop ebp
    sub ebp, get_delta

    ; 1. Find Kernel32 Base
    xor ecx, ecx
    mov eax, [fs:ecx + 0x30]    ; PEB
    mov eax, [eax + 0x0C]       ; PEB_LDR_DATA
    mov esi, [eax + 0x14]       ; InMemoryOrderModuleList
    
    mov esi, [esi]              ; Exe
    mov esi, [esi]              ; Ntdll
    mov esi, [esi]              ; Kernel32
    
    mov ebx, [esi + 0x10]       ; DllBase
    
    ; 2. Resolve GetProcAddress
    lea esi, [ebp + str_GetProcAddress]
    push esi
    push ebx
    call resolve_api
    test eax, eax
    jz fail_open
    mov edi, eax                
    
    ; 3. Resolve CreateFileA
    lea esi, [ebp + str_CreateFileA]
    push esi
    push ebx
    call edi                    
    test eax, eax
    jz fail_open
    mov esi, eax                
    
    ; 4. Resolve SetStdHandle
    lea eax, [ebp + str_SetStdHandle]
    push eax
    push ebx
    call edi                    
    test eax, eax
    jz fail_open
    mov edi, eax                ; EDI = SetStdHandle

    ; 5. Connect to Pipe
    lea eax, [ebp + pipe_name]
    
    push 0                      ; hTemplate
    push 0                      ; Flags
    push 3                      ; OPEN_EXISTING
    push 0                      ; Security
    push 0                      ; Share
    push 0x40000000             ; GENERIC_WRITE
    push eax                    ; lpFileName
    call esi                    ; CreateFileA
    
    cmp eax, -1
    je fail_open
    mov ebx, eax                
    
    ; 6. Redirect IO
    ; SetStdout
    push ebx
    push -11
    call edi
    
    ; SetStderr
    push ebx
    push -12
    call edi

fail_open:
    popfd
    popad
    jmp donut_payload

; -------------------------------------------------------------------------
; Helper: resolve_api
; Inputs: Stack [hModule, Name]
; Output: EAX = Address
; -------------------------------------------------------------------------
resolve_api:
    push ebp
    mov ebp, esp
    push ebx
    push esi
    push edi
    push ecx
    push edx
    
    mov ebx, [ebp + 8]          ; hModule
    mov esi, [ebp + 12]         ; Target Name
    
    mov eax, [ebx + 0x3C]       ; PE Sig
    mov edx, [ebx + eax + 0x78] ; Export Dir RVA
    add edx, ebx                ; Export Dir VA
    
    mov ecx, [edx + 0x18]       ; NumberOfNames
    mov edi, [edx + 0x20]       ; AddressOfNames RVA
    add edi, ebx
    
    xor eax, eax
    
search_loop:
    cmp eax, ecx
    je not_found
    
    push eax                    ; Save Index (Stack)
    
    mov eax, [edi + eax * 4]
    add eax, ebx                ; Candidate Name
    
    ; Strcmp
    push esi
    push eax
    call strcmp
    add esp, 8
    
    test eax, eax
    pop eax                     ; Restore Index
    je found
    
    inc eax
    jmp search_loop
    
found:
    ; Index in EAX
    mov ecx, [edx + 0x24]       ; Ordinals
    add ecx, ebx
    movzx eax, word [ecx + eax * 2]
    
    mov ecx, [edx + 0x1C]       ; Functions
    add ecx, ebx
    mov eax, [ecx + eax * 4]
    add eax, ebx
    jmp finish

not_found:
    xor eax, eax

finish:
    pop edx
    pop ecx
    pop edi
    pop esi
    pop ebx
    pop ebp
    ret 8                       ; Clean 2 args

; Helpers
strcmp:
    push ebp
    mov ebp, esp
    push esi
    push edi
    
    mov esi, [ebp + 8]
    mov edi, [ebp + 12]
    
str_loop:
    mov al, [esi]
    mov bl, [edi]
    cmp al, bl
    jne str_diff
    test al, al
    jz str_equal
    inc esi
    inc edi
    jmp str_loop
    
str_diff:
    mov eax, 1
    jmp str_end
str_equal:
    xor eax, eax
str_end:
    pop edi
    pop esi
    pop ebp
    ret

; -------------------------------------------------------------------------
; Data
; -------------------------------------------------------------------------
str_GetProcAddress: db 'GetProcAddress', 0
str_CreateFileA:    db 'CreateFileA', 0
str_SetStdHandle:   db 'SetStdHandle', 0
pipe_name:          db '\\.\pipe\dnt_00000000', 0
                    times 64 db 0

donut_payload:
