#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>

// --- NT API Definitions ---

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)
#endif

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

// Syscall structure
typedef struct _SYSCALL_ENTRY {
	DWORD Hash;
	DWORD Address;
    DWORD Ssn;
} SYSCALL_ENTRY, *PSYSCALL_ENTRY;

// Function Prototypes for C Code
void InitSyscalls();
DWORD GetSyscallNumber(DWORD functionHash);

// External Assembly Stubs
NTSTATUS NtAllocateVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect
);

NTSTATUS NtWriteVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToWrite,
    PSIZE_T NumberOfBytesWritten
);

NTSTATUS NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

NTSTATUS NtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcArgument1,
    PVOID ApcArgument2,
    PVOID ApcArgument3
);

NTSTATUS NtResumeThread(
    HANDLE ThreadHandle,
    PULONG PreviousSuspendCount
);

NTSTATUS NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

NTSTATUS NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// Resolved SSNs (Global)
extern DWORD ssnAllocateVirtualMemory;
extern DWORD ssnWriteVirtualMemory;
extern DWORD ssnProtectVirtualMemory;
extern DWORD ssnQueueApcThread;
extern DWORD ssnResumeThread;
extern DWORD ssnOpenProcess;
extern DWORD ssnCreateThreadEx;

// --- API Hashing ---
#define HASH_NtAllocateVirtualMemory 0xe33a06bf
#define HASH_NtWriteVirtualMemory    0x7a65c193
#define HASH_NtProtectVirtualMemory  0x82bb0ee0
#define HASH_NtQueueApcThread        0xcd2a07ec
#define HASH_NtResumeThread          0x918a52f1
#define HASH_NtOpenProcess           0x61cf38bc
#define HASH_NtCreateThreadEx        0xe5f15daa

#endif // SYSCALLS_H
