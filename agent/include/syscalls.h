#ifndef SYSCALLS_H
#define SYSCALLS_H

#include <windows.h>
#include "ntdefs.h"

/* DJB2 hashes of Nt* function names */
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
#define H_NtAllocateVirtualMemory    0x6793C34C
#define H_NtFreeVirtualMemory        0x471AA7E9
#define H_NtReadFile                 0x2E979AE3
#define H_NtQueryInformationFile     0x4725F863
#define H_NtSetInformationFile       0x6E88B479
#define H_NtOpenKey                  0x4BB73E02
#define H_NtSaveKey                  0x5DD180BF
#define H_NtOpenProcessToken         0x7BD07459
#define H_NtAdjustPrivilegesToken    0x6921F9CD
#define H_NtTerminateProcess         0x1703AB2F
#define H_NtFsControlFile            0xF89DDF61
#define H_NtFlushBuffersFile         0x832E7ED6
#define H_NtCreateNamedPipeFile      0xDF32E02E

/* Syscall numbers (resolved at runtime via Hell's Gate) */
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
    DWORD NtAllocateVirtualMemory;
    DWORD NtFreeVirtualMemory;
    DWORD NtReadFile;
    DWORD NtQueryInformationFile;
    DWORD NtSetInformationFile;
    DWORD NtOpenKey;
    DWORD NtSaveKey;
    DWORD NtOpenProcessToken;
    DWORD NtAdjustPrivilegesToken;
    DWORD NtTerminateProcess;
    DWORD NtFsControlFile;
    DWORD NtFlushBuffersFile;
    DWORD NtCreateNamedPipeFile;
} SYSCALL_TABLE;

/* Address of `syscall` instruction in ntdll (for indirect calls) */
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
    PVOID NtAllocateVirtualMemory;
    PVOID NtFreeVirtualMemory;
    PVOID NtReadFile;
    PVOID NtQueryInformationFile;
    PVOID NtSetInformationFile;
    PVOID NtOpenKey;
    PVOID NtSaveKey;
    PVOID NtOpenProcessToken;
    PVOID NtAdjustPrivilegesToken;
    PVOID NtTerminateProcess;
    PVOID NtFsControlFile;
    PVOID NtFlushBuffersFile;
    PVOID NtCreateNamedPipeFile;
} SYSCALL_ADDR_TABLE;

extern SYSCALL_TABLE g_ssn;
extern SYSCALL_ADDR_TABLE g_addr;

BOOL resolve_syscalls(void);

/* Indirect syscall stubs (defined in syscalls_gas.S / syscalls.asm)
 * Each variant shifts N stack slots to fix the +0x10 offset from
 * the 2 extra C params (SSN, addr). Use the one matching NT_args - 4. */
extern NTSTATUS indirect_syscall(DWORD ssn, PVOID syscall_addr, ...);
extern NTSTATUS indirect_syscall_s2(DWORD ssn, PVOID syscall_addr, ...);
extern NTSTATUS indirect_syscall_s7(DWORD ssn, PVOID syscall_addr, ...);
extern NTSTATUS indirect_syscall_s10(DWORD ssn, PVOID syscall_addr, ...);

/* ── Typed wrappers ───────────────────────────────────────── */

NTSTATUS sys_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

NTSTATUS sys_NtClose(HANDLE Handle);

NTSTATUS sys_NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    DWORD MemoryInformationClass, PVOID MemoryInformation,
    SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);

NTSTATUS sys_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
    PVOID Buffer, SIZE_T NumberOfBytesToRead, PSIZE_T NumberOfBytesRead);

NTSTATUS sys_NtQueryInformationProcess(HANDLE ProcessHandle,
    DWORD ProcessInformationClass, PVOID ProcessInformation,
    ULONG ProcessInformationLength, PULONG ReturnLength);

NTSTATUS sys_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    PLARGE_INTEGER AllocationSize, ULONG FileAttributes, ULONG ShareAccess,
    ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

NTSTATUS sys_NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
    ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

NTSTATUS sys_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

NTSTATUS sys_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

NTSTATUS sys_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType);

NTSTATUS sys_NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
    ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

NTSTATUS sys_NtQueryInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, DWORD FileInformationClass);

NTSTATUS sys_NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, DWORD FileInformationClass);

NTSTATUS sys_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS sys_NtSaveKey(HANDLE KeyHandle, HANDLE FileHandle);

NTSTATUS sys_NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle);

NTSTATUS sys_NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState, ULONG BufferLength, PTOKEN_PRIVILEGES PreviousState,
    PULONG ReturnLength);

NTSTATUS sys_NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

NTSTATUS sys_NtFsControlFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG FsControlCode,
    PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer,
    ULONG OutputBufferLength);

NTSTATUS sys_NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);

NTSTATUS sys_NtCreateNamedPipeFile(PHANDLE FileHandle, ULONG DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
    ULONG NamedPipeType, ULONG ReadMode, ULONG CompletionMode,
    ULONG MaximumInstances, ULONG InboundQuota, ULONG OutboundQuota,
    PLARGE_INTEGER DefaultTimeout);

/* ETW patch */
BOOL patch_etw(void);

/* PEB helpers */
PVOID get_peb(void);
PUNICODE_STRING get_command_line(void);
PUNICODE_STRING get_image_path(void);
DWORD get_os_build(void);
DWORD get_os_major(void);
DWORD get_os_minor(void);
DWORD get_tick(void);

#endif /* SYSCALLS_H */
