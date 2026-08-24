/**
 * Named pipe communication via NT syscalls only.
 * Uses NtCreateNamedPipeFile, NtFsControlFile, NtWriteFile, NtFlushBuffersFile.
 * DACL restricts access to SYSTEM + Administrators.
 * Wire data is XOR-encrypted with the pipe name as key.
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"
#include "../include/agent.h"

HANDLE open_named_pipe(const wchar_t *pipe_name) {
    /*
     * Build NT path: \??\pipe\<name>
     * Must be on stack — no string literals in .rdata
     */
    wchar_t path[256];
    /* prefix: \??\pipe\ */
    path[0] = L'\\';
    path[1] = L'?';
    path[2] = L'?';
    path[3] = L'\\';
    path[4] = L'p';
    path[5] = L'i';
    path[6] = L'p';
    path[7] = L'e';
    path[8] = L'\\';
    int off = 9;

    /* append pipe_name */
    const wchar_t *s = pipe_name;
    while (*s && off < 254) {
        path[off++] = *s++;
    }
    path[off] = L'\0';

    /* Build UNICODE_STRING */
    UNICODE_STRING us;
    us.Length = (USHORT)(off * sizeof(wchar_t));
    us.MaximumLength = (USHORT)((off + 1) * sizeof(wchar_t));
    us.Buffer = path;

    /* Build restricted DACL: allow SYSTEM + Administrators only */
    BYTE acl_buf[64];
    for (int i = 0; i < 64; i++) acl_buf[i] = 0;

    ACL *acl = (ACL *)acl_buf;
    acl->AclRevision = ACL_REVISION;
    acl->AclSize     = 52;  /* 8 + 20 + 24 */
    acl->AceCount    = 2;

    /* ACE 1: SYSTEM (S-1-5-18) */
    BYTE *ace1 = acl_buf + 8;
    ace1[0] = ACCESS_ALLOWED_ACE_TYPE;
    ace1[1] = 0;
    *(WORD  *)&ace1[2] = 20;
    *(DWORD *)&ace1[4] = 0x1F01FF;
    BYTE *sid1 = ace1 + 8;
    sid1[0] = 1; sid1[1] = 1;
    sid1[2] = 0; sid1[3] = 0; sid1[4] = 0;
    sid1[5] = 0; sid1[6] = 0; sid1[7] = 5;
    *(DWORD *)&sid1[8] = 18;

    /* ACE 2: BUILTIN\Administrators (S-1-5-32-544) */
    BYTE *ace2 = acl_buf + 28;
    ace2[0] = ACCESS_ALLOWED_ACE_TYPE;
    ace2[1] = 0;
    *(WORD  *)&ace2[2] = 24;
    *(DWORD *)&ace2[4] = 0x1F01FF;
    BYTE *sid2 = ace2 + 8;
    sid2[0] = 1; sid2[1] = 2;
    sid2[2] = 0; sid2[3] = 0; sid2[4] = 0;
    sid2[5] = 0; sid2[6] = 0; sid2[7] = 5;
    *(DWORD *)&sid2[8]  = 32;
    *(DWORD *)&sid2[12] = 544;

    SECURITY_DESCRIPTOR sd;
    sd.Revision = SECURITY_DESCRIPTOR_REVISION;
    sd.Sbz1     = 0;
    sd.Control  = SE_DACL_PRESENT;
    sd.Owner    = NULL;
    sd.Group    = NULL;
    sd.Sacl     = NULL;
    sd.Dacl     = (PACL)acl_buf;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, &sd);

    IO_STATUS_BLOCK iosb;
    HANDLE pipe = NULL;

    LARGE_INTEGER timeout;
    timeout.QuadPart = -300000000LL;

    NTSTATUS status = sys_NtCreateNamedPipeFile(
        &pipe,
        0xC0100000,             /* GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE */
        &oa,
        &iosb,
        3,                      /* FILE_SHARE_READ|FILE_SHARE_WRITE */
        FILE_OPEN_IF,
        FILE_SYNCHRONOUS_IO_NONALERT,
        0,                      /* NamedPipeType = byte */
        0,                      /* ReadMode = byte */
        0,                      /* CompletionMode = blocking */
        1,                      /* MaximumInstances */
        0,                      /* InboundQuota */
        1048576,                /* OutboundQuota = 1MB */
        &timeout
    );

    if (!NT_SUCCESS(status)) return NULL;

    /* Wait for client connection (FSCTL_PIPE_LISTEN) */
    IO_STATUS_BLOCK iosb2;
    status = sys_NtFsControlFile(
        pipe, NULL, NULL, NULL, &iosb2,
        FSCTL_PIPE_LISTEN,
        NULL, 0, NULL, 0
    );

    /* STATUS_PIPE_CONNECTED (0x00000108) is also success */
    if (!NT_SUCCESS(status) && status != 0x00000108) {
        sys_NtClose(pipe);
        return NULL;
    }

    return pipe;
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

BOOL write_pipe(HANDLE pipe, const void *data, DWORD size) {
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
            NTSTATUS status = sys_NtWriteFile(pipe, NULL, NULL, NULL, &iosb,
                                               buf, chunk, NULL, NULL);
            if (!NT_SUCCESS(status)) return FALSE;
            off += chunk;
        }
        return TRUE;
    }

    IO_STATUS_BLOCK iosb;
    NTSTATUS status = sys_NtWriteFile(pipe, NULL, NULL, NULL, &iosb,
                                       (PVOID)data, size, NULL, NULL);
    return NT_SUCCESS(status);
}

void close_pipe(HANDLE pipe) {
    IO_STATUS_BLOCK iosb;
    sys_NtFlushBuffersFile(pipe, &iosb);
    sys_NtClose(pipe);
}
