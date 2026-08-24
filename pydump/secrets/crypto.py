"""Cryptographic operations for SAM/LSA secret decryption.

Implements:
- Boot key extraction (SysKey) from SYSTEM hive
- SAM key derivation
- NTLM hash decryption (RC4 + DES for older, AES for newer)
- LSA key decryption
- LSA secret decryption
- DCC2 (cached domain credentials) decryption
"""

import struct
import hashlib
import hmac

from Crypto.Cipher import AES, DES, ARC4


# Boot key class order (permutation applied to raw key)
BOOT_KEY_PERM = [
    0x8, 0x5, 0x4, 0x2, 0xB, 0x9, 0xD, 0x3,
    0x0, 0x6, 0x1, 0xC, 0xE, 0xA, 0xF, 0x7,
]


def extract_boot_key(jd: bytes, skew1: bytes, gbg: bytes, data: bytes) -> bytes:
    """Extract and unscramble the boot key from SYSTEM hive class names.

    The boot key is derived from the class names of 4 registry keys under
    HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa: JD, Skew1, GBG, Data.
    Each class name is a hex string — concatenated they form the scrambled key.
    """
    raw = bytes.fromhex(jd.decode() + skew1.decode() + gbg.decode() + data.decode())
    return bytes(raw[BOOT_KEY_PERM[i]] for i in range(16))


def decrypt_sam_hash_aes(encrypted: bytes, key: bytes, rid: int) -> bytes:
    """Decrypt an AES-encrypted SAM hash (Windows 10 1607+)."""
    # Structure: revision(2) + data_offset(2) + ...
    # AES encrypted data starts at offset 4: iv(16) + encrypted(rest)
    iv = encrypted[:16]
    enc_data = encrypted[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(enc_data)
    return _rid_decrypt(rid, decrypted[:16])


def decrypt_sam_hash_rc4(encrypted: bytes, hashed_boot_key: bytes, rid: int) -> bytes:
    """Decrypt an RC4-encrypted SAM hash (older Windows)."""
    # RC4 key = MD5(hashed_boot_key + RID + ALMPASSLM/NTPASSWORD constant)
    rid_bytes = struct.pack("<I", rid)
    ntpassword = b"NTPASSWORD\x00"
    rc4_key = hashlib.md5(hashed_boot_key + rid_bytes + ntpassword).digest()
    cipher = ARC4.new(rc4_key)
    obfuscated = cipher.decrypt(encrypted)
    return _rid_decrypt(rid, obfuscated)


def compute_hashed_boot_key(boot_key: bytes, f_value: bytes) -> bytes:
    """Compute the hashed boot key from SAM\\Domains\\Account F value.

    For AES (revision 3): F[0x70:0x80] = salt, F[0x80:0xA0] = encrypted key
    For RC4 (revision 2): key = MD5(F[0x70:0x80] + constant + boot_key + constant)
    """
    revision = struct.unpack_from("<I", f_value, 0x68)[0]

    if revision >= 2:
        # AES-based (Windows 10+, SAM_KEY_DATA_AES: revision 2)
        salt = f_value[0x78:0x88]
        enc_key = f_value[0x88:0xA8]
        cipher = AES.new(boot_key, AES.MODE_CBC, salt)
        return cipher.decrypt(enc_key)[:16]
    else:
        # RC4-based (legacy, SAM_KEY_DATA: revision 1)
        qwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00"
        digits = b"0123456789012345678901234567890123456789\x00"
        rc4_key = hashlib.md5(f_value[0x70:0x80] + qwerty + boot_key + digits).digest()
        cipher = ARC4.new(rc4_key)
        return cipher.decrypt(f_value[0x80:0xA0])


def _lsa_aes_decrypt(key: bytes, encrypted: bytes) -> bytes:
    """AES decrypt used by LSA — each 16-byte block decrypted independently with IV=0."""
    result = b""
    for i in range(0, len(encrypted), 16):
        cipher = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
        result += cipher.decrypt(encrypted[i:i + 16])
    return result


def decrypt_lsa_key(boot_key: bytes, pol_ek_list: bytes) -> bytes:
    """Decrypt the LSA encryption key from SECURITY\\Policy\\PolEKList."""
    # Structure: header(28) + salt(32) + encrypted_data
    if len(pol_ek_list) < 76:
        raise RuntimeError("PolEKList too short")

    salt = pol_ek_list[28:60]
    encrypted = pol_ek_list[60:]

    # Derive AES key from boot_key + salt using SHA256
    sha = hashlib.sha256()
    sha.update(boot_key)
    for _ in range(1000):
        sha.update(salt)
    key = sha.digest()

    decrypted = _lsa_aes_decrypt(key, encrypted)

    # The LSA key is at offset 0x24 in the decrypted PEKLIST_PLAIN (32 bytes)
    return decrypted[0x24:0x44]


def decrypt_lsa_secret(lsa_key: bytes, encrypted: bytes) -> bytes:
    """Decrypt an LSA secret value using the LSA key."""
    if len(encrypted) < 28:
        return b""

    # Structure: header(28) + salt(32) + encrypted_data
    salt = encrypted[28:60]
    data = encrypted[60:]

    if not data:
        return b""

    sha = hashlib.sha256()
    sha.update(lsa_key)
    for _ in range(1000):
        sha.update(salt)
    key = sha.digest()

    return _lsa_aes_decrypt(key, data)


def decrypt_cached_cred(lsa_key: bytes, nl_km: bytes, cache_entry: bytes) -> tuple[str, str, bytes]:
    """Decrypt a cached domain credential (DCC2/mscash2).

    Returns (username, domain, dcc2_hash).
    """
    # NL_RECORD structure
    user_len = struct.unpack_from("<H", cache_entry, 0)[0]
    domain_len = struct.unpack_from("<H", cache_entry, 2)[0]
    dns_domain_len = struct.unpack_from("<H", cache_entry, 4)[0]

    # Encrypted data starts at offset 96
    iv = cache_entry[64:80]
    enc_data = cache_entry[96:]

    # Derive key from NL$KM
    hmac_key = hmac.new(nl_km, iv, hashlib.sha1).digest()
    cipher = ARC4.new(hmac_key)
    decrypted = cipher.decrypt(enc_data)

    # Parse decrypted data: hash(16) + username + domain...
    cached_hash = decrypted[:16]
    offset = 16 + (16 - 16 % 8) if 16 % 8 else 16  # align
    offset = 72  # fixed offset for username in decrypted blob
    username = decrypted[offset:offset + user_len].decode("utf-16-le", errors="ignore")
    domain = cache_entry[96 + 72 + user_len:96 + 72 + user_len + domain_len].decode("utf-16-le", errors="ignore")

    return username, domain, cached_hash


def _rid_decrypt(rid: int, data: bytes) -> bytes:
    """Final DES-based deobfuscation using the user RID."""
    key1 = _rid_to_des_key(rid)
    key2 = _rid_to_des_key(((rid >> 24) | (rid << 8)) & 0xFFFFFFFF)

    d1 = DES.new(key1, DES.MODE_ECB).decrypt(data[:8])
    d2 = DES.new(key2, DES.MODE_ECB).decrypt(data[8:16])
    return d1 + d2


def _rid_to_des_key(rid: int) -> bytes:
    """Convert a RID to an 8-byte DES key (7-bit groups shifted to positions 7-1)."""
    s = struct.pack("<I", rid) + struct.pack("<I", rid)
    return bytes([
        ((s[0] >> 1) << 1) & 0xFE,
        ((((s[0] & 0x01) << 6) | (s[1] >> 2)) << 1) & 0xFE,
        ((((s[1] & 0x03) << 5) | (s[2] >> 3)) << 1) & 0xFE,
        ((((s[2] & 0x07) << 4) | (s[3] >> 4)) << 1) & 0xFE,
        ((((s[3] & 0x0F) << 3) | (s[4] >> 5)) << 1) & 0xFE,
        ((((s[4] & 0x1F) << 2) | (s[5] >> 6)) << 1) & 0xFE,
        ((((s[5] & 0x3F) << 1) | (s[6] >> 7)) << 1) & 0xFE,
        ((s[6] & 0x7F) << 1) & 0xFE,
    ])
