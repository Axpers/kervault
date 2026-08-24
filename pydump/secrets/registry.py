"""Offline registry hive parsing — SAM hashes and LSA secrets.

Parses raw REGF hive bytes (received from agent or loaded from disk).
No network, no RPC — pure offline decryption.
"""

import struct
from dataclasses import dataclass

from .hivereader import RegistryHive
from .crypto import (
    extract_boot_key,
    compute_hashed_boot_key,
    decrypt_sam_hash_aes,
    decrypt_sam_hash_rc4,
    decrypt_lsa_key,
    decrypt_lsa_secret,
)


@dataclass
class SamHash:
    username: str
    rid: int
    ntlm_hash: str
    lm_hash: str = ""


@dataclass
class LsaSecret:
    name: str
    value: bytes
    decoded: str = ""


def extract_boot_key_from_hive(system_data: bytes) -> bytes:
    """Extract boot key from raw SYSTEM hive bytes."""
    hive = RegistryHive(system_data)
    select_key = hive.open_key("Select")
    _, current_data = hive.query_value(select_key, "Current")
    cs_num = struct.unpack_from("<I", current_data, 0)[0]
    cs_path = f"ControlSet{cs_num:03d}\\Control\\Lsa"

    parts = []
    for name in ("JD", "Skew1", "GBG", "Data"):
        subkey = hive.open_key(f"{cs_path}\\{name}")
        class_data = hive.query_key_class(subkey)
        parts.append(class_data.decode("utf-16-le").encode("ascii"))

    return extract_boot_key(parts[0], parts[1], parts[2], parts[3])


def parse_sam_hive(sam_data: bytes, boot_key: bytes) -> list[SamHash]:
    """Parse SAM hive bytes and return decrypted NTLM hashes."""
    hive = RegistryHive(sam_data)
    hashes = []

    try:
        account_key = hive.open_key("SAM\\Domains\\Account")
        _, f_value = hive.query_value(account_key, "F")
    except (KeyError, ValueError):
        return hashes

    if len(f_value) < 0x70:
        return hashes

    hashed_boot_key = compute_hashed_boot_key(boot_key, f_value)
    sam_revision = struct.unpack_from("<I", f_value, 0x68)[0]

    try:
        users_key = hive.open_key("SAM\\Domains\\Account\\Users")
    except KeyError:
        return hashes

    for subkey_name in hive.enum_subkeys(users_key):
        if subkey_name == "Names" or len(subkey_name) != 8:
            continue
        try:
            rid = int(subkey_name, 16)
        except ValueError:
            continue
        try:
            user_key = hive.open_key(f"SAM\\Domains\\Account\\Users\\{subkey_name}")
            _, v_value = hive.query_value(user_key, "V")
            sam_hash = _parse_sam_v(v_value, rid, hashed_boot_key, sam_revision)
            if sam_hash:
                hashes.append(sam_hash)
        except (KeyError, RuntimeError):
            continue

    return hashes


def parse_security_hive(sec_data: bytes, boot_key: bytes) -> list[LsaSecret]:
    """Parse SECURITY hive bytes and return decrypted LSA secrets."""
    hive = RegistryHive(sec_data)
    secrets = []

    try:
        pol_key = hive.open_key("Policy\\PolEKList")
        _, pol_data = hive.query_value(pol_key, "(Default)")
    except KeyError:
        return secrets

    lsa_key = decrypt_lsa_key(boot_key, pol_data)

    try:
        secrets_key = hive.open_key("Policy\\Secrets")
    except KeyError:
        return secrets

    for name in hive.enum_subkeys(secrets_key):
        try:
            currval_key = hive.open_key(f"Policy\\Secrets\\{name}\\CurrVal")
            _, encrypted = hive.query_value(currval_key, "(Default)")
            decrypted = decrypt_lsa_secret(lsa_key, encrypted)
            secret = LsaSecret(name=name, value=decrypted)
            secret.decoded = _decode_secret(name, decrypted)
            secrets.append(secret)
        except (KeyError, RuntimeError):
            continue

    return secrets


def _parse_sam_v(v_value: bytes, rid: int, hashed_boot_key: bytes, revision: int) -> SamHash | None:
    """Parse SAM V value to extract username and encrypted hash."""
    name_offset = struct.unpack_from("<I", v_value, 0x0C)[0] + 0xCC
    name_length = struct.unpack_from("<I", v_value, 0x10)[0]
    username = v_value[name_offset:name_offset + name_length].decode("utf-16-le", errors="ignore")

    if not username:
        return None

    nt_offset = struct.unpack_from("<I", v_value, 0xA8)[0] + 0xCC
    nt_length = struct.unpack_from("<I", v_value, 0xAC)[0]

    if nt_length == 0:
        return SamHash(username=username, rid=rid, ntlm_hash="aad3b435b51404eeaad3b435b51404ee")

    nt_data = v_value[nt_offset:nt_offset + nt_length]

    try:
        nt_revision = struct.unpack_from("<H", nt_data, 2)[0]
        if nt_revision >= 2:
            data_offset = struct.unpack_from("<I", nt_data, 4)[0]
            if data_offset == 0 or len(nt_data) <= 24:
                return SamHash(username=username, rid=rid,
                               ntlm_hash="31d6cfe0d16ae931b73c59d7e0c089c0")
            nt_hash = decrypt_sam_hash_aes(nt_data[8:], hashed_boot_key, rid)
        else:
            nt_hash = decrypt_sam_hash_rc4(nt_data[4:], hashed_boot_key, rid)
    except Exception:
        return SamHash(username=username, rid=rid, ntlm_hash="(decryption failed)")

    return SamHash(username=username, rid=rid, ntlm_hash=nt_hash.hex())


def _decode_secret(name: str, data: bytes) -> str:
    """Decode a decrypted LSA secret to a readable string."""
    if not data:
        return ""

    if name.startswith("_SC_"):
        try:
            text = data.decode("utf-16-le", errors="ignore").rstrip("\x00")
            if text and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in text):
                return text
        except Exception:
            pass

    if name.startswith("DPAPI"):
        return data[:20].hex()

    return data[:64].hex() + ("..." if len(data) > 64 else "")
