"""SVCCTL (Service Control Manager) RPC interface.

Allows remote service creation and execution via the \\pipe\\svcctl named pipe.
This is the same mechanism used by PsExec, sc.exe, etc.

Interface UUID: 367ABB81-9844-35F1-AD32-98F038001003 v2.0
Reference: [MS-SCMR] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr
"""

import struct

from ..smb import PipeIO
from .core import build_bind, build_request, parse_response
from .ndr import (
    ndr_wstring,
    ndr_wstring_null,
    ndr_dword,
    ndr_handle,
    parse_context_handle,
    parse_dword,
)

# SVCCTL interface UUID: 367ABB81-9844-35F1-AD32-98F038001003
SVCCTL_UUID = (
    b"\x81\xbb\x7a\x36\x44\x98\xf1\x35"
    b"\xad\x32\x98\xf0\x38\x00\x10\x03"
)
SVCCTL_VERSION = (2, 0)

# Operation numbers
OPNUM_CLOSE_SERVICE_HANDLE = 0
OPNUM_DELETE_SERVICE = 2
OPNUM_OPEN_SC_MANAGER_W = 15
OPNUM_OPEN_SERVICE_W = 16
OPNUM_START_SERVICE_W = 19
OPNUM_CREATE_SERVICE_W = 12

# Access masks
SC_MANAGER_ALL_ACCESS = 0x000F003F
SERVICE_ALL_ACCESS = 0x000F01FF

# Service types
SERVICE_WIN32_OWN_PROCESS = 0x00000010

# Start types
SERVICE_DEMAND_START = 0x00000003

# Error control
SERVICE_ERROR_IGNORE = 0x00000000


class SvcCtl:
    """SVCCTL RPC client for remote service management."""

    def __init__(self, pipe: PipeIO):
        self._pipe = pipe
        self._call_id = 0
        self._scm_handle: bytes | None = None

    def bind(self) -> None:
        """Bind to the SVCCTL interface."""
        pdu = build_bind(SVCCTL_UUID, SVCCTL_VERSION, call_id=self._next_call_id())
        self._pipe.write(pdu)
        resp_data = self._pipe.read(4096)
        # Parse bind_ack — just verify no fault
        parse_response(resp_data)

    def open_sc_manager(self, target: str = "") -> bytes:
        """ROpenSCManagerW — open a handle to the SCM on the remote machine.

        Returns the 20-byte SCM context handle.
        """
        # [MS-SCMR] 3.1.4.2 ROpenSCManagerW
        # lpMachineName: SVCCTL_HANDLEW (pointer to wstring)
        # lpDatabaseName: pointer to wstring or NULL
        # dwDesiredAccess: DWORD
        stub = ndr_wstring(target) if target else ndr_wstring_null()
        stub += ndr_wstring_null()  # database name = NULL (default SERVICES_ACTIVE)
        stub += ndr_dword(SC_MANAGER_ALL_ACCESS)

        resp = self._call(OPNUM_OPEN_SC_MANAGER_W, stub)
        handle, offset = parse_context_handle(resp, 0)
        status, _ = parse_dword(resp, offset)

        if status != 0:
            raise RuntimeError(f"OpenSCManagerW failed: 0x{status:08X}")

        self._scm_handle = handle
        return handle

    def create_service(
        self,
        service_name: str,
        display_name: str,
        binary_path: str,
    ) -> bytes:
        """RCreateServiceW — create a new service.

        Returns the 20-byte service context handle.
        """
        if not self._scm_handle:
            raise RuntimeError("Must call open_sc_manager() first")

        # [MS-SCMR] 3.1.4.12 RCreateServiceW
        stub = ndr_handle(self._scm_handle)
        stub += ndr_wstring(service_name)
        stub += ndr_wstring(display_name)      # lpDisplayName (referent)
        stub += ndr_dword(SERVICE_ALL_ACCESS)   # dwDesiredAccess
        stub += ndr_dword(SERVICE_WIN32_OWN_PROCESS)  # dwServiceType
        stub += ndr_dword(SERVICE_DEMAND_START)       # dwStartType
        stub += ndr_dword(SERVICE_ERROR_IGNORE)       # dwErrorControl
        stub += ndr_wstring(binary_path)        # lpBinaryPathName
        stub += ndr_wstring_null()              # lpLoadOrderGroup
        stub += ndr_dword(0)                    # lpdwTagId (NULL)
        stub += ndr_lpbyte_null()               # lpDependencies
        stub += ndr_dword(0)                    # dwDependSize
        stub += ndr_wstring_null()              # lpServiceStartName (LocalSystem)
        stub += ndr_lpbyte_null()               # lpPassword
        stub += ndr_dword(0)                    # dwPwSize

        resp = self._call(OPNUM_CREATE_SERVICE_W, stub)

        # Response: lpdwTagId(4) + ServiceHandle(20) + ReturnValue(4)
        _tag, offset = parse_dword(resp, 0)
        handle, offset = parse_context_handle(resp, offset)
        status, _ = parse_dword(resp, offset)

        if status != 0:
            raise RuntimeError(f"CreateServiceW failed: 0x{status:08X}")

        return handle

    def open_service(self, service_name: str) -> bytes:
        """ROpenServiceW — open an existing service by name.

        Returns the 20-byte service context handle.
        """
        if not self._scm_handle:
            raise RuntimeError("Must call open_sc_manager() first")

        stub = ndr_handle(self._scm_handle)
        stub += ndr_wstring(service_name)
        stub += ndr_dword(SERVICE_ALL_ACCESS)

        resp = self._call(OPNUM_OPEN_SERVICE_W, stub)
        handle, offset = parse_context_handle(resp, 0)
        status, _ = parse_dword(resp, offset)

        if status != 0:
            raise RuntimeError(f"OpenServiceW failed: 0x{status:08X}")

        return handle

    def start_service(self, service_handle: bytes) -> None:
        """RStartServiceW — start a service."""
        stub = ndr_handle(service_handle)
        stub += ndr_dword(0)  # argc = 0
        stub += ndr_dword(0)  # argv = NULL

        resp = self._call(OPNUM_START_SERVICE_W, stub)
        status, _ = parse_dword(resp, 0)

        # ERROR_SERVICE_ALREADY_RUNNING (1056) is acceptable
        if status != 0 and status != 1056:
            raise RuntimeError(f"StartServiceW failed: 0x{status:08X}")

    def delete_service(self, service_handle: bytes) -> None:
        """RDeleteService — mark a service for deletion."""
        stub = ndr_handle(service_handle)

        resp = self._call(OPNUM_DELETE_SERVICE, stub)
        status, _ = parse_dword(resp, 0)

        if status != 0:
            raise RuntimeError(f"DeleteService failed: 0x{status:08X}")

    def close_handle(self, handle: bytes) -> None:
        """RCloseServiceHandle — close a service/SCM handle."""
        stub = ndr_handle(handle)

        resp = self._call(OPNUM_CLOSE_SERVICE_HANDLE, stub)
        # Response is handle(20) + status(4), we just check status
        _, offset = parse_context_handle(resp, 0)
        status, _ = parse_dword(resp, offset)

        if status != 0:
            raise RuntimeError(f"CloseServiceHandle failed: 0x{status:08X}")

    def _call(self, opnum: int, stub_data: bytes) -> bytes:
        """Send an RPC request and return the stub response data."""
        pdu = build_request(opnum, stub_data, call_id=self._next_call_id())
        self._pipe.write(pdu)
        resp_data = self._pipe.read(65536)
        response = parse_response(resp_data)
        return response.stub_data

    def _next_call_id(self) -> int:
        self._call_id += 1
        return self._call_id


def ndr_lpbyte_null() -> bytes:
    """Null LPBYTE pointer."""
    return struct.pack("<I", 0)
