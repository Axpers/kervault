"""Remote Registry (MS-RRP) RPC client.

Interface UUID: 338CD001-2244-31F1-AAAA-900038001003 v1.0
Reference: [MS-RRP] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rrp
"""

import struct

from ..smb import PipeIO
from .core import build_bind, build_request, parse_response
from .ndr import (
    ndr_dword,
    ndr_handle,
    ndr_wstring_data,
    ndr_wstring_null,
    parse_context_handle,
    parse_dword,
)

# WINREG interface UUID: 338CD001-2244-31F1-AAAA-900038001003
WINREG_UUID = (
    b"\x01\xd0\x8c\x33\x44\x22\xf1\x31"
    b"\xaa\xaa\x90\x00\x38\x00\x10\x03"
)
WINREG_VERSION = (1, 0)

# Operation numbers
OPNUM_OPEN_HKLM = 2
OPNUM_CLOSE_KEY = 5
OPNUM_ENUM_KEY = 9
OPNUM_ENUM_VALUE = 10
OPNUM_OPEN_KEY = 15
OPNUM_QUERY_INFO_KEY = 16
OPNUM_QUERY_VALUE = 17

# Access masks
KEY_READ = 0x00020019
KEY_ENUMERATE_SUB_KEYS = 0x00000008
KEY_QUERY_VALUE = 0x00000001
MAXIMUM_ALLOWED = 0x02000000

# Value types
REG_NONE = 0
REG_SZ = 1
REG_BINARY = 3
REG_DWORD = 4


class WinReg:
    """Remote Registry RPC client."""

    def __init__(self, pipe: PipeIO):
        self._pipe = pipe
        self._call_id = 0

    def bind(self) -> None:
        pdu = build_bind(WINREG_UUID, WINREG_VERSION, call_id=self._next_call_id())
        self._pipe.write(pdu)
        resp_data = self._pipe.read(4096)
        parse_response(resp_data)

    def open_hklm(self) -> bytes:
        """OpenLocalMachine — open HKEY_LOCAL_MACHINE."""
        # [MS-RRP] 3.1.5.3 — minimal stub: system_name(NULL) + desired_access
        stub = ndr_dword(0)  # NULL pointer for system name
        stub += ndr_dword(MAXIMUM_ALLOWED)
        resp = self._call(OPNUM_OPEN_HKLM, stub)
        handle, offset = parse_context_handle(resp, 0)
        status, _ = parse_dword(resp, offset)
        if status != 0:
            raise RuntimeError(f"OpenHKLM failed: 0x{status:08X}")
        return handle

    def open_key(self, parent_handle: bytes, subkey: str) -> bytes:
        """BaseRegOpenKey — open a registry subkey."""
        stub = ndr_handle(parent_handle)
        stub += self._encode_rrp_unicode_string(subkey)
        stub += ndr_dword(0)  # dwOptions = 0
        stub += ndr_dword(MAXIMUM_ALLOWED)  # samDesired

        resp = self._call(OPNUM_OPEN_KEY, stub)
        handle, offset = parse_context_handle(resp, 0)
        status, _ = parse_dword(resp, offset)
        if status != 0:
            raise RuntimeError(f"OpenKey({subkey}) failed: 0x{status:08X}")
        return handle

    def query_value(self, key_handle: bytes, value_name: str) -> tuple[int, bytes]:
        """BaseRegQueryValue — read a registry value. Returns (type, data)."""
        buf_size = 512

        stub = ndr_handle(key_handle)
        stub += self._encode_rrp_unicode_string(value_name)
        # lpType: [in, out, unique] LPDWORD
        stub += struct.pack("<I", 0x00020004)  # referent
        stub += ndr_dword(0)
        # lpData: [in, out, unique] conformant varying byte array
        stub += struct.pack("<I", 0x00020008)  # referent
        stub += struct.pack("<I", buf_size)  # max_count
        stub += struct.pack("<I", 0)  # offset
        stub += struct.pack("<I", buf_size)  # actual_count
        stub += b"\x00" * buf_size  # pre-allocated buffer
        # lpcbData: [in, out, unique] LPDWORD
        stub += struct.pack("<I", 0x0002000C)  # referent
        stub += ndr_dword(buf_size)
        # lpcbLen: [in, out, unique] LPDWORD
        stub += struct.pack("<I", 0x00020010)  # referent
        stub += ndr_dword(buf_size)

        resp = self._call(OPNUM_QUERY_VALUE, stub)
        return self._parse_query_value_response(resp)

    def enum_key(self, key_handle: bytes, index: int) -> str | None:
        """BaseRegEnumKey — enumerate subkeys by index. Returns name or None."""
        stub = ndr_handle(key_handle)
        stub += ndr_dword(index)
        # lpNameIn: RRP_UNICODE_STRING {Length=0, MaxLength=512, Buffer}
        stub += struct.pack("<HH", 0, 512)
        stub += struct.pack("<I", 0x00020000)  # referent
        stub += struct.pack("<III", 256, 0, 0)  # max_count, offset, actual=0
        # lpClassIn: RRP_UNICODE_STRING (NULL)
        stub += struct.pack("<HH", 0, 0)
        stub += struct.pack("<I", 0)  # NULL pointer
        # lpftLastWriteTime: pointer (NULL ok)
        stub += struct.pack("<I", 0x00020004)  # referent
        stub += struct.pack("<Q", 0)  # FILETIME = 0

        try:
            resp = self._call(OPNUM_ENUM_KEY, stub)
        except RuntimeError as e:
            if "0x00000103" in str(e):  # ERROR_NO_MORE_ITEMS
                return None
            raise

        # Parse lpNameOut: RRP_UNICODE_STRING
        char_len = struct.unpack_from("<H", resp, 0)[0]
        # Skip Length(2) + MaxLength(2) + referent(4) + max_count(4) + offset(4) + actual_count(4)
        actual = struct.unpack_from("<I", resp, 16)[0]
        name_data = resp[20: 20 + actual * 2]
        return name_data.decode("utf-16-le").rstrip("\x00")

    def enum_value(self, key_handle: bytes, index: int) -> tuple[str, int, bytes] | None:
        """BaseRegEnumValue — enumerate values by index. Returns (name, type, data) or None."""
        stub = ndr_handle(key_handle)
        stub += ndr_dword(index)
        # lpValueNameIn: RRP_UNICODE_STRING
        stub += struct.pack("<HH", 0, 512)
        stub += struct.pack("<I", 0x00020000)  # referent
        stub += struct.pack("<III", 256, 0, 0)
        # lpType
        stub += struct.pack("<I", 0x00020004)
        stub += ndr_dword(0)
        # lpData
        stub += struct.pack("<I", 0x00020008)
        stub += struct.pack("<I", 65536)  # max_count
        stub += struct.pack("<I", 0)  # offset
        stub += struct.pack("<I", 0)  # actual_count
        # lpcbData
        stub += struct.pack("<I", 0x0002000C)
        stub += ndr_dword(65536)
        # lpcbLen
        stub += struct.pack("<I", 0x00020010)
        stub += ndr_dword(65536)

        try:
            resp = self._call(OPNUM_ENUM_VALUE, stub)
        except RuntimeError as e:
            if "0x00000103" in str(e):  # ERROR_NO_MORE_ITEMS
                return None
            raise

        # Parse response: lpValueNameOut + lpType + lpData + lpcbData + lpcbLen + status
        # lpValueNameOut: Length(2) + MaxLength(2) + referent(4) + max(4) + off(4) + act(4) + data
        actual = struct.unpack_from("<I", resp, 16)[0]
        name_data = resp[20: 20 + actual * 2]
        name = name_data.decode("utf-16-le").rstrip("\x00")

        # Advance past name + padding
        offset = 20 + actual * 2
        if offset % 4 != 0:
            offset += 4 - (offset % 4)

        # lpType referent + value
        offset += 4  # referent
        vtype = struct.unpack_from("<I", resp, offset)[0]
        offset += 4

        # lpData referent + conformant array (max + off + actual + data)
        offset += 4  # referent
        max_count = struct.unpack_from("<I", resp, offset)[0]
        offset += 4
        _ = struct.unpack_from("<I", resp, offset)[0]  # data_offset
        offset += 4
        data_actual = struct.unpack_from("<I", resp, offset)[0]
        offset += 4
        data = resp[offset: offset + data_actual]

        return name, vtype, data

    def query_info_key_class(self, key_handle: bytes) -> bytes:
        """BaseRegQueryInfoKey — get the class name of a key (used for boot key)."""
        stub = ndr_handle(key_handle)
        # lpClassIn: RRP_UNICODE_STRING (empty, will be filled by server)
        stub += struct.pack("<HH", 0, 64)  # Length=0, MaxLength=64
        stub += struct.pack("<I", 0x00020000)  # referent
        stub += struct.pack("<III", 32, 0, 0)  # max_count, offset, actual=0

        resp = self._call(OPNUM_QUERY_INFO_KEY, stub)

        # Response: lpClassOut (RRP_UNICODE_STRING) + ...
        char_len = struct.unpack_from("<H", resp, 0)[0]
        # Skip Length(2) + MaxLength(2) + referent(4) + max_count(4) + offset(4) + actual_count(4)
        actual = struct.unpack_from("<I", resp, 16)[0]
        class_data = resp[20: 20 + actual * 2]
        return class_data.decode("utf-16-le").rstrip("\x00").encode()

    def close_key(self, handle: bytes) -> None:
        """BaseRegCloseKey."""
        stub = ndr_handle(handle)
        resp = self._call(OPNUM_CLOSE_KEY, stub)
        # Don't check status — sometimes returns handle even on success

    def _parse_query_value_response(self, resp: bytes) -> tuple[int, bytes]:
        """Parse QueryValue response to extract type and data."""
        offset = 0
        # lpType referent + value
        offset += 4  # referent
        vtype = struct.unpack_from("<I", resp, offset)[0]
        offset += 4
        # lpData referent + conformant array
        offset += 4  # referent
        max_count = struct.unpack_from("<I", resp, offset)[0]
        offset += 4
        data_offset_val = struct.unpack_from("<I", resp, offset)[0]
        offset += 4
        actual_count = struct.unpack_from("<I", resp, offset)[0]
        offset += 4
        data = resp[offset: offset + actual_count]
        return vtype, data

    def _encode_rrp_unicode_string(self, s: str) -> bytes:
        """Encode an RRP_UNICODE_STRING (Length includes null terminator)."""
        encoded = (s + "\x00").encode("utf-16-le")
        byte_len = len(encoded)  # includes null
        char_count = byte_len // 2

        result = struct.pack("<HH", byte_len, byte_len)  # Length, MaxLength
        result += struct.pack("<I", 0x00020000)  # referent pointer
        result += struct.pack("<III", char_count, 0, char_count)
        result += encoded
        if len(encoded) % 4 != 0:
            result += b"\x00" * (4 - len(encoded) % 4)
        return result

    def _call(self, opnum: int, stub_data: bytes) -> bytes:
        pdu = build_request(opnum, stub_data, call_id=self._next_call_id())
        self._pipe.write(pdu)
        resp_data = self._pipe.read(65536)
        response = parse_response(resp_data)
        return response.stub_data

    def _next_call_id(self) -> int:
        self._call_id += 1
        return self._call_id
