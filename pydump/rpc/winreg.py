"""MS-RRP (Remote Registry Protocol) RPC client.

Reads registry keys/values remotely via \\pipe\\winreg, with reads
appearing from svchost.exe (the RemoteRegistry service host).

Interface UUID: 338CD001-2244-31F1-AAAA-900038001003 v1.0
"""

import struct

from ..smb import PipeIO
from .core import build_bind, build_request, parse_response
from .ndr import ndr_handle, ndr_dword, parse_context_handle, parse_dword

WINREG_UUID = (
    b"\x01\xd0\x8c\x33\x44\x22\xf1\x31"
    b"\xaa\xaa\x90\x00\x38\x00\x10\x03"
)
WINREG_VERSION = (1, 0)

KEY_READ = 0x20019

_ref = 0x00060000


def _ref_id():
    global _ref
    _ref += 4
    return _ref


def _rrp_string(s: str) -> bytes:
    """Encode RRP_UNICODE_STRING with string data."""
    encoded = (s + "\x00").encode("utf-16-le")
    byte_len = len(encoded)
    char_count = byte_len // 2
    result = struct.pack("<HH", byte_len, byte_len)
    result += struct.pack("<I", _ref_id())
    result += struct.pack("<III", char_count, 0, char_count)
    result += encoded
    if len(encoded) % 4:
        result += b"\x00" * (4 - len(encoded) % 4)
    return result


def _rrp_buf(max_chars: int) -> bytes:
    """Encode empty RRP_UNICODE_STRING buffer for receiving data."""
    max_bytes = max_chars * 2
    result = struct.pack("<HH", 0, max_bytes)
    result += struct.pack("<I", _ref_id())
    result += struct.pack("<III", max_chars, 0, 0)
    return result


def _parse_rrp_string(data: bytes, offset: int) -> tuple[bytes, int]:
    """Parse RRP_UNICODE_STRING from response, return raw UTF-16LE bytes."""
    length = struct.unpack_from("<H", data, offset)[0]
    offset += 4
    ref_id = struct.unpack_from("<I", data, offset)[0]
    offset += 4
    if ref_id == 0 or length == 0:
        return b"", offset
    _, _, actual_count = struct.unpack_from("<III", data, offset)
    offset += 12
    byte_count = actual_count * 2
    raw = data[offset:offset + byte_count]
    offset += byte_count
    if byte_count % 4:
        offset += 4 - (byte_count % 4)
    return raw, offset


class WinReg:
    """MS-RRP client for remote registry reads via \\pipe\\winreg."""

    def __init__(self, pipe: PipeIO):
        self._pipe = pipe
        self._call_id = 0

    def bind(self) -> None:
        pdu = build_bind(WINREG_UUID, WINREG_VERSION,
                         call_id=self._next_call_id())
        self._pipe.write(pdu)
        resp = self._pipe.read(4096)
        parse_response(resp)

    def open_local_machine(self) -> bytes:
        """OpenLocalMachine (opnum 2) — get HKLM root handle."""
        stub = struct.pack("<I", 0)
        stub += ndr_dword(KEY_READ)
        resp = self._call(2, stub)
        handle, off = parse_context_handle(resp, 0)
        status, _ = parse_dword(resp, off)
        if status != 0:
            raise RuntimeError(f"OpenLocalMachine: 0x{status:08X}")
        return handle

    def open_key(self, parent: bytes, subkey: str) -> bytes:
        """BaseRegOpenKey (opnum 15) — open a subkey."""
        stub = ndr_handle(parent)
        stub += _rrp_string(subkey)
        stub += ndr_dword(0)
        stub += ndr_dword(KEY_READ)
        resp = self._call(15, stub)
        handle, off = parse_context_handle(resp, 0)
        status, _ = parse_dword(resp, off)
        if status != 0:
            raise RuntimeError(f"OpenKey '{subkey}': 0x{status:08X}")
        return handle

    def query_info_key(self, key: bytes) -> bytes:
        """BaseRegQueryInfoKey (opnum 16) — get key class name as raw UTF-16LE."""
        stub = ndr_handle(key)
        stub += _rrp_buf(256)
        resp = self._call(16, stub)
        raw, off = _parse_rrp_string(resp, 0)
        off += 7 * 4 + 8
        status, _ = parse_dword(resp, off)
        if status != 0:
            raise RuntimeError(f"QueryInfoKey: 0x{status:08X}")
        return raw

    def query_value(self, key: bytes, name: str,
                    max_size: int = 65536) -> tuple[int, bytes]:
        """BaseRegQueryValue (opnum 17) — read a value. name="" for default."""
        stub = ndr_handle(key)
        stub += _rrp_string(name)
        stub += struct.pack("<II", _ref_id(), 0)
        stub += struct.pack("<I", _ref_id())
        stub += struct.pack("<III", max_size, 0, 0)
        stub += struct.pack("<II", _ref_id(), max_size)
        stub += struct.pack("<II", _ref_id(), 0)

        resp = self._call(17, stub)
        off = 0

        ref = struct.unpack_from("<I", resp, off)[0]; off += 4
        val_type = 0
        if ref:
            val_type = struct.unpack_from("<I", resp, off)[0]; off += 4

        ref = struct.unpack_from("<I", resp, off)[0]; off += 4
        val_data = b""
        if ref:
            _, _, ac = struct.unpack_from("<III", resp, off); off += 12
            val_data = resp[off:off + ac]
            off += ac
            if ac % 4:
                off += 4 - (ac % 4)

        ref = struct.unpack_from("<I", resp, off)[0]; off += 4
        if ref:
            off += 4
        ref = struct.unpack_from("<I", resp, off)[0]; off += 4
        if ref:
            off += 4

        status = struct.unpack_from("<I", resp, off)[0]
        if status != 0:
            raise RuntimeError(f"QueryValue '{name}': 0x{status:08X}")
        return val_type, val_data

    def enum_key(self, key: bytes, index: int) -> str | None:
        """BaseRegEnumKey (opnum 9) — enumerate subkey by index. None at end."""
        stub = ndr_handle(key)
        stub += ndr_dword(index)
        stub += _rrp_buf(256)
        stub += struct.pack("<I", 0)
        stub += struct.pack("<I", 0)

        resp = self._call(9, stub)
        raw, off = _parse_rrp_string(resp, 0)

        ref = struct.unpack_from("<I", resp, off)[0]; off += 4
        if ref:
            _, off = _parse_rrp_string(resp, off)

        ref = struct.unpack_from("<I", resp, off)[0]; off += 4
        if ref:
            off += 8

        status = struct.unpack_from("<I", resp, off)[0]
        if status == 0x00000103:
            return None
        if status != 0:
            raise RuntimeError(f"EnumKey: 0x{status:08X}")

        return raw.decode("utf-16-le", errors="ignore").rstrip("\x00")

    def close_key(self, key: bytes) -> None:
        """BaseRegCloseKey (opnum 5)."""
        stub = ndr_handle(key)
        self._call(5, stub)

    def _call(self, opnum: int, stub_data: bytes) -> bytes:
        pdu = build_request(opnum, stub_data,
                            call_id=self._next_call_id())
        self._pipe.write(pdu)
        resp = self._pipe.read(65536)
        return parse_response(resp).stub_data

    def _next_call_id(self) -> int:
        self._call_id += 1
        return self._call_id
