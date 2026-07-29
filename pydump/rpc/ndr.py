"""Minimal NDR (Network Data Representation) encoding for SVCCTL operations.

Only implements the subset needed for Service Control Manager RPC calls:
- Conformant+varying strings (LPWSTR)
- Context handles (20 bytes)
- DWORD / LPBYTE / pointers

Reference: [C706] DCE/RPC NDR specification
"""

import struct


def ndr_wstring(s: str) -> bytes:
    """Encode a null-terminated wide string (conformant+varying LPWSTR).

    NDR format:
        [Referent ID: 4 bytes]
        [Max count: 4 bytes]   = len + 1 (including null)
        [Offset: 4 bytes]      = 0
        [Actual count: 4 bytes] = len + 1
        [UTF-16LE data + null terminator, padded to 4-byte boundary]
    """
    encoded = (s + "\x00").encode("utf-16-le")
    char_count = len(s) + 1  # including null

    result = struct.pack("<I", 0x00020000)  # referent pointer ID
    result += struct.pack("<III", char_count, 0, char_count)
    result += encoded

    # Pad to 4-byte alignment
    if len(encoded) % 4 != 0:
        result += b"\x00" * (4 - len(encoded) % 4)

    return result


def ndr_wstring_null() -> bytes:
    """Encode a NULL LPWSTR pointer."""
    return struct.pack("<I", 0)  # NULL referent


def ndr_dword(value: int) -> bytes:
    """Encode a DWORD (unsigned 32-bit)."""
    return struct.pack("<I", value)


def ndr_handle(handle: bytes) -> bytes:
    """Encode/pass-through a 20-byte context handle."""
    assert len(handle) == 20, f"Context handle must be 20 bytes, got {len(handle)}"
    return handle


def ndr_lpbyte(data: bytes | None) -> bytes:
    """Encode LPBYTE (pointer to conformant byte array)."""
    if data is None:
        return struct.pack("<I", 0)  # NULL pointer

    result = struct.pack("<I", 0x00020004)  # referent ID
    result += struct.pack("<I", len(data))  # max count
    result += struct.pack("<I", 0)  # offset
    result += struct.pack("<I", len(data))  # actual count
    result += data

    # Pad to 4-byte alignment
    if len(data) % 4 != 0:
        result += b"\x00" * (4 - len(data) % 4)

    return result


def parse_context_handle(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Parse a 20-byte context handle from response data."""
    handle = data[offset : offset + 20]
    return handle, offset + 20


def parse_dword(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Parse a DWORD from response data."""
    value = struct.unpack_from("<I", data, offset)[0]
    return value, offset + 4
