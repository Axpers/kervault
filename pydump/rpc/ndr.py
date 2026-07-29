"""Minimal NDR (Network Data Representation) encoding for SVCCTL operations.

Only implements the subset needed for Service Control Manager RPC calls:
- Conformant+varying strings (LPWSTR)
- Context handles (20 bytes)
- DWORD / LPBYTE / pointers

Reference: [C706] DCE/RPC NDR specification
"""

import struct

# Auto-incrementing referent ID counter
_referent_id = 0x00020000


def _next_referent() -> int:
    global _referent_id
    _referent_id += 4
    return _referent_id


def ndr_wstring(s: str) -> bytes:
    """Encode a unique pointer to a null-terminated wide string (conformant+varying LPWSTR).

    NDR format (unique pointer — inline, for simple cases):
        [Referent ID: 4 bytes]
        [Max count: 4 bytes]   = len + 1 (including null)
        [Offset: 4 bytes]      = 0
        [Actual count: 4 bytes] = len + 1
        [UTF-16LE data + null terminator, padded to 4-byte boundary]
    """
    ref = struct.pack("<I", _next_referent())
    return ref + ndr_wstring_data(s)


def ndr_wstring_ref() -> bytes:
    """Emit just a non-NULL referent ID (4 bytes) for deferred encoding."""
    return struct.pack("<I", _next_referent())


def ndr_wstring_data(s: str) -> bytes:
    """Encode the conformant+varying string body (without referent ID).

    Used for deferred pointer data.
    """
    encoded = (s + "\x00").encode("utf-16-le")
    char_count = len(s) + 1

    result = struct.pack("<III", char_count, 0, char_count)
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


def ndr_lpbyte_null() -> bytes:
    """Encode a NULL LPBYTE pointer."""
    return struct.pack("<I", 0)


def parse_context_handle(data: bytes, offset: int = 0) -> tuple[bytes, int]:
    """Parse a 20-byte context handle from response data."""
    handle = data[offset : offset + 20]
    return handle, offset + 20


def parse_dword(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Parse a DWORD from response data."""
    value = struct.unpack_from("<I", data, offset)[0]
    return value, offset + 4
