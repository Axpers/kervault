"""DCE/RPC protocol layer — PDU construction and parsing.

Implements just enough of DCE/RPC (MS-RPCE) to communicate over SMB named pipes:
- Bind / Bind Ack (with optional NTLM auth verifiers)
- Auth3 (for NTLM handshake completion)
- Request / Response (bare or sealed at PKT_PRIVACY level)
- Fragmentation handling

Reference: [MS-RPCE] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce
"""

import os
import struct
from dataclasses import dataclass

# PDU types
BIND = 11
BIND_ACK = 12
AUTH3 = 16
REQUEST = 0
RESPONSE = 2
FAULT = 3

# Auth
NTLMSSP = 0x0A
PKT_PRIVACY = 0x06

# Flags
PFC_FIRST_FRAG = 0x01
PFC_LAST_FRAG = 0x02


@dataclass
class RpcResponse:
    """Parsed RPC response."""
    call_id: int
    stub_data: bytes


def build_bind(interface_uuid: bytes, interface_version: tuple[int, int], call_id: int = 1) -> bytes:
    """Build a DCE/RPC Bind PDU.

    Args:
        interface_uuid: 16-byte UUID of the target interface
        interface_version: (major, minor) version tuple
        call_id: RPC call identifier
    """
    # Transfer syntax: NDR 2.0
    ndr_uuid = b"\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"
    ndr_version = struct.pack("<HH", 2, 0)

    # Context item (1 context, 1 transfer syntax)
    ctx_item = struct.pack("<HBB", 0, 1, 0)  # context_id=0, num_transfer=1, reserved
    ctx_item += interface_uuid
    ctx_item += struct.pack("<HH", interface_version[0], interface_version[1])
    ctx_item += ndr_uuid
    ctx_item += ndr_version

    # Bind body
    body = struct.pack("<HHI", 4280, 4280, 0)  # max_xmit, max_recv, assoc_group
    body += struct.pack("<I", 1)  # num_ctx_items (as u32 with padding)
    body += ctx_item

    # Common header
    header = _build_header(BIND, call_id, len(body))

    return header + body


def build_request(opnum: int, stub_data: bytes, call_id: int = 1) -> bytes:
    """Build a DCE/RPC Request PDU.

    Args:
        opnum: Operation number in the interface
        stub_data: NDR-encoded arguments
        call_id: RPC call identifier
    """
    # Request header fields: alloc_hint(4) + context_id(2) + opnum(2)
    body = struct.pack("<IHH", len(stub_data), 0, opnum)
    body += stub_data

    header = _build_header(REQUEST, call_id, len(body))

    return header + body


def parse_response(data: bytes) -> RpcResponse:
    """Parse a DCE/RPC Response PDU.

    Raises:
        RuntimeError: If the PDU is a Fault or unexpected type
    """
    if len(data) < 24:
        raise RuntimeError(f"RPC response too short: {len(data)} bytes")

    _, _, ptype, flags, _, frag_length, _, call_id = struct.unpack_from(
        "<BBBBIHHI", data, 0
    )

    if ptype == FAULT:
        status = struct.unpack_from("<I", data, 24)[0] if len(data) >= 28 else 0
        raise RuntimeError(f"RPC Fault: status=0x{status:08X}")

    if ptype == BIND_ACK:
        return RpcResponse(call_id=call_id, stub_data=data[24:])

    if ptype != RESPONSE:
        raise RuntimeError(f"Unexpected RPC PDU type: {ptype}")

    # Response: skip alloc_hint(4) + context_id(2) + cancel_count(1) + reserved(1)
    stub_data = data[24:]

    return RpcResponse(call_id=call_id, stub_data=stub_data)


def _build_header(ptype: int, call_id: int, body_len: int,
                  auth_len: int = 0) -> bytes:
    """Build the 16-byte common RPC header."""
    frag_length = 16 + body_len

    return struct.pack(
        "<BBBBIHHI",
        5,                              # rpc_vers
        0,                              # rpc_vers_minor
        ptype,                          # PTYPE
        PFC_FIRST_FRAG | PFC_LAST_FRAG, # flags
        0x00000010,                     # data representation (little-endian, ASCII, IEEE)
        frag_length,                    # frag_length
        auth_len,                       # auth_length
        call_id,                        # call_id
    )


# --- Authenticated PDU construction (for PKT_PRIVACY / NTLM) ---


_AUTH_CTX_ID = os.getpid() & 0xFFFFFFFF


def _sec_trailer(auth_pad: int = 0) -> bytes:
    return struct.pack("<BBBBI", NTLMSSP, PKT_PRIVACY, auth_pad, 0, _AUTH_CTX_ID)


def build_bind_auth(interface_uuid: bytes, interface_version: tuple[int, int],
                    auth_token: bytes, call_id: int = 1) -> bytes:
    """Build a BIND PDU with an NTLM auth verifier."""
    ndr_uuid = b"\x04\x5d\x88\x8a\xeb\x1c\xc9\x11\x9f\xe8\x08\x00\x2b\x10\x48\x60"
    ndr_version = struct.pack("<HH", 2, 0)

    ctx_item = struct.pack("<HBB", 0, 1, 0)
    ctx_item += interface_uuid
    ctx_item += struct.pack("<HH", interface_version[0], interface_version[1])
    ctx_item += ndr_uuid
    ctx_item += ndr_version

    body = struct.pack("<HHI", 4280, 4280, 0)
    body += struct.pack("<I", 1)
    body += ctx_item

    trailer = _sec_trailer()
    auth_len = len(auth_token)
    frag_len = 16 + len(body) + 8 + auth_len

    header = struct.pack(
        "<BBBBIHHI",
        5, 0, BIND, PFC_FIRST_FRAG | PFC_LAST_FRAG,
        0x00000010, frag_len, auth_len, call_id,
    )
    return header + body + trailer + auth_token


def parse_bind_ack_auth(data: bytes) -> bytes:
    """Extract the NTLM challenge token from a BIND_ACK."""
    if len(data) < 16:
        raise RuntimeError("BIND_ACK too short")
    _, _, ptype, _, _, frag_len, auth_len, _ = struct.unpack_from(
        "<BBBBIHHI", data, 0
    )
    if ptype == FAULT:
        raise RuntimeError("RPC Fault on BIND")
    if ptype != BIND_ACK:
        raise RuntimeError(f"Expected BIND_ACK (12), got {ptype}")
    if auth_len == 0:
        raise RuntimeError("No auth data in BIND_ACK")
    return data[frag_len - auth_len : frag_len]


def build_auth3(auth_token: bytes, call_id: int = 1) -> bytes:
    """Build an AUTH3 PDU with an NTLM authenticate token."""
    pad = b"\x20" * 4
    trailer = _sec_trailer()
    auth_len = len(auth_token)
    frag_len = 16 + 4 + 8 + auth_len

    header = struct.pack(
        "<BBBBIHHI",
        5, 0, AUTH3, PFC_FIRST_FRAG | PFC_LAST_FRAG,
        0x00000010, frag_len, auth_len, call_id,
    )
    return header + pad + trailer + auth_token


def build_sealed_request(opnum: int, stub_data: bytes, seal_ctx,
                         call_id: int = 1) -> bytes:
    """Build a REQUEST PDU with PKT_PRIVACY sealed stub data."""
    auth_pad = (4 - (len(stub_data) % 4)) % 4
    padded = stub_data + b"\xBB" * auth_pad

    req_hdr = struct.pack("<IHH", len(padded), 0, opnum)
    trailer = _sec_trailer(auth_pad)

    sig_len = 16
    frag_len = 16 + 8 + len(padded) + 8 + sig_len

    header = struct.pack(
        "<BBBBIHHI",
        5, 0, REQUEST, PFC_FIRST_FRAG | PFC_LAST_FRAG,
        0x00000010, frag_len, sig_len, call_id,
    )

    pdu_to_sign = header + req_hdr + padded + trailer
    encrypted, signature = seal_ctx.seal(padded, pdu_to_sign)

    return header + req_hdr + encrypted + trailer + signature


def parse_sealed_response(data: bytes, seal_ctx) -> bytes:
    """Parse a RESPONSE PDU and unseal the stub data."""
    if len(data) < 24:
        raise RuntimeError(f"RPC response too short: {len(data)} bytes")

    _, _, ptype, _, _, frag_len, auth_len, _ = struct.unpack_from(
        "<BBBBIHHI", data, 0
    )

    if ptype == FAULT:
        status = struct.unpack_from("<I", data, 24)[0] if len(data) >= 28 else 0
        raise RuntimeError(f"RPC Fault: status=0x{status:08X}")

    if ptype != RESPONSE:
        raise RuntimeError(f"Unexpected RPC PDU type: {ptype}")

    if auth_len == 0:
        return data[24:]

    sig_start = frag_len - auth_len
    trailer_start = sig_start - 8

    sealed = data[24:trailer_start]
    auth_pad = data[trailer_start + 2]
    sig = data[sig_start : sig_start + auth_len]

    plain = seal_ctx.unseal(sealed, sig)

    if auth_pad > 0:
        plain = plain[:-auth_pad]

    return plain
