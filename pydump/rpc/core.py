"""DCE/RPC protocol layer — PDU construction and parsing.

Implements just enough of DCE/RPC (MS-RPCE) to communicate over SMB named pipes:
- Bind / Bind Ack
- Request / Response
- Fragmentation handling

Reference: [MS-RPCE] https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce
"""

import struct
from dataclasses import dataclass

# PDU types
BIND = 11
BIND_ACK = 12
REQUEST = 0
RESPONSE = 2
FAULT = 3

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


def _build_header(ptype: int, call_id: int, body_len: int) -> bytes:
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
        0,                              # auth_length
        call_id,                        # call_id
    )
