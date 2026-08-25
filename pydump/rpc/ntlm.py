"""NTLMv2 authentication and sealing for DCE/RPC PKT_PRIVACY.

Implements:
- Type 1/2/3 message construction (MS-NLMP)
- Bidirectional seal/unseal with the negotiated session key

Supports both password and pass-the-hash (raw NT hash).
Uses pycryptodome for crypto — no pyspnego dependency.
"""

import hashlib
import hmac as _hmac
import os
import struct
import time

from Crypto.Cipher import ARC4
from Crypto.Hash import MD4

_SIG = b"NTLMSSP\x00"

_FLAGS = (
    0x80000000  # NEGOTIATE_56
    | 0x40000000  # KEY_EXCH
    | 0x20000000  # NEGOTIATE_128
    | 0x00800000  # NEGOTIATE_TARGET_INFO
    | 0x00080000  # EXTENDED_SESSIONSECURITY
    | 0x00008000  # ALWAYS_SIGN
    | 0x00000200  # NEGOTIATE_NTLM
    | 0x00000020  # NEGOTIATE_SEAL
    | 0x00000010  # NEGOTIATE_SIGN
    | 0x00000004  # REQUEST_TARGET
    | 0x00000001  # NEGOTIATE_UNICODE
)

_C2S_SIGN = b"session key to client-to-server signing key magic constant\x00"
_C2S_SEAL = b"session key to client-to-server sealing key magic constant\x00"
_S2C_SIGN = b"session key to server-to-client signing key magic constant\x00"
_S2C_SEAL = b"session key to server-to-client sealing key magic constant\x00"


def _nthash(password: str) -> bytes:
    return MD4.new(password.encode("utf-16-le")).digest()


def _ntv2_key(nt: bytes, user: str, domain: str = "") -> bytes:
    return _hmac.new(
        nt, (user.upper() + domain).encode("utf-16-le"), hashlib.md5
    ).digest()


def _filetime() -> bytes:
    return struct.pack(
        "<Q", int(time.time() * 10_000_000) + 116_444_736_000_000_000
    )


def _av_timestamp(info: bytes) -> bytes | None:
    off = 0
    while off + 4 <= len(info):
        aid, alen = struct.unpack_from("<HH", info, off)
        if aid == 7:
            return info[off + 4 : off + 4 + alen]
        if aid == 0:
            break
        off += 4 + alen
    return None


# --- NTLM messages ---


def negotiate() -> bytes:
    """Build NTLM Type 1 (NEGOTIATE) message."""
    return (
        _SIG
        + struct.pack("<I", 1)
        + struct.pack("<I", _FLAGS)
        + b"\x00" * 8  # DomainNameFields
        + b"\x00" * 8  # WorkstationFields
    )


def _parse_challenge(data: bytes) -> tuple[bytes, bytes]:
    """Extract (server_challenge, target_info) from Type 2."""
    chal = data[24:32]
    ti_len = struct.unpack_from("<H", data, 40)[0]
    ti_off = struct.unpack_from("<I", data, 44)[0]
    return chal, data[ti_off : ti_off + ti_len]


def authenticate(
    type2: bytes,
    username: str,
    password: str | None = None,
    nt_hash_hex: str | None = None,
    domain: str = "",
) -> tuple[bytes, bytes]:
    """Build Type 3 (AUTHENTICATE) from a Type 2 challenge.

    Returns (type3_message, exported_session_key).
    """
    srv_chal, target_info = _parse_challenge(type2)

    nt = bytes.fromhex(nt_hash_hex) if nt_hash_hex else _nthash(password)
    rk = _ntv2_key(nt, username, domain)

    ts = _av_timestamp(target_info) or _filetime()
    cn = os.urandom(8)

    blob = struct.pack("<BBHI", 1, 1, 0, 0) + ts + cn
    blob += struct.pack("<I", 0) + target_info + struct.pack("<I", 0)

    proof = _hmac.new(rk, srv_chal + blob, hashlib.md5).digest()
    nt_resp = proof + blob
    lm_resp = b"\x00" * 24

    sbk = _hmac.new(rk, proof, hashlib.md5).digest()
    esk = os.urandom(16)
    enc_esk = ARC4.new(sbk).encrypt(esk)

    dom_b = domain.encode("utf-16-le")
    usr_b = username.encode("utf-16-le")

    base = 64
    d_o = base
    u_o = d_o + len(dom_b)
    w_o = u_o + len(usr_b)
    lm_o = w_o
    nt_o = lm_o + len(lm_resp)
    ek_o = nt_o + len(nt_resp)

    msg = _SIG + struct.pack("<I", 3)
    msg += struct.pack("<HHI", len(lm_resp), len(lm_resp), lm_o)
    msg += struct.pack("<HHI", len(nt_resp), len(nt_resp), nt_o)
    msg += struct.pack("<HHI", len(dom_b), len(dom_b), d_o)
    msg += struct.pack("<HHI", len(usr_b), len(usr_b), u_o)
    msg += struct.pack("<HHI", 0, 0, w_o)
    msg += struct.pack("<HHI", len(enc_esk), len(enc_esk), ek_o)
    msg += struct.pack("<I", _FLAGS)

    msg += dom_b + usr_b + lm_resp + nt_resp + enc_esk

    return msg, esk


# --- Seal / unseal ---


class SealContext:
    """Bidirectional NTLM seal/unseal using the exported session key."""

    def __init__(self, session_key: bytes):
        self._c_sign = hashlib.md5(session_key + _C2S_SIGN).digest()
        self._c_rc4 = ARC4.new(hashlib.md5(session_key + _C2S_SEAL).digest())
        self._c_seq = 0

        self._s_sign = hashlib.md5(session_key + _S2C_SIGN).digest()
        self._s_rc4 = ARC4.new(hashlib.md5(session_key + _S2C_SEAL).digest())
        self._s_seq = 0

    def seal(self, data: bytes, sign_data: bytes | None = None) -> tuple[bytes, bytes]:
        """Seal outbound data. Returns (encrypted, 16-byte signature).

        With NTLM2 (extended session security), the HMAC covers the entire
        PDU (header + stub + sec_trailer), not just the stub.  Pass the full
        PDU-minus-signature as *sign_data*; *data* is the stub to encrypt.
        """
        seq = struct.pack("<I", self._c_seq)
        self._c_seq += 1

        encrypted = self._c_rc4.encrypt(data)
        chk = _hmac.new(
            self._c_sign, seq + (sign_data if sign_data is not None else data),
            hashlib.md5,
        ).digest()[:8]
        enc_chk = self._c_rc4.encrypt(chk)

        return encrypted, struct.pack("<I", 1) + enc_chk + seq

    def unseal(self, encrypted: bytes, signature: bytes,
               sign_data: bytes | None = None) -> bytes:
        """Unseal inbound data.

        For NTLM2, pass the full PDU (with plaintext stub swapped in,
        minus the 16-byte signature) as *sign_data*.
        """
        data = self._s_rc4.decrypt(encrypted)

        seq = struct.pack("<I", self._s_seq)
        self._s_seq += 1
        chk = _hmac.new(
            self._s_sign, seq + (sign_data if sign_data is not None else data),
            hashlib.md5,
        ).digest()[:8]
        self._s_rc4.decrypt(chk)  # advance RC4 state

        return data
