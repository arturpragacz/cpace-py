"""CPace balanced PAKE protocol implementation.

draft-irtf-cfrg-cpace, CPACE-X25519-SHA512 cipher suite.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from enum import Enum
from typing import Final

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

__version__ = "0.1.0"

__all__ = ["CPace", "CPaceError", "CPaceRole"]

# Curve25519 field and Elligator2 parameters (draft group G_X25519).
_Q: Final[int] = 2**255 - 19
_A: Final[int] = 486662
_Z: Final[int] = 2  # the non-square used by Elligator2 on Curve25519
_FIELD_BYTES: Final[int] = 32
_SHARE_SIZE: Final[int] = 32

_DSI: Final[bytes] = b"CPace255"
_DSI_ISK: Final[bytes] = b"CPace255_ISK"
_MAC_LABEL: Final[bytes] = b"CPaceMac"
_SID_OUTPUT_LABEL: Final[bytes] = b"CPaceSidOutput"
_SHA512_BLOCK_BYTES: Final[int] = 128

_INV2: Final[int] = pow(2, -1, _Q)
_LEGENDRE_POWER: Final[int] = (_Q - 1) // 2


class CPaceError(Exception):
    """A CPace step failed (bad peer share, tag mismatch, or out-of-order use)."""


class CPaceRole(Enum):
    """CPace protocol role in initiator-responder mode."""

    INITIATOR = "A"
    RESPONDER = "B"


def _prepend_len(data: bytes) -> bytes:
    length = len(data)
    out = bytearray()
    while True:
        out.append(length & 0x7F)
        length >>= 7
        if length == 0:
            break
        out[-1] |= 0x80
    return bytes(out) + data


def _lv_cat(*parts: bytes) -> bytes:
    return b"".join(_prepend_len(p) for p in parts)


def _generator_string(prs: bytes, ci: bytes, sid: bytes) -> bytes:
    len_zpad = max(
        0,
        _SHA512_BLOCK_BYTES - 1 - len(_prepend_len(prs)) - len(_prepend_len(_DSI)),
    )
    return _lv_cat(_DSI, prs, b"\x00" * len_zpad, ci, sid)


def _decode_u(value: bytes) -> int:
    u = bytearray(value)
    u[-1] &= 0x7F  # 255-bit field: ignore the unused top bit (RFC 7748)
    return int.from_bytes(u, "little")


def _inv0(x: int) -> int:
    return pow(x, _Q - 2, _Q)  # Fermat inversion: maps 0 to 0 (RFC 9380 inv0)


def _elligator2(r: int) -> bytes:
    r %= _Q
    v = (-_A * _inv0((1 + _Z * r * r) % _Q)) % _Q
    eps = pow((v * v * v + _A * v * v + v) % _Q, _LEGENDRE_POWER, _Q)  # B = 1
    x = (eps * v - (1 - eps) * _A * _INV2) % _Q
    return x.to_bytes(_FIELD_BYTES, "little")


def _calculate_generator(prs: bytes, ci: bytes, sid: bytes) -> bytes:
    gen_hash = hashlib.sha512(_generator_string(prs, ci, sid)).digest()[:_FIELD_BYTES]
    return _elligator2(_decode_u(gen_hash))


def _scalar_mult_vfy(scalar: bytes, point: bytes) -> bytes | None:
    """X25519 scalar mult, or None if the result encodes the identity (low order)."""
    try:
        shared = X25519PrivateKey.from_private_bytes(scalar).exchange(
            X25519PublicKey.from_public_bytes(point),
        )
    except ValueError:  # cryptography rejects low-order points outright
        return None
    if shared == bytes(_FIELD_BYTES):  # RFC 7748 all-zero check is a MAY; enforce it here
        return None
    return shared


class CPace:
    """One side of a CPACE-X25519-SHA512 run with optional explicit mutual confirmation."""

    __slots__ = (
        "_ad",
        "_derived",
        "_isk",
        "_mac_key",
        "_role",
        "_scalar",
        "_sid",
        "_sides",
        "public_share",
    )

    # set by derive(), guarded by _derived
    _isk: bytes
    _mac_key: bytes
    # ((Ya, ADa), (Yb, ADb)) — initiator side first
    _sides: tuple[tuple[bytes, bytes], tuple[bytes, bytes]]

    def __init__(
        self,
        *,
        role: CPaceRole,
        sid: bytes,
        ad: bytes,
        scalar: bytes,
        public_share: bytes,
    ) -> None:
        """Initialize from an explicit scalar and public share; prefer ``start()``."""
        self._role = role
        self._sid = sid
        self._ad = ad
        self._scalar: bytes | None = scalar
        self.public_share = public_share
        self._derived = False

    @classmethod
    def start(
        cls,
        *,
        role: CPaceRole,
        prs: bytes,
        sid: bytes,
        ci: bytes = b"",
        ad: bytes = b"",
    ) -> CPace:
        """Begin a CPace run, sampling a scalar and computing ``public_share``.

        ``prs`` is the password-related string, ``sid`` the session id (unique
        per run; if empty, use ``sid_output`` after ``derive()``), ``ci`` the
        channel identifier, and ``ad`` this side's associated data.
        """
        scalar = secrets.token_bytes(_FIELD_BYTES)
        share = _scalar_mult_vfy(scalar, _calculate_generator(prs, ci, sid))
        if share is None:  # a low-order generator makes every share the identity
            raise CPaceError("generator encodes a low-order point")
        return cls(role=role, sid=sid, ad=ad, scalar=scalar, public_share=share)

    def derive(self, peer_share: bytes, peer_ad: bytes = b"") -> None:
        """Ingest the peer's message, deriving ``isk`` and the confirmation MAC key."""
        if self._scalar is None:
            raise CPaceError("derive() may only be called once")
        scalar = self._scalar
        self._scalar = None  # single-use: consume before it can fail
        if len(peer_share) != _SHARE_SIZE:
            raise CPaceError(f"peer share must be {_SHARE_SIZE} bytes, got {len(peer_share)}")
        shared = _scalar_mult_vfy(scalar, peer_share)
        if shared is None:
            raise CPaceError("peer share encodes a low-order point")
        if self._role is CPaceRole.INITIATOR:
            sides = ((self.public_share, self._ad), (peer_share, peer_ad))
        else:
            sides = ((peer_share, peer_ad), (self.public_share, self._ad))
        transcript = _lv_cat(*sides[0]) + _lv_cat(*sides[1])
        self._sides = sides
        self._isk = hashlib.sha512(_lv_cat(_DSI_ISK, self._sid, shared) + transcript).digest()
        self._mac_key = hashlib.sha512(_MAC_LABEL + self._sid + self._isk).digest()
        self._derived = True

    @property
    def isk(self) -> bytes:
        """The intermediate session key; process with a KDF before use in a protocol."""
        if not self._derived:
            raise CPaceError("derive() must be called before accessing the ISK")
        return self._isk

    @property
    def sid_output(self) -> bytes:
        """Public session identifier for runs started with an empty ``sid``."""
        if not self._derived:
            raise CPaceError("derive() must be called before computing sid_output")
        transcript = _lv_cat(*self._sides[0]) + _lv_cat(*self._sides[1])
        return hashlib.sha512(_SID_OUTPUT_LABEL + transcript).digest()

    def tag(self) -> bytes:
        """Return this side's confirmation tag (``Ta`` for ``A``, ``Tb`` for ``B``)."""
        if not self._derived:
            raise CPaceError("derive() must be called before computing confirmation tags")
        return self._mac(own=True)

    def verify(self, peer_tag: bytes) -> bool:
        """Return whether ``peer_tag`` proves the peer's knowledge of the password."""
        if not self._derived:
            raise CPaceError("derive() must be called before computing confirmation tags")
        if self._sides[0] == self._sides[1]:  # reflection: expected peer tag equals own tag
            return False
        return hmac.compare_digest(peer_tag, self._mac(own=False))

    def _mac(self, *, own: bool) -> bytes:
        # Ta authenticates (Ya, ADa); Tb authenticates (Yb, ADb).
        share, ad = self._sides[0 if own == (self._role is CPaceRole.INITIATOR) else 1]
        return hmac.new(self._mac_key, _lv_cat(share, ad), hashlib.sha512).digest()
