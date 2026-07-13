"""CPACE-X25519-SHA512 tests against the draft's ``testvectors.json``."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from cpace import (
    _DSI_ISK,
    CPace,
    CPaceError,
    CPaceRole,
    _calculate_generator,
    _lv_cat,
    _scalar_mult_vfy,
)

_VECTORS = json.loads((Path(__file__).parent / "testvectors.json").read_text())
TV = {key: bytes.fromhex(value) for key, value in _VECTORS["G_25519"].items()}
INVALID_POINTS = {name: bytes.fromhex(value) for name, value in _VECTORS["X25519_points"].items()}

# Draft "Test vectors for G_X25519.scalar_mult_vfy: low order points": with scalar s,
# u0-u5 and u7 MUST abort; u6, u8, u9, ua, ub are low-order only if bit #255 is not
# cleared per RFC 7748 and MUST instead yield q6, q8, q9, qa, qb.
_VFY_SCALAR = bytes.fromhex("af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff")
ABORT_POINTS = [f"Invalid Y{i}" for i in (0, 1, 2, 3, 4, 5, 7)]
BIT255_POINT_RESULTS = {
    "Invalid Y6": "d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806",
    "Invalid Y8": "c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38",
    "Invalid Y9": "db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456",
    "Invalid Y10": "e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a",
    "Invalid Y11": "993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175",
}


def test_kat_calculate_generator() -> None:
    """Generator derivation matches the draft G_25519 vector."""
    assert _calculate_generator(TV["PRS"], TV["CI"], TV["sid"]) == TV["g"]


def test_kat_public_shares() -> None:
    """Ya and Yb match X25519(scalar, generator) for the draft vector."""
    assert _scalar_mult_vfy(TV["ya"], TV["g"]) == TV["Ya"]
    assert _scalar_mult_vfy(TV["yb"], TV["g"]) == TV["Yb"]


def test_kat_shared_secret_both_sides() -> None:
    """Both sides derive the draft's shared secret K."""
    assert _scalar_mult_vfy(TV["ya"], TV["Yb"]) == TV["K"]
    assert _scalar_mult_vfy(TV["yb"], TV["Ya"]) == TV["K"]


def test_kat_isk_ir() -> None:
    """The initiator-responder ISK matches the draft vector."""
    transcript = _lv_cat(TV["Ya"], TV["ADa"]) + _lv_cat(TV["Yb"], TV["ADb"])
    isk = hashlib.sha512(_lv_cat(_DSI_ISK, TV["sid"], TV["K"]) + transcript).digest()
    assert isk == TV["ISK_IR"]


def _from_vector(role: CPaceRole) -> CPace:
    scalar, share = (TV["ya"], TV["Ya"]) if role is CPaceRole.INITIATOR else (TV["yb"], TV["Yb"])
    ad = TV["ADa"] if role is CPaceRole.INITIATOR else TV["ADb"]
    return CPace(role=role, sid=TV["sid"], ad=ad, scalar=scalar, public_share=share)


@pytest.mark.parametrize("role", [CPaceRole.INITIATOR, CPaceRole.RESPONDER])
def test_kat_full_run(role: CPaceRole) -> None:
    """A full run seeded with the vector's scalars reproduces ISK_IR and sid_output_ir."""
    side = _from_vector(role)
    peer_share = TV["Yb"] if role is CPaceRole.INITIATOR else TV["Ya"]
    peer_ad = TV["ADb"] if role is CPaceRole.INITIATOR else TV["ADa"]
    side.derive(peer_share, peer_ad)
    assert side.isk == TV["ISK_IR"]
    assert side.sid_output == TV["sid_output_ir"]


def test_kat_confirmation_tags_cross_verify() -> None:
    """Vector-seeded initiator and responder produce mutually verifying tags."""
    initiator = _from_vector(CPaceRole.INITIATOR)
    responder = _from_vector(CPaceRole.RESPONDER)
    initiator.derive(TV["Yb"], TV["ADb"])
    responder.derive(TV["Ya"], TV["ADa"])
    assert initiator.tag() != responder.tag()
    assert responder.verify(initiator.tag())
    assert initiator.verify(responder.tag())


@pytest.mark.parametrize("name", ABORT_POINTS)
def test_scalar_mult_vfy_rejects_low_order_points(name: str) -> None:
    """Every abort-case point from the draft vector set maps to None."""
    assert _scalar_mult_vfy(_VFY_SCALAR, INVALID_POINTS[name]) is None


@pytest.mark.parametrize("name", ABORT_POINTS)
def test_derive_rejects_low_order_points(name: str) -> None:
    """derive() propagates low-order-point rejection."""
    side = CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=b"\x33" * 16)
    with pytest.raises(CPaceError):
        side.derive(INVALID_POINTS[name])


@pytest.mark.parametrize(("name", "expected"), BIT255_POINT_RESULTS.items())
def test_scalar_mult_vfy_clears_bit_255(name: str, expected: str) -> None:
    """Points that are low-order only without bit-255 clearing yield the draft's qN."""
    assert _scalar_mult_vfy(_VFY_SCALAR, INVALID_POINTS[name]) == bytes.fromhex(expected)


def test_round_trip_matching_password() -> None:
    """Matching passwords yield equal ISKs and mutually verifying tags."""
    sid = b"\x11" * 16
    initiator = CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=sid)
    responder = CPace.start(role=CPaceRole.RESPONDER, prs=b"password", sid=sid)

    initiator.derive(responder.public_share)
    responder.derive(initiator.public_share)

    assert initiator.isk == responder.isk
    assert initiator.sid_output == responder.sid_output
    assert responder.verify(initiator.tag())
    assert initiator.verify(responder.tag())


def test_round_trip_mismatched_password() -> None:
    """Mismatched passwords yield different ISKs and failing confirmation."""
    sid = b"\x22" * 16
    initiator = CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=sid)
    responder = CPace.start(role=CPaceRole.RESPONDER, prs=b"passw0rd", sid=sid)

    initiator.derive(responder.public_share)
    responder.derive(initiator.public_share)

    assert initiator.isk != responder.isk
    assert not responder.verify(initiator.tag())
    assert not initiator.verify(responder.tag())


def test_associated_data_binds_into_tags() -> None:
    """A peer_ad mismatch fails confirmation even with matching passwords."""
    sid = b"\x44" * 16
    initiator = CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=sid, ad=b"A")
    responder = CPace.start(role=CPaceRole.RESPONDER, prs=b"password", sid=sid, ad=b"B")

    initiator.derive(responder.public_share, b"B")
    responder.derive(initiator.public_share, b"wrong")

    assert not initiator.verify(responder.tag())


def test_use_before_derive_raises() -> None:
    """isk, sid_output, and tag() all require derive() first."""
    side = CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=b"s")
    with pytest.raises(CPaceError):
        _ = side.isk
    with pytest.raises(CPaceError):
        _ = side.sid_output
    with pytest.raises(CPaceError):
        side.tag()


def test_derive_twice_raises() -> None:
    """A CPace instance is single-use."""
    sid = b"\x55" * 16
    initiator = CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=sid)
    responder = CPace.start(role=CPaceRole.RESPONDER, prs=b"password", sid=sid)
    initiator.derive(responder.public_share)
    with pytest.raises(CPaceError):
        initiator.derive(responder.public_share)


def test_derive_rejects_wrong_length_share() -> None:
    """A wrong-length peer share is rejected."""
    side = CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=b"s")
    with pytest.raises(CPaceError):
        side.derive(b"too-short")


def test_verify_rejects_malformed_tag() -> None:
    """verify() returns False for wrong-length or wrong-value tags, without raising."""
    initiator = _from_vector(CPaceRole.INITIATOR)
    initiator.derive(TV["Yb"])
    assert not initiator.verify(b"too-short")
    assert not initiator.verify(bytes(64))


def test_verify_rejects_reflected_share() -> None:
    """A peer that echoes our own share and tag back fails confirmation (no false accept)."""
    initiator = CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=b"\x66" * 16)
    initiator.derive(initiator.public_share)  # attacker reflects our share
    assert not initiator.verify(initiator.tag())  # and reflects our own tag


def test_verify_rejects_reflected_share_with_distinct_ad() -> None:
    """With distinct ADs a reflected tag fails via the MAC comparison itself."""
    initiator = CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=b"\x77" * 16, ad=b"A")
    initiator.derive(initiator.public_share, b"B")
    assert not initiator.verify(initiator.tag())


def test_start_rejects_degenerate_generator(monkeypatch: pytest.MonkeyPatch) -> None:
    """start() raises CPaceError when the generator maps to a low-order point."""
    monkeypatch.setattr("cpace._calculate_generator", lambda *_: bytes(32))
    with pytest.raises(CPaceError):
        CPace.start(role=CPaceRole.INITIATOR, prs=b"password", sid=b"s")
