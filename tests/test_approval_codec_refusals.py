# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The refusals of the device-approval object codec, one field at a time.

Every case starts from a valid shared FAKE object (the contract fixture), changes one thing, and
keeps the original signature, which `object_claims` never checks: what is refused here is the
shape of the claims, not the signature. Each refusal is a fixed code (`invalid_approval` 400 or
`approval_conflict` 409), never an exception of another kind, and none names the field.
"""

import json
from base64 import urlsafe_b64encode

import pytest

from carlos_patient_portal.approval_codec import (
    object_claims,
    verify_approval,
    verify_clinic,
)
from carlos_patient_portal.mailbox_codec import MailboxRefusal
from carlos_patient_portal.mycarlos_devices import strict_b64url_decode
from tests.test_approval_codec import FIXTURE, SCOPE

FLOWS = FIXTURE["flows"]


def b64(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode()


REMOVE = object()


def compact_with(source: dict, **changes: object) -> str:
    """The source object's compact form with `changes` applied (REMOVE drops a field, None makes
    it null) and its old signature kept."""
    claims = dict(source["claims"])
    for name, value in changes.items():
        if value is REMOVE:
            claims.pop(name, None)
        else:
            claims[name] = value
    payload = b64(json.dumps(claims, separators=(",", ":")).encode())
    return payload + "." + source["compact"].split(".")[1]


def refused(kind: str, flow: str, status: int = 400, code: str = "invalid_approval", **changes):
    source = FLOWS[flow][kind]
    with pytest.raises(MailboxRefusal) as failure:
        object_claims(kind, compact_with(source, **changes), **SCOPE)
    assert (failure.value.code, failure.value.status) == (code, status), changes


# --------------------------------------------------------------------------------------------
# The compact form itself
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        None,
        5,
        b"a.b",
        "été.AAAA",
        "a" * 8193,
        "nodot",
        "a.b.c",
        "!!!!.AAAA",
    ],
)
def test_a_compact_that_is_not_one_short_ascii_payload_dot_signature_is_refused(bad) -> None:
    with pytest.raises(MailboxRefusal) as failure:
        object_claims("intent", bad, **SCOPE)
    assert (failure.value.code, failure.value.status) == ("invalid_approval", 400)


def test_the_longest_compact_that_can_be_valid_is_read_and_one_more_character_is_not() -> None:
    """The limit is 8192 characters, but a 64-byte signature is 86 characters and the payload's
    base64 length is never 1 modulo 4, so the longest valid compact is 8191: that one is read.
    (A compact of exactly 8192 can never be valid, so `>` against `>=` there is not observable.)
    """
    from carlos_patient_portal.approval_codec import compact_parts

    signature = b64(bytes(range(64)))
    assert len(signature) == 86
    overhead = len(json.dumps({"pad": ""}, separators=(",", ":")))
    raw = json.dumps({"pad": "x" * (6078 - overhead)}, separators=(",", ":")).encode()
    assert len(raw) == 6078 and len(b64(raw)) == 8104
    longest = b64(raw) + "." + signature
    assert len(longest) == 8191
    claims, read_raw, read_signature = compact_parts(longest)
    assert read_raw == raw and read_signature == bytes(range(64)) and claims["pad"]
    # One more byte of payload makes 8193 characters: refused by the length, not by its shape.
    too_long = json.dumps({"pad": "x" * (6079 - overhead)}, separators=(",", ":")).encode()
    with pytest.raises(MailboxRefusal) as failure:
        compact_parts(b64(too_long) + "." + signature)
    assert (failure.value.code, failure.value.status) == ("invalid_approval", 400)


def test_a_signature_of_the_wrong_size_is_refused() -> None:
    source = FLOWS["first"]["intent"]
    payload = source["compact"].split(".")[0]
    for signature in (b64(bytes(63)), b64(bytes(65)), ""):
        with pytest.raises(MailboxRefusal) as failure:
            object_claims("intent", payload + "." + signature, **SCOPE)
        assert failure.value.code == "invalid_approval"


# --------------------------------------------------------------------------------------------
# The candidate device's keys
# --------------------------------------------------------------------------------------------


def test_a_candidate_key_that_is_not_a_canonical_key_is_refused() -> None:
    for name in (
        "candidate_device_key_id",
        "candidate_x25519_public_key",
        "candidate_ed25519_public_key",
    ):
        for bad in ("short", 7, None, "!" * 43, "A" * 44):
            refused("intent", "first", **{name: bad})


def test_an_all_zero_public_key_is_refused_even_though_it_is_canonical_and_its_id_matches() -> None:
    import hashlib

    zero = b64(bytes(32))
    claims = FLOWS["first"]["intent"]["claims"]
    x = strict_b64url_decode(claims["candidate_x25519_public_key"])
    ed = strict_b64url_decode(claims["candidate_ed25519_public_key"])

    def key_id(raw_x: bytes, raw_ed: bytes) -> str:
        framed = len(raw_x).to_bytes(8, "big") + raw_x + len(raw_ed).to_bytes(8, "big") + raw_ed
        return b64(hashlib.sha256(b"mycarlos-device-key-v1" + framed).digest())

    # The key id is made to match, so only the all-zero rule can refuse them.
    refused(
        "intent",
        "first",
        candidate_x25519_public_key=zero,
        candidate_device_key_id=key_id(bytes(32), ed),
    )
    refused(
        "intent",
        "first",
        candidate_ed25519_public_key=zero,
        candidate_device_key_id=key_id(x, bytes(32)),
    )


def test_a_key_id_that_is_not_the_hash_of_the_two_keys_is_refused() -> None:
    other = b64(bytes(range(32)))
    refused("intent", "first", candidate_device_key_id=other)


# --------------------------------------------------------------------------------------------
# The envelope
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["intent", "challenge", "acceptance"])
def test_another_portal_address_is_a_conflict_not_a_malformed_object(kind) -> None:
    refused(
        kind,
        "first",
        status=409,
        code="approval_conflict",
        public_portal_base_url="https://other.example.test",
    )


def test_the_approval_kind_does_not_carry_a_portal_address_so_it_is_never_a_conflict() -> None:
    source = FLOWS["later"]["approval"]
    assert "public_portal_base_url" not in source["claims"]
    key = FIXTURE["keys"]["predecessor"]
    assert verify_approval(
        source["compact"],
        predecessor_kid=key["device_key_id"],
        predecessor_ed=strict_b64url_decode(key["ed25519_public_key"]),
        **SCOPE,
    )


@pytest.mark.parametrize(
    ("kind", "name", "bad"),
    [
        ("intent", "request_id", "not-a-uuid"),
        ("intent", "request_id", "00000000-0000-1000-8000-000000000000"),  # a version 1 id
        ("intent", "request_id", 7),
        ("approval", "jti", "not-a-uuid"),
        ("challenge", "challenge_id", "short"),
        ("challenge", "kid", "short"),
        ("challenge", "candidate_intent_sha256", "xyz"),
        ("acceptance", "challenge_sha256", "ABC"),
        ("acceptance", "challenge_sha256", "0" * 63),
        ("intent", "iat", "1"),
        ("intent", "exp", -1),
        ("intent", "exp", True),
        ("challenge", "issued_at", 1.5),
        ("challenge", "expires_at", None),
        ("intent", "predecessor_device_key_id", "short"),
        ("challenge", "predecessor_device_key_id", 7),
        ("acceptance", "accepted_at", "1"),
    ],
)
def test_a_field_of_the_wrong_form_is_refused(kind, name, bad) -> None:
    flow = "later" if kind == "approval" else "first"
    refused(kind, flow, **{name: bad})


def test_an_intent_or_approval_must_come_from_mycarlos() -> None:
    refused("intent", "first", iss="someone-else")
    refused("approval", "later", iss="someone-else")
    refused("intent", "first", iss=REMOVE)


# --------------------------------------------------------------------------------------------
# Lifetimes, kinds and predecessors
# --------------------------------------------------------------------------------------------


def test_an_intent_must_end_after_it_began_and_within_its_life() -> None:
    source = FLOWS["first"]["intent"]["claims"]
    iat = source["iat"]
    version = source["v"]
    life = 86_400 if version == 2 else 600
    refused("intent", "first", exp=iat)  # no lifetime at all
    refused("intent", "first", exp=iat - 1)
    refused("intent", "first", exp=iat + life + 1)


def test_an_intent_and_a_challenge_may_last_exactly_their_life() -> None:
    from carlos_patient_portal.approval_codec import challenge_life, intent_life

    intent = FLOWS["first"]["intent"]["claims"]
    life = intent_life(intent["v"])
    kept, *_ = object_claims(
        "intent", compact_with(FLOWS["first"]["intent"], exp=intent["iat"] + life), **SCOPE
    )
    assert kept["exp"] - kept["iat"] == life
    for flow in ("first", "later"):
        challenge = FLOWS[flow]["challenge"]["claims"]
        life = challenge_life(challenge["v"], challenge["approval_kind"])
        kept, *_ = object_claims(
            "challenge",
            compact_with(FLOWS[flow]["challenge"], expires_at=challenge["issued_at"] + life),
            **SCOPE,
        )
        assert kept["expires_at"] - kept["issued_at"] == life


def test_a_challenge_must_end_after_it_was_issued_and_within_its_life() -> None:
    source = FLOWS["later"]["challenge"]["claims"]
    issued = source["issued_at"]
    refused("challenge", "later", expires_at=issued)
    refused("challenge", "later", expires_at=issued - 5)
    refused("challenge", "later", expires_at=issued + 86_401)


@pytest.mark.parametrize("flow", ["first", "later"])
def test_the_approval_kind_must_agree_with_whether_there_is_a_predecessor(flow) -> None:
    for kind in ("challenge", "acceptance"):
        claims = FLOWS[flow][kind]["claims"]
        has_predecessor = claims["predecessor_device_key_id"] is not None
        # A kind that needs the other answer.
        wrong = "accepted_device" if not has_predecessor else "staff_first"
        refused(kind, flow, approval_kind=wrong)
        refused(kind, flow, approval_kind="not-a-kind")


def test_a_predecessor_version_must_be_null_without_a_predecessor_and_a_cursor_with_one() -> None:
    refused("challenge", "first", predecessor_version="1")
    refused("challenge", "later", predecessor_version="not a cursor")
    refused("challenge", "later", predecessor_version=7)


def test_an_approval_needs_a_predecessor_and_an_acceptance_a_zero_version() -> None:
    # Without a predecessor (and so without a predecessor version) an approval has no one to be by.
    refused("approval", "later", predecessor_device_key_id=None, predecessor_version=None)
    refused("acceptance", "later", accepted_version="1")
    refused("acceptance", "first", approval_sha256="0" * 64)  # a first device has no approval
    refused("acceptance", "later", approval_sha256=None)  # a later one must name it
    refused("acceptance", "later", approval_sha256="xyz")


# --------------------------------------------------------------------------------------------
# The signatures' own keys
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("curve", ["ed25519", "p384"])
def test_a_clinic_key_that_is_not_a_p256_public_key_is_refused(curve) -> None:
    import hashlib

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519

    source = FLOWS["first"]["challenge"]
    if curve == "ed25519":
        other = ed25519.Ed25519PrivateKey.from_private_bytes(bytes(range(32))).public_key()
    else:
        other = ec.derive_private_key(12345, ec.SECP384R1()).public_key()
    spki = other.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    # Its hash is the object's key id, so only the key's kind is what is refused.
    kid = b64(hashlib.sha256(spki).digest())
    compact = compact_with(source, kid=kid)
    with pytest.raises(MailboxRefusal) as failure:
        verify_clinic("challenge", compact, spki=spki, **SCOPE)
    assert (failure.value.code, failure.value.status) == ("invalid_approval", 400)


def test_an_approval_by_another_predecessor_is_a_conflict() -> None:
    source = FLOWS["later"]["approval"]
    key = FIXTURE["keys"]["predecessor"]
    with pytest.raises(MailboxRefusal) as failure:
        verify_approval(
            source["compact"],
            predecessor_kid=b64(bytes(range(32))),
            predecessor_ed=strict_b64url_decode(key["ed25519_public_key"]),
            **SCOPE,
        )
    assert (failure.value.code, failure.value.status) == ("approval_conflict", 409)


# --------------------------------------------------------------------------------------------
# The small rules the routes lean on
# --------------------------------------------------------------------------------------------


def test_a_challenge_ends_at_its_kinds_life_and_never_after_its_intent() -> None:
    from carlos_patient_portal.approval_codec import (
        challenge_expiry,
        compact_hash,
        unanswered_until,
    )

    # v2 lets a staff_first request stay open a day; every other kind keeps ten minutes, v1 too.
    assert challenge_expiry(2, "staff_first", 1_000, 10**9) == 1_000 + 86_400
    assert challenge_expiry(2, "code", 1_000, 10**9) == 1_000 + 600
    assert challenge_expiry(1, "staff_first", 1_000, 10**9) == 1_000 + 600
    assert challenge_expiry(2, "staff_first", 1_000, 1_100) == 1_100  # never past its intent
    # A request with no challenge yet counts as open for ten minutes at most.
    assert unanswered_until(1_000, 5_000) == 1_600
    assert unanswered_until(1_000, 1_100) == 1_100
    # The hash of a compact object is the lower-case SHA-256 of its ASCII text.
    assert compact_hash("abc") == (
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    )
