"""What the mailbox codec refuses: an oversized or malformed JSON object, a key that is not
canonical base64url, and every way a delivery receipt can be wrong (size, encoding, signature,
claims).

Synthetic keys and ids only; receipts are signed here with a throwaway Ed25519 key.
"""

import json
from base64 import urlsafe_b64encode

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from carlos_patient_portal.mailbox_codec import (
    LONG_MAX,
    MailboxRefusal,
    canonical_key,
    receipt_claims,
    strict_object,
)

KID = "FAKE-device-key-id"
RECIPIENT = "FAKE-recipient"
DELIVERY = "6f9619ff-8b86-4d11-b42d-00c04fc964ff"  # a version 4 UUID
JTI = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"  # any UUID
HASH = "ab" * 32

SIGNER = Ed25519PrivateKey.generate()
OTHER = Ed25519PrivateKey.generate()
PUBLIC = SIGNER.public_key().public_bytes(
    serialization.Encoding.Raw, serialization.PublicFormat.Raw
)


def b64(raw: bytes) -> str:
    return urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def good_claims() -> dict:
    return {
        "typ": "mycarlos-delivery-receipt",
        "aud": "carlos-delivery-receipt",
        "delivery_id": DELIVERY,
        "recipient_id": RECIPIENT,
        "device_key_id": KID,
        "ciphertext_sha256": HASH,
        "document_sha256": HASH,
        "picked_up_at": 1_790_000_000,
        "vault_head_link": HASH,
        "jti": JTI,
    }


def signed(claims, key=SIGNER) -> str:
    payload = json.dumps(claims, separators=(",", ":")).encode()
    return f"{b64(payload)}.{b64(key.sign(payload))}"


def verify(compact: str) -> dict:
    return receipt_claims(compact, key=PUBLIC, kid=KID, recipient=RECIPIENT)


def refused(compact: str) -> MailboxRefusal:
    with pytest.raises(MailboxRefusal) as caught:
        verify(compact)
    return caught.value


def test_a_well_formed_receipt_signed_by_the_device_is_accepted():
    assert verify(signed(good_claims())) == good_claims()


def test_an_object_over_its_limit_is_refused_before_it_is_parsed():
    assert strict_object(b'{"a":1}', limit=7, code="FAKE") == {"a": 1}
    with pytest.raises(MailboxRefusal) as caught:
        strict_object(b'{"a":12}', limit=7, code="FAKE-limit")
    assert caught.value.code == "FAKE-limit"


@pytest.mark.parametrize(
    "raw",
    [
        b"\xff",  # not UTF-8
        b"{",  # not JSON
        b'{"a":1,"a":2}',  # a repeated member
        b'{"a":NaN}',  # a non-finite number
        b"[1]",  # not an object
        b'"text"',
        b"7",
    ],
)
def test_an_object_that_is_not_strict_json_is_refused_with_the_callers_code(raw):
    with pytest.raises(MailboxRefusal) as caught:
        strict_object(raw, limit=4096, code="FAKE-code")
    assert caught.value.code == "FAKE-code"


def test_a_key_must_be_exactly_the_canonical_base64url_of_32_bytes():
    assert canonical_key(b64(bytes(range(32))))
    assert not canonical_key(b64(bytes(31)))  # 31 bytes
    assert not canonical_key("A" * 42 + "B")  # extra bits in the last character
    assert not canonical_key("!" + "A" * 42)  # a character outside the alphabet leaves it short
    assert not canonical_key("A" * 42 + "é")  # not ASCII
    assert not canonical_key("A" * 44)
    assert not canonical_key(None)
    assert not canonical_key(b"A" * 43)


@pytest.mark.parametrize(
    "compact",
    [
        "",  # too short
        "x" * 4097,  # too long
        "é." + b64(bytes(64)),  # not ASCII
        "only-one-part",  # no separator
        "a.b.c",  # three parts
    ],
)
def test_a_receipt_of_the_wrong_size_or_shape_is_refused(compact):
    assert refused(compact).code == "invalid_receipt"


def test_a_receipt_is_refused_for_its_length_alone_just_past_4096_characters():
    # Valid in every other way: correctly signed claims, padded with JSON white space. The payload
    # stays well under its own 4,096-byte limit, so only the receipt's length can refuse it.
    # Base64 grows in steps, so a receipt of exactly 4,096 characters cannot be made this way; the
    # sizes either side of the limit are 4,095 (accepted) and 4,097 (refused).
    sizes = {}
    for spaces in range(3200):
        payload = (json.dumps(good_claims(), separators=(",", ":")) + " " * spaces).encode()
        compact = f"{b64(payload)}.{b64(SIGNER.sign(payload))}"
        sizes.setdefault(len(compact), compact)
    assert 4095 in sizes and 4097 in sizes
    assert verify(sizes[4095]) == good_claims()
    assert refused(sizes[4097]).code == "invalid_receipt"


def test_a_receipt_whose_parts_are_not_canonical_base64url_is_refused():
    good = signed(good_claims())
    encoded, signature = good.split(".")
    assert refused(f"{encoded}=.{signature}").code == "invalid_receipt"  # padding kept
    assert refused(f"{encoded}.{signature}=").code == "invalid_receipt"
    assert refused(f"{encoded[:-1]}B.{signature}").code == "invalid_receipt"  # spare bits set


def test_a_receipt_signature_of_the_wrong_length_is_refused():
    payload = json.dumps(good_claims(), separators=(",", ":")).encode()
    for size in (0, 63, 65):
        refusal = refused(f"{b64(payload)}.{b64(bytes(size))}")
        assert refusal.code == "invalid_receipt", size


def test_a_receipt_signed_by_another_key_or_changed_after_signing_is_refused():
    assert refused(signed(good_claims(), key=OTHER)).code == "invalid_receipt"
    encoded, signature = signed(good_claims()).split(".")
    changed = dict(good_claims(), picked_up_at=1_790_000_001)
    other_payload = json.dumps(changed, separators=(",", ":")).encode()
    assert refused(f"{b64(other_payload)}.{signature}").code == "invalid_receipt"


def test_a_receipt_that_is_not_a_json_object_is_refused_even_when_signed():
    for payload in (b"[1]", b"{", b'{"typ":1,"typ":2}', b"\xff"):
        compact = f"{b64(payload)}.{b64(SIGNER.sign(payload))}"
        assert refused(compact).code == "invalid_receipt", payload


@pytest.mark.parametrize(
    ("change", "why"),
    [
        ({"typ": "mycarlos-delivery-receipt-2"}, "a wrong type"),
        ({"aud": "someone-else"}, "a wrong audience"),
        ({"device_key_id": "FAKE-another-device"}, "another device"),
        ({"recipient_id": "FAKE-another-recipient"}, "another recipient"),
        ({"delivery_id": JTI}, "a delivery id that is not a version 4 UUID"),
        ({"delivery_id": DELIVERY.upper()}, "a delivery id not in canonical form"),
        ({"jti": "not-a-uuid"}, "a jti that is not a UUID"),
        ({"picked_up_at": -1}, "a time before the epoch"),
        ({"picked_up_at": LONG_MAX + 1}, "a time past a signed 64-bit integer"),
        ({"picked_up_at": True}, "a boolean as the time"),
        ({"picked_up_at": 1.5}, "a fractional time"),
        ({"ciphertext_sha256": "AB" * 32}, "an upper-case hash"),
        ({"document_sha256": "ab" * 31}, "a short hash"),
        ({"vault_head_link": 7}, "a hash that is not text"),
    ],
)
def test_a_correctly_signed_receipt_with_a_wrong_claim_is_refused(change, why):
    claims = good_claims() | change
    assert refused(signed(claims)).code == "invalid_receipt", why


@pytest.mark.parametrize("drop", sorted(good_claims()))
def test_a_receipt_with_a_missing_claim_is_refused(drop):
    claims = good_claims()
    del claims[drop]
    assert refused(signed(claims)).code == "invalid_receipt"


def test_a_receipt_with_an_extra_claim_is_refused():
    assert refused(signed(good_claims() | {"extra": 1})).code == "invalid_receipt"
