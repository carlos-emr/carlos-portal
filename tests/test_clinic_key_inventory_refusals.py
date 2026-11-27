"""What the clinic key inventory refuses, and why each refusal protects the patient.

The portal publishes the clinic's signing keys, and myCarlos trusts them to check what the clinic
sends. A key that is not a plain P-256 public key, a kid that is not the hash of its key, a list
with the same key twice, or a replacement chain that does not start at a key we already trusted
must never be stored. Every key here is generated for the test; the clinic id and kids are FAKE.
"""

from hashlib import sha256

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from carlos_patient_portal.clinic_key_proofs import (
    MAX_CLINIC_KEY_INVENTORY,
    ClinicKeyInventoryError,
    ClinicKeyMaterial,
    checked_public_key,
    replacement_statement,
    validate_clinic_key_inventory,
)
from carlos_patient_portal.device_identity import b64url

CLINIC = "FAKE-clinic"


def spki_of(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def new_pair(curve: ec.EllipticCurve | None = None):
    private = ec.generate_private_key(curve or ec.SECP256R1())
    return private, spki_of(private.public_key())


def material(spki: bytes, status: str = "active", **fields) -> ClinicKeyMaterial:
    return ClinicKeyMaterial(
        kid=b64url(sha256(spki).digest()), spki=spki, status=status, **fields
    )


def signed_successor(predecessor_private, predecessor: ClinicKeyMaterial) -> ClinicKeyMaterial:
    """A new key that the predecessor vouches for, with a standard P-256 replacement proof."""
    _, spki = new_pair()
    unsigned = material(spki)
    der = predecessor_private.sign(
        replacement_statement(CLINIC, predecessor.kid, unsigned), ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(der)
    return material(
        spki,
        replaces_kid=predecessor.kid,
        replacement_signature=r.to_bytes(32, "big") + s.to_bytes(32, "big"),
    )


# --- a key is accepted only as a plain, canonical P-256 key named by its own hash -------------


def test_a_p256_key_named_by_the_hash_of_its_encoding_is_accepted() -> None:
    private, spki = new_pair()

    public = checked_public_key(material(spki))

    assert spki_of(public) == spki


@pytest.mark.parametrize(
    "spki",
    [b"", b"not a der encoded key", b"\x30\x03\x02\x01\x00"],
    ids=["empty", "text", "truncated structure"],
)
def test_bytes_that_are_not_a_public_key_are_refused_not_crashed_on(spki: bytes) -> None:
    with pytest.raises(ClinicKeyInventoryError) as refused:
        checked_public_key(material(spki))

    assert refused.value.code == "invalid_key"


def test_a_public_key_of_another_kind_or_curve_is_refused() -> None:
    # A real key that is valid but is not P-256: the clinic's proofs are P-256 only, so a
    # different curve or algorithm would be verified by something else than what was reviewed.
    other_curve = spki_of(ec.generate_private_key(ec.SECP384R1()).public_key())
    other_algorithm = spki_of(rsa.generate_private_key(65537, 2048).public_key())

    for spki in (other_curve, other_algorithm):
        with pytest.raises(ClinicKeyInventoryError) as refused:
            checked_public_key(material(spki))
        assert refused.value.code == "invalid_key"


def test_a_kid_that_is_not_the_hash_of_its_key_is_refused() -> None:
    # The kid is how the rest of the system names a key, so it must be the key's own hash: a
    # different name for the same key (or the name of another key) cannot be listed.
    _, spki = new_pair()
    _, other_spki = new_pair()

    for kid in (b64url(sha256(other_spki).digest()), "FAKE-kid", ""):
        with pytest.raises(ClinicKeyInventoryError) as refused:
            checked_public_key(ClinicKeyMaterial(kid=kid, spki=spki, status="active"))
        assert refused.value.code == "invalid_key"


def compressed_spki(public_key) -> bytes:
    """The same P-256 key as an SPKI whose point is written compressed (33 bytes, not 65)."""
    point = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    header = bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")
    return header + point


def test_the_bytes_stored_for_a_key_must_be_its_canonical_encoding_not_another_spelling() -> None:
    # The same key can be written more than one way and still load. The kid is the hash of the
    # CANONICAL encoding, so a kid that is right for this key does not by itself prove the bytes
    # next to it are the canonical ones: a different spelling under the right kid would store
    # other bytes for the same name (and a replacement proof signs the stored bytes). Only the
    # canonical encoding is accepted. Here the key loads, and the kid is the canonical hash, so
    # only the canonical-encoding check can refuse it.
    private, canonical = new_pair()
    other_spelling = compressed_spki(private.public_key())
    assert serialization.load_der_public_key(other_spelling).public_numbers() == (
        private.public_key().public_numbers()
    )
    assert other_spelling != canonical
    right_kid = b64url(sha256(canonical).digest())

    with pytest.raises(ClinicKeyInventoryError) as refused:
        checked_public_key(
            ClinicKeyMaterial(kid=right_kid, spki=other_spelling, status="active")
        )

    assert refused.value.code == "invalid_key"
    # The canonical bytes under the same kid are accepted.
    checked_public_key(ClinicKeyMaterial(kid=right_kid, spki=canonical, status="active"))


# --- the list itself --------------------------------------------------------------------------


def test_the_same_key_listed_twice_is_refused_with_the_list_code() -> None:
    _, spki = new_pair()
    key = material(spki)

    with pytest.raises(ClinicKeyInventoryError) as refused:
        validate_clinic_key_inventory(CLINIC, [key, key])

    assert refused.value.code == "invalid_key_list"


def test_an_empty_list_and_a_list_over_the_limit_are_refused_and_the_limit_itself_is_not() -> None:
    limit = MAX_CLINIC_KEY_INVENTORY
    keys = [material(new_pair()[1]) for _ in range(limit + 1)]

    for too_many_or_none in ([], keys):
        with pytest.raises(ClinicKeyInventoryError) as refused:
            validate_clinic_key_inventory(CLINIC, too_many_or_none)
        assert refused.value.code == "invalid_key_list"

    # Exactly the limit is a valid inventory, and so is one key.
    assert validate_clinic_key_inventory(CLINIC, keys[:limit]) == ()
    assert validate_clinic_key_inventory(CLINIC, keys[:1]) == ()


@pytest.mark.parametrize("status", ["", "pending", "ACTIVE", "retired"])
def test_a_key_that_is_neither_active_nor_revoked_is_refused(status: str) -> None:
    _, spki = new_pair()

    with pytest.raises(ClinicKeyInventoryError) as refused:
        validate_clinic_key_inventory(CLINIC, [material(spki, status=status)])

    assert refused.value.code == "invalid_key"


def test_a_valid_first_inventory_is_accepted_and_names_no_new_roots() -> None:
    _, first = new_pair()
    _, second = new_pair()

    assert validate_clinic_key_inventory(CLINIC, [material(first), material(second)]) == ()


# --- a chain of replacements has to lead back to a key that was already trusted ---------------


def test_a_signed_successor_of_a_previously_active_key_is_accepted() -> None:
    old_private, old_spki = new_pair()
    old = material(old_spki)
    successor = signed_successor(old_private, old)

    assert validate_clinic_key_inventory(CLINIC, [old, successor], previous=[old]) == ()


def test_a_replacement_chain_that_ends_at_a_key_nobody_trusted_is_refused() -> None:
    # The stored inventory knew `old` with a status that is not "active" (damaged or hand-edited
    # data: only active and revoked are ever written). A new key vouched for by it has nothing
    # trusted behind it, and a signature from a key we never trusted does not make it so. The
    # check fails closed: the new key is refused rather than stored on the strength of a proof.
    old_private, old_spki = new_pair()
    old_before = material(old_spki, status="retired")
    old_now = material(old_spki, status="active")
    successor = signed_successor(old_private, old_now)

    with pytest.raises(ClinicKeyInventoryError) as refused:
        validate_clinic_key_inventory(CLINIC, [old_now, successor], previous=[old_before])

    assert refused.value.code == "invalid_key"
