# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Refusals of the clinic key publisher that the route tests do not reach (coverage round 3).

The route checks a published list first and most of these refusals are defence in depth under it:
the service refuses on its own whatever calls it. FAKE keys only, derived from labels.

Pinned: base64url is read in its one canonical form only; a clinic key must be a P-256 public key in
its one DER encoding (a point written compressed is not that encoding); a list holds 1 to the
maximum keys, each with a status the portal knows, a replacement that names another key and carries
its signature; a key already published for another clinic is never adopted; and removing a device
of an account that does not exist is "not found".
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from carlos_patient_portal.models import PatientPortalClinicKey
from carlos_patient_portal.mycarlos_devices import (
    MAX_PUBLISHED_CLINIC_KEYS,
    ClinicKeyPublishError,
    ClinicKeySpec,
    b64url,
    check_clinic_spki,
    clinic_key_id,
    publish_clinic_keys,
    remove_device,
    strict_b64url_decode,
)
from tests.test_mycarlos_availability_store import migrated  # noqa: F401
from tests.test_mycarlos_internal_routes import clinic_spki

NOW = datetime(2026, 11, 25, 12, 0, tzinfo=UTC)
CLINIC = "clinic-a"


@pytest.fixture
def factory(migrated) -> sessionmaker:  # noqa: F811
    engine, _config = migrated
    return sessionmaker(engine, expire_on_commit=False)


def spec(label: str, status: str = "active", **changes: object) -> ClinicKeySpec:
    spki = clinic_spki(label)
    return ClinicKeySpec(kid=clinic_key_id(spki), spki=spki, status=status, **changes)  # type: ignore[arg-type]


def refused(factory: sessionmaker, specs: list[ClinicKeySpec], clinic: str = CLINIC) -> str:  # noqa: ANN001
    with factory() as session, session.begin():
        with pytest.raises(ClinicKeyPublishError) as raised:
            publish_clinic_keys(session, clinic_id=clinic, specs=specs, now=NOW)
    return raised.value.code


def stored_count(factory: sessionmaker) -> int:  # noqa: ANN001
    with factory() as session:
        return session.scalar(select(func.count()).select_from(PatientPortalClinicKey))


# --- base64url and the key's encoding ----------------------------------------------------------


def test_base64url_is_read_in_its_one_canonical_form_only() -> None:
    assert strict_b64url_decode("") == b""
    assert strict_b64url_decode(b64url(b"\x00\xff\xfe")) == b"\x00\xff\xfe"
    for bad in (
        "A",  # one character is never a whole number of bytes
        "AAAAA",  # 5 mod 4 is 1: the decoder itself refuses
        "AB",  # decodes, but "AA" is how those bytes are written
        "AAB",  # a last character with stray low bits
        "AA==",  # padding is not part of the form
        "AA\n",  # a character outside the alphabet is not skipped
        "A A",
        "AA/+",  # the standard alphabet is not the URL one
        "é",  # not ASCII
    ):
        with pytest.raises(ValueError, match="not canonical base64url"):
            strict_b64url_decode(bad)


def test_a_key_that_is_not_der_is_invalid_and_a_compressed_point_is_not_the_one_encoding() -> None:
    for garbage in (b"", b"\x00", b"not a key at all", clinic_spki("garbage")[:-1]):
        with pytest.raises(ClinicKeyPublishError) as raised:
            check_clinic_spki(garbage)
        assert raised.value.code == "invalid_key"
    # The same P-256 key with its point written compressed: it loads, but it is not the one DER
    # encoding the portal stores and hashes, so the same key could have two `kid`s.
    point = (
        ec.derive_private_key(777, ec.SECP256R1())
        .public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    )
    algorithm = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    bits = b"\x03" + bytes([len(point) + 1]) + b"\x00" + point
    compressed = b"\x30" + bytes([len(algorithm) + len(bits)]) + algorithm + bits
    with pytest.raises(ClinicKeyPublishError) as raised:
        check_clinic_spki(compressed)
    assert raised.value.code == "invalid_key"


def test_a_key_of_another_type_or_curve_is_not_a_clinic_key() -> None:
    ed25519 = (
        Ed25519PrivateKey.from_private_bytes(bytes(range(1, 33)))
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    p384 = (
        ec.derive_private_key(12345, ec.SECP384R1())
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    for other in (ed25519, p384):
        with pytest.raises(ClinicKeyPublishError) as raised:
            check_clinic_spki(other)
        assert raised.value.code == "invalid_key"
    # And the one kind it accepts passes.
    check_clinic_spki(clinic_spki("the-right-kind"))


# --- the list ----------------------------------------------------------------------------------


def test_an_empty_list_or_one_past_the_maximum_is_refused_and_the_maximum_is_not(factory) -> None:  # noqa: ANN001
    assert refused(factory, []) == "invalid_key_list"
    too_many = [spec(f"many-{n}") for n in range(MAX_PUBLISHED_CLINIC_KEYS + 1)]
    assert refused(factory, too_many) == "invalid_key_list"
    assert stored_count(factory) == 0
    with factory() as session, session.begin():
        result = publish_clinic_keys(
            session, clinic_id=CLINIC, specs=too_many[:MAX_PUBLISHED_CLINIC_KEYS], now=NOW
        )
    assert len(result.keys) == MAX_PUBLISHED_CLINIC_KEYS and result.changed


def test_a_list_that_names_a_key_twice_is_refused(factory) -> None:  # noqa: ANN001
    one = spec("twice")
    assert refused(factory, [one, one]) == "invalid_key_list"
    assert stored_count(factory) == 0


def test_a_status_the_portal_does_not_know_is_refused(factory) -> None:  # noqa: ANN001
    for status in ("pending", "ACTIVE", "", "retired"):
        assert refused(factory, [spec("odd-status", status)]) == "invalid_key", status
    assert stored_count(factory) == 0


def test_a_replacement_names_another_key_and_carries_its_signature(factory) -> None:  # noqa: ANN001
    old = spec("replaced")
    own = spec("replaces-itself")
    signature = b"\x01" * 64
    # A key that says it replaces itself.
    assert (
        refused(
            factory,
            [
                ClinicKeySpec(
                    own.kid,
                    own.spki,
                    "active",
                    replaces_kid=own.kid,
                    replacement_signature=signature,
                )
            ],
        )
        == "invalid_key"
    )
    # A signature with no key it replaces, and a key it replaces with no signature.
    new = spec("replacement")
    assert (
        refused(
            factory,
            [old, ClinicKeySpec(new.kid, new.spki, "active", replacement_signature=signature)],
        )
        == "invalid_key"
    )
    assert (
        refused(factory, [old, ClinicKeySpec(new.kid, new.spki, "active", replaces_kid=old.kid)])
        == "invalid_key"
    )
    assert stored_count(factory) == 0


def test_a_key_must_be_named_by_its_own_hash(factory) -> None:  # noqa: ANN001
    one, other = spec("named-one"), spec("named-other")
    assert refused(factory, [ClinicKeySpec(other.kid, one.spki, "active")]) == "invalid_key"
    assert stored_count(factory) == 0


# --- a key that belongs to another clinic -------------------------------------------------------


def test_a_key_already_published_for_another_clinic_is_never_adopted(factory) -> None:  # noqa: ANN001
    shared = spec("belongs-to-b")
    with factory() as session, session.begin():
        publish_clinic_keys(session, clinic_id="clinic-b", specs=[shared], now=NOW)
    assert refused(factory, [shared], clinic=CLINIC) == "invalid_key"
    # Still clinic-b's alone, and clinic-a holds nothing.
    with factory() as session:
        rows = list(session.scalars(select(PatientPortalClinicKey)))
    assert [(row.kid, row.clinic_id) for row in rows] == [(shared.kid, "clinic-b")]
    # Its own clinic can still publish it again: that is the no-op.
    with factory() as session, session.begin():
        again = publish_clinic_keys(session, clinic_id="clinic-b", specs=[shared], now=NOW)
    assert not again.changed


# --- removing a device --------------------------------------------------------------------------


def test_removing_a_device_of_an_account_that_does_not_exist_is_not_found(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        assert (
            remove_device(
                session, account_id=987654, device_key_id="a" * 43, removed_by="device_removed"
            )
            is None
        )
