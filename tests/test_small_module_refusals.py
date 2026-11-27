"""Refusal and error branches of eight small modules that the rest of the suite never reached.

Test-only, FAKE and synthetic values only. Each test names one line of behaviour a caller relies
on: an address or key that is refused must stay refused, and a database that is down must say so.
"""

from datetime import UTC, date, datetime
from hashlib import sha256
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from fastapi.testclient import TestClient
from sqlalchemy.exc import SQLAlchemyError

from carlos_patient_portal import main, mycarlos_qr
from carlos_patient_portal.audit import summarize_recent_activation_failures
from carlos_patient_portal.clinic_key_proofs import (
    ClinicKeyInventoryError,
    ClinicKeyMaterial,
    b64url,
    checked_public_key,
    validate_clinic_key_inventory,
)
from carlos_patient_portal.identity import (
    IdentityProof,
    build_identity_hashes,
    normalize_date_of_birth,
    verify_identity_proof,
)
from carlos_patient_portal.mycarlos_links import IssuedLinkCode
from carlos_patient_portal.public_device_path import canonical_public_device_url
from carlos_patient_portal.routes import public as public_routes
from carlos_patient_portal.sms_delivery import PortalSmsSender, WebhookPortalSmsSender
from tests.support import INTERNAL_HEALTH_TOKEN, development_settings

# ---- the link QR payload -------------------------------------------------------------------


def issued() -> IssuedLinkCode:
    return IssuedLinkCode("FAKE0001", "FAKE7Q2M4K", datetime(2026, 1, 1, tzinfo=UTC))


def test_a_portal_address_that_cannot_be_encoded_is_refused_not_crashed() -> None:
    # A lone surrogate is a str Python holds but UTF-8 cannot write.
    with pytest.raises(ValueError, match="invalid portal address"):
        mycarlos_qr.link_qr_payload(issued(), "https://portal.example.test/\ud800")


def test_the_qr_payload_size_guard_refuses_rather_than_truncates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A guard test. The limit is fixed at 4096 bytes and the address at 1024, so the payload cannot
    # reach it today; the check is the guard against that changing, and it must refuse, not
    # truncate (a cut JSON payload would be a QR code that links nothing).
    assert len(mycarlos_qr.link_qr_payload(issued(), "https://portal.example.test")) < 200
    monkeypatch.setattr(mycarlos_qr, "MAX_LINK_QR_BYTES", 40)
    with pytest.raises(ValueError, match="link payload too large"):
        mycarlos_qr.link_qr_payload(issued(), "https://portal.example.test")


# ---- the activation failure summary ----------------------------------------------------------


def test_an_activation_failure_summary_needs_a_hash_to_count_by() -> None:
    session = MagicMock()
    since = datetime(2026, 1, 1, tzinfo=UTC)
    with pytest.raises(ValueError, match="is required"):
        summarize_recent_activation_failures(session, since=since)
    with pytest.raises(ValueError, match="invite_token_hash must be a hash value"):
        summarize_recent_activation_failures(session, since=since, invite_token_hash="short")
    with pytest.raises(ValueError, match="client_reference_hash must be a hash value"):
        summarize_recent_activation_failures(session, since=since, client_reference_hash="short")
    # Nothing was asked of the database for any of them.
    session.execute.assert_not_called()


# ---- the public device address ---------------------------------------------------------------


@pytest.mark.parametrize(
    "address",
    [
        "https://" + "a" * 1100 + ".example",
        " https://portal.example.test",
        "https://portal.example.test ",
        "https:\\\\portal.example.test",
    ],
    ids=["too long", "leading space", "trailing space", "backslash"],
)
def test_a_public_device_address_with_a_forbidden_shape_is_refused(address: str) -> None:
    with pytest.raises(ValueError, match="invalid public device address"):
        canonical_public_device_url(address)


# ---- the identity proof ----------------------------------------------------------------------


def test_a_date_time_of_birth_is_normalised_to_its_date() -> None:
    # The time of day is dropped; the value is the ISO date, the same as for a plain date.
    assert normalize_date_of_birth(datetime(1980, 5, 20, 13, 45)) == "1980-05-20"
    assert normalize_date_of_birth(date(1980, 5, 20)) == "1980-05-20"


def test_identity_hashes_are_refused_for_a_blank_salt() -> None:
    proof = IdentityProof("fake.patient@example.test", date(1980, 5, 20), "ABCD 1234-5678")
    with pytest.raises(ValueError, match="salt must not be blank"):
        build_identity_hashes(proof, "FAKE-secret", "   ")


def test_a_proof_that_cannot_be_hashed_does_not_verify() -> None:
    # Complete hash values and a real salt, but an email that normalisation refuses: no match,
    # and no exception for the caller to mistake for "the proof was fine".
    hashes = {name: "a" * 64 for name in ("email_hash", "date_of_birth_hash", "health_card_hash")}
    proof = IdentityProof("not an email", date(1980, 5, 20), "ABCD 1234-5678")
    assert verify_identity_proof(proof, "FAKE-secret", salt="FAKE-salt", **hashes) is False


# ---- SMS delivery ----------------------------------------------------------------------------


def test_the_sms_sender_protocol_has_no_default_delivery() -> None:
    with pytest.raises(NotImplementedError):
        PortalSmsSender.send_code(  # type: ignore[arg-type]
            object(), recipient="+15555550123", code="123456", expires_in_seconds=60
        )


def test_the_webhook_sms_sender_needs_its_address_and_token() -> None:
    with pytest.raises(ValueError, match="SMS webhook URL and token are required"):
        WebhookPortalSmsSender(development_settings())


# ---- the clinic key inventory ----------------------------------------------------------------


def key_material(private_key, *, status: str = "active", kid: str | None = None):
    spki = private_key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return ClinicKeyMaterial(kid or b64url(sha256(spki).digest()), spki, status)


def test_a_key_that_is_not_a_public_key_is_refused() -> None:
    with pytest.raises(ClinicKeyInventoryError) as refused:
        checked_public_key(ClinicKeyMaterial("FAKE-kid", b"not a DER public key", "active"))
    assert refused.value.code == "invalid_key"


def test_only_a_p256_key_is_accepted() -> None:
    good = key_material(ec.generate_private_key(ec.SECP256R1()))
    assert checked_public_key(good) is not None
    for other in (ec.generate_private_key(ec.SECP384R1()), ed25519.Ed25519PrivateKey.generate()):
        with pytest.raises(ClinicKeyInventoryError) as refused:
            checked_public_key(key_material(other))
        assert refused.value.code == "invalid_key"


def test_a_key_id_that_is_not_the_hash_of_its_key_is_refused() -> None:
    material = key_material(ec.generate_private_key(ec.SECP256R1()), kid="FAKE-not-the-hash")
    with pytest.raises(ClinicKeyInventoryError) as refused:
        checked_public_key(material)
    assert refused.value.code == "invalid_key"


def test_an_inventory_must_list_between_one_and_the_most_keys_each_once() -> None:
    first = key_material(ec.generate_private_key(ec.SECP256R1()))
    for incoming in ([], [first, first]):
        with pytest.raises(ClinicKeyInventoryError) as refused:
            validate_clinic_key_inventory("FAKE-clinic", incoming)
        assert refused.value.code == "invalid_key_list"
    # A first inventory is an explicit bootstrap: one valid key, and no new unsigned root to report.
    assert validate_clinic_key_inventory("FAKE-clinic", [first]) == ()


def test_a_key_with_a_status_other_than_active_or_revoked_is_refused() -> None:
    pending = key_material(ec.generate_private_key(ec.SECP256R1()), status="pending")
    with pytest.raises(ClinicKeyInventoryError) as refused:
        validate_clinic_key_inventory("FAKE-clinic", [pending])
    assert refused.value.code == "invalid_key"


# ---- the health probes -----------------------------------------------------------------------


def test_a_database_that_is_down_is_reported_as_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def down(session) -> None:
        raise SQLAlchemyError("FAKE database down")

    monkeypatch.setattr(public_routes, "check_database", down)
    client = TestClient(
        main.create_app(
            development_settings(
                database_url="sqlite+pysqlite:///:memory:",
                internal_health_token=INTERNAL_HEALTH_TOKEN,
            )
        )
    )
    headers = {"Authorization": f"Bearer {INTERNAL_HEALTH_TOKEN}"}

    health = client.get("/internal/health/db", headers=headers)
    assert health.status_code == 503
    assert health.json() == {"detail": "database unavailable"}
    assert "FAKE database down" not in health.text

    readiness = client.get("/internal/readiness", headers=headers)
    assert readiness.status_code == 503
    body = readiness.json()
    assert body["status"] == "unavailable"
    assert body["database"] == "unavailable"
    # With the database down the schema cannot be read, and maintenance mode is still reported.
    assert body["schema"] == "unknown"
    assert body["maintenance"] is False
    assert "FAKE database down" not in readiness.text
