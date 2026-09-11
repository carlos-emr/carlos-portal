# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This software is published under the GPL GNU General Public License.

from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import UTC, datetime

import pytest

from carlos_patient_portal.staff_identity import (
    CarlosServiceAuthenticationError,
    StaffPrincipal,
    consume_staff_assertion,
    normalize_permissions,
    verify_staff_assertion,
)
from tests.support import (
    TEST_STAFF_ASSERTION_KEY_ID,
    TEST_STAFF_ASSERTION_PRIVATE_KEY,
    TEST_STAFF_ASSERTION_PUBLIC_KEY,
    sign_staff_assertion,
)


def encoded(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@pytest.mark.parametrize(
    "assertion",
    [
        "",
        "missing-separator",
        f"A.{encoded(bytes(64))}",
        f"AA=.{encoded(bytes(64))}",
        f"{encoded(b'{}')}.AA",
        f"{encoded(b'not-json')}.{encoded(bytes(64))}",
        f"{encoded(b'[]')}.{encoded(bytes(64))}",
    ],
)
def test_staff_assertion_rejects_malformed_envelopes(assertion: str) -> None:
    with pytest.raises(CarlosServiceAuthenticationError):
        verify_staff_assertion(
            {TEST_STAFF_ASSERTION_KEY_ID: TEST_STAFF_ASSERTION_PUBLIC_KEY},
            assertion,
        )


def test_staff_assertion_rejects_an_oversized_envelope() -> None:
    with pytest.raises(CarlosServiceAuthenticationError):
        verify_staff_assertion(
            {TEST_STAFF_ASSERTION_KEY_ID: TEST_STAFF_ASSERTION_PUBLIC_KEY},
            "x" * 4097,
        )


def test_staff_assertion_rejects_an_unknown_rotation_key() -> None:
    request_hash = "a" * 64
    assertion = sign_staff_assertion(
        "portal.contact.review",
        key_id="retired-key",
        request_hash=request_hash,
    )

    with pytest.raises(CarlosServiceAuthenticationError):
        verify_staff_assertion(
            {TEST_STAFF_ASSERTION_KEY_ID: TEST_STAFF_ASSERTION_PUBLIC_KEY},
            assertion,
            expected_request_hash=request_hash,
        )


def test_staff_assertion_rejects_duplicate_json_claims() -> None:
    request_hash = "a" * 64
    signed = sign_staff_assertion(
        "portal.contact.review",
        key_id=TEST_STAFF_ASSERTION_KEY_ID,
        request_hash=request_hash,
    )
    payload_segment = signed.partition(".")[0]
    payload = urlsafe_b64decode(payload_segment + "=" * (-len(payload_segment) % 4))
    duplicate_payload = payload.replace(b'{"aud":', b'{"aud":"wrong","aud":', 1)
    duplicate_assertion = (
        f"{encoded(duplicate_payload)}."
        f"{encoded(TEST_STAFF_ASSERTION_PRIVATE_KEY.sign(duplicate_payload))}"
    )

    with pytest.raises(CarlosServiceAuthenticationError):
        verify_staff_assertion(
            {TEST_STAFF_ASSERTION_KEY_ID: TEST_STAFF_ASSERTION_PUBLIC_KEY},
            duplicate_assertion,
            expected_request_hash=request_hash,
        )


@pytest.mark.parametrize(
    "claim_overrides",
    [
        {"jti": "not-a-uuid"},
        {"provider_id": None},
        {"permissions": "portal.contact.review"},
    ],
)
def test_staff_assertion_rejects_invalid_identity_claim_types(
    claim_overrides: dict[str, object],
) -> None:
    request_hash = "b" * 64
    assertion = sign_staff_assertion(
        "portal.contact.review",
        key_id=TEST_STAFF_ASSERTION_KEY_ID,
        request_hash=request_hash,
        claim_overrides=claim_overrides,
    )

    with pytest.raises(CarlosServiceAuthenticationError):
        verify_staff_assertion(
            {TEST_STAFF_ASSERTION_KEY_ID: TEST_STAFF_ASSERTION_PUBLIC_KEY},
            assertion,
            expected_request_hash=request_hash,
        )


def test_staff_assertion_rejects_a_non_ascii_request_hash() -> None:
    assertion = sign_staff_assertion(
        "portal.contact.review",
        key_id=TEST_STAFF_ASSERTION_KEY_ID,
        request_hash="é" * 64,
    )

    with pytest.raises(CarlosServiceAuthenticationError):
        verify_staff_assertion(
            {TEST_STAFF_ASSERTION_KEY_ID: TEST_STAFF_ASSERTION_PUBLIC_KEY},
            assertion,
            expected_request_hash="a" * 64,
        )


def test_staff_assertion_requires_at_least_one_permission() -> None:
    with pytest.raises(CarlosServiceAuthenticationError):
        normalize_permissions(())


def test_expired_bound_assertion_cannot_be_consumed() -> None:
    principal = StaffPrincipal(
        provider_id="provider-42",
        display_name="CarlosDoc",
        clinic_id="test-clinic",
        permissions=frozenset({"portal.contact.review"}),
        assertion_id="00000000-0000-0000-0000-000000000001",
        assertion_expires_at=int(datetime(2020, 1, 1, tzinfo=UTC).timestamp()),
        request_bound=True,
    )

    with pytest.raises(CarlosServiceAuthenticationError):
        consume_staff_assertion(None, principal)  # type: ignore[arg-type]
