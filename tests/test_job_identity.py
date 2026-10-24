# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

"""CARLOS jobs as internal callers: the signed job assertion, its refusals, and their audit rows."""

import json
from base64 import urlsafe_b64decode, urlsafe_b64encode
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Annotated
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.config import Config
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, select, text

from carlos_patient_portal import internal_routes
from carlos_patient_portal.job_identity import (
    JOB_ASSERTION_FIELDS,
    JOB_REFUSAL_CODES,
    CarlosJobRefusal,
    JobPrincipal,
    consume_job_assertion,
    verify_job_assertion,
)
from carlos_patient_portal.models import (
    AUDIT_EVENT_JOB_AUTH_REFUSED,
    AUDIT_EVENT_STAFF_ACTION,
    PatientPortalAuditEvent,
    PatientPortalStaffAssertionUse,
    utc_now,
)
from carlos_patient_portal.staff_identity import (
    CarlosServiceAuthenticationError,
    StaffPrincipal,
    consume_staff_assertion,
    staff_request_hash,
    verify_staff_assertion,
)
from carlos_patient_portal.system_jobs import (
    JOB_NAME_PATTERN,
    JOB_ONLY_PERMISSIONS,
    SYSTEM_JOBS,
)
from tests.support import (
    TEST_JOB_ASSERTION_KEY_IDS,
    TEST_JOB_ASSERTION_NEXT_PRIVATE_KEY,
    TEST_JOB_ASSERTION_NEXT_PUBLIC_KEY,
    TEST_JOB_ASSERTION_PRIVATE_KEYS,
    TEST_JOB_ASSERTION_PUBLIC_KEYS,
    TEST_STAFF_ASSERTION_KEY_ID,
    TEST_STAFF_ASSERTION_PRIVATE_KEY,
    TEST_STAFF_ASSERTION_PUBLIC_KEY,
    carlos_job_headers,
    carlos_staff_headers,
    encode_assertion,
    sign_job_assertion,
    sign_staff_assertion,
)
from tests.test_internal_api import INTERNAL_API_TOKEN, internal_app

SYNC = "portal.booking_prompt.sync"
SIGNUP = "portal.signup.manage"
INVITE = "portal.invite.manage"
CLINIC = "clinic-a"
CHOICES_PATH = "/internal/carlos/booking-prompts/choices"
CHOICES_URI = f"{CHOICES_PATH}?state=pending"
NOW = 1_792_454_400
REQUEST_HASH = staff_request_hash("GET", CHOICES_PATH.encode(), b"state=pending", b"")
JOB_KEYS = {
    job: {TEST_JOB_ASSERTION_KEY_IDS[job]: public_key}
    for job, public_key in TEST_JOB_ASSERTION_PUBLIC_KEYS.items()
}
BOOKING_KID = TEST_JOB_ASSERTION_KEY_IDS["booking-sync"]
SIGNUP_KID = TEST_JOB_ASSERTION_KEY_IDS["signup-poll"]


def encoded(value: bytes) -> str:
    return urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def signed(
    job: str = "booking-sync",
    permission: object = SYNC,
    **options: object,
) -> str:
    """A job assertion for the choices poll at NOW, unless an option says otherwise."""
    values: dict[str, object] = {
        "request_hash": REQUEST_HASH,
        "clinic_id": CLINIC,
        "issued_at": NOW,
        **options,
    }
    return sign_job_assertion(job, permission, **values)


def verify(
    assertion: str,
    *,
    now: int = NOW,
    request_hash: str = REQUEST_HASH,
    staff_assertion_present: bool = False,
) -> JobPrincipal:
    return verify_job_assertion(
        JOB_KEYS,
        assertion,
        expected_request_hash=request_hash,
        expected_clinic_id=CLINIC,
        staff_assertion_present=staff_assertion_present,
        now=now,
    )


def refusal_of(assertion: str, **options: object) -> CarlosJobRefusal:
    with pytest.raises(CarlosJobRefusal) as caught:
        verify(assertion, **options)
    return caught.value


def payload_of(assertion: str) -> dict[str, object]:
    encoded_payload = assertion.split(".", 1)[0]
    return json.loads(urlsafe_b64decode(encoded_payload + "=" * (-len(encoded_payload) % 4)))


# --------------------------------------------------------------------------------------
# The registry
# --------------------------------------------------------------------------------------


def test_registered_jobs_have_well_formed_names_display_names_and_permissions() -> None:
    assert set(SYSTEM_JOBS) == {"booking-sync", "delivery-sync", "key-publish", "signup-poll"}
    for name, job in SYSTEM_JOBS.items():
        assert job.name == name
        assert JOB_NAME_PATTERN.fullmatch(name)
        assert job.actor_id == f"job:{name}"
        assert job.permissions
    assert SYSTEM_JOBS["booking-sync"].display_name == "Clinic booking"
    assert SYSTEM_JOBS["booking-sync"].permissions == {SYNC}
    assert SYSTEM_JOBS["signup-poll"].display_name == "Patient self sign-up"
    assert SYSTEM_JOBS["signup-poll"].permissions == {SIGNUP, INVITE}
    assert SYSTEM_JOBS["key-publish"].display_name == "Clinic signing keys"
    assert SYSTEM_JOBS["key-publish"].permissions == {"portal.mycarlos.clinic_keys.publish"}
    assert SYSTEM_JOBS["delivery-sync"].display_name == "Clinic document delivery"
    assert SYSTEM_JOBS["delivery-sync"].permissions == {
        "portal.mycarlos.delivery.upload",
        "portal.mycarlos.delivery.events.read",
        "portal.mycarlos.delivery.events.ack",
    }
    assert JOB_ONLY_PERMISSIONS == {
        SYNC,
        "portal.mycarlos.clinic_keys.publish",
        "portal.mycarlos.delivery.upload",
        "portal.mycarlos.delivery.events.read",
        "portal.mycarlos.delivery.events.ack",
    }


def test_no_route_is_open_to_the_signup_job_yet() -> None:
    app = internal_app()
    jobs = {
        getattr(dependency.call, internal_routes.CALLER_POLICY_ATTRIBUTE).job
        for route in app.routes
        if getattr(route, "path", "").startswith("/internal/carlos/")
        for dependency in route.dependant.dependencies
        if hasattr(dependency.call, internal_routes.CALLER_POLICY_ATTRIBUTE)
    }

    assert jobs == {None, "booking-sync"}


def test_a_refusal_code_must_be_one_the_audit_log_knows() -> None:
    with pytest.raises(ValueError, match="unknown job refusal code"):
        CarlosJobRefusal("made_up", key_owner="booking-sync", key_id=BOOKING_KID, assertion_id=None)
    forbidden = {
        code
        for code in JOB_REFUSAL_CODES
        if CarlosJobRefusal(
            code, key_owner="booking-sync", key_id=BOOKING_KID, assertion_id=None
        ).status_code
        == 403
    }
    assert forbidden == {"permission_not_held", "wrong_permission"}


# --------------------------------------------------------------------------------------
# The verifier
# --------------------------------------------------------------------------------------


def test_a_valid_job_assertion_is_accepted() -> None:
    assertion = signed()

    principal = verify(assertion)

    assert principal == JobPrincipal(
        job="booking-sync",
        display_name="Clinic booking",
        clinic_id=CLINIC,
        permission=SYNC,
        key_id=BOOKING_KID,
        assertion_id=payload_of(assertion)["jti"],
        assertion_expires_at=NOW + 60,
    )
    assert principal.actor_id == "job:booking-sync"


def test_the_signed_payload_carries_exactly_the_job_claims() -> None:
    assert (
        set(payload_of(signed()))
        == JOB_ASSERTION_FIELDS
        == {
            "aud",
            "clinic_id",
            "exp",
            "iat",
            "iss",
            "jti",
            "job",
            "kid",
            "permission",
            "request_hash",
        }
    )


@pytest.mark.parametrize("claim", sorted(JOB_ASSERTION_FIELDS - {"kid"}))
def test_each_missing_claim_is_refused(claim: str) -> None:
    refusal = refusal_of(signed(removed_claims=(claim,)))

    assert (refusal.code, refusal.key_owner, refusal.key_id) == (
        "invalid_claims",
        "booking-sync",
        BOOKING_KID,
    )


def test_a_missing_key_id_cannot_be_verified_at_all() -> None:
    with pytest.raises(CarlosServiceAuthenticationError):
        verify(signed(removed_claims=("kid",)))


@pytest.mark.parametrize(
    "extra",
    [
        {"unexpected": "claim"},
        {"provider_id": "provider-42"},
        {"provider_name": "CarlosDoc"},
        {"permissions": [SYNC]},
    ],
)
def test_an_extra_claim_is_refused(extra: dict[str, object]) -> None:
    assert refusal_of(signed(claim_overrides=extra)).code == "invalid_claims"


def test_a_duplicated_claim_is_refused_before_the_signature_is_checked() -> None:
    payload = json.dumps(payload_of(signed()), separators=(",", ":"), sort_keys=True)
    duplicated = payload[:-1] + ',"permission":"portal.invite.manage"}'

    with pytest.raises(CarlosServiceAuthenticationError):
        verify(
            encode_assertion(duplicated.encode(), TEST_JOB_ASSERTION_PRIVATE_KEYS["booking-sync"])
        )


@pytest.mark.parametrize(
    ("claim", "value"),
    [
        ("aud", ["carlos-patient-portal-job-api"]),
        ("clinic_id", 7),
        ("clinic_id", None),
        ("exp", str(NOW + 60)),
        ("exp", True),
        ("iat", float(NOW)),
        ("iat", None),
        ("iss", None),
        ("jti", 12),
        ("jti", "not-a-uuid"),
        # A UUID, but not in canonical form.
        ("jti", str(uuid4()).upper()),
        ("job", ["booking-sync"]),
        ("job", None),
        ("permission", [SYNC]),
        ("permission", {"name": SYNC}),
        ("permission", ""),
        ("permission", f" {SYNC}"),
        ("permission", SYNC.upper()),
        ("permission", "p" * 65),
        ("request_hash", 0),
        ("request_hash", REQUEST_HASH.upper()),
        ("request_hash", REQUEST_HASH[:-1]),
    ],
)
def test_each_claim_of_the_wrong_type_or_shape_is_refused(claim: str, value: object) -> None:
    assert refusal_of(signed(claim_overrides={claim: value})).code == "invalid_claims"


def test_a_non_text_key_id_cannot_be_verified_at_all() -> None:
    with pytest.raises(CarlosServiceAuthenticationError):
        verify(signed(claim_overrides={"kid": 7}))


@pytest.mark.parametrize(
    "options",
    [
        {"audience": "carlos-patient-portal-internal-api"},
        {"audience": "another-service"},
        {"issuer": "someone-else"},
    ],
)
def test_the_staff_audience_or_another_issuer_is_refused(options: dict[str, object]) -> None:
    assert refusal_of(signed(**options)).code == "invalid_claims"


def test_a_staff_assertion_in_the_job_header_is_refused_unattributed() -> None:
    staff_assertion = sign_staff_assertion(
        SYNC,
        clinic_id=CLINIC,
        key_id=TEST_STAFF_ASSERTION_KEY_ID,
        request_hash=REQUEST_HASH,
    )

    # Its key id is not a job key, so nothing about it verifies.
    with pytest.raises(CarlosServiceAuthenticationError):
        verify(staff_assertion)


def test_a_staff_shaped_payload_signed_with_a_job_key_is_refused_and_attributed() -> None:
    staff_shaped = sign_staff_assertion(
        SYNC,
        clinic_id=CLINIC,
        key_id=BOOKING_KID,
        request_hash=REQUEST_HASH,
        signing_key=TEST_JOB_ASSERTION_PRIVATE_KEYS["booking-sync"],
    )

    refusal = refusal_of(staff_shaped)

    assert (refusal.code, refusal.key_owner) == ("invalid_claims", "booking-sync")


@pytest.mark.parametrize("allow_legacy_unbound", [False, True])
def test_a_job_assertion_in_the_staff_header_is_refused(allow_legacy_unbound: bool) -> None:
    # Even signed with the staff key under the staff key id, a job payload is not a staff one.
    job_payload_with_staff_key = signed(
        key_id=TEST_STAFF_ASSERTION_KEY_ID,
        signing_key=TEST_STAFF_ASSERTION_PRIVATE_KEY,
    )
    for assertion in (signed(), job_payload_with_staff_key):
        with pytest.raises(CarlosServiceAuthenticationError):
            verify_staff_assertion(
                {TEST_STAFF_ASSERTION_KEY_ID: TEST_STAFF_ASSERTION_PUBLIC_KEY},
                assertion,
                expected_request_hash=REQUEST_HASH,
                allow_legacy_unbound=allow_legacy_unbound,
            )


def test_an_unknown_job_is_refused() -> None:
    refusal = refusal_of(signed("nightly-export"))

    assert (refusal.code, refusal.key_owner) == ("unknown_job", "booking-sync")


def test_another_jobs_key_is_refused_and_the_key_owner_is_named() -> None:
    assertion = signed(
        key_id=SIGNUP_KID,
        signing_key=TEST_JOB_ASSERTION_PRIVATE_KEYS["signup-poll"],
    )

    refusal = refusal_of(assertion)

    assert (refusal.code, refusal.key_owner, refusal.key_id) == (
        "wrong_key",
        "signup-poll",
        SIGNUP_KID,
    )


def test_a_staff_key_id_or_a_signature_by_the_wrong_key_does_not_verify() -> None:
    staff_kid = signed(
        key_id=TEST_STAFF_ASSERTION_KEY_ID,
        signing_key=TEST_STAFF_ASSERTION_PRIVATE_KEY,
    )
    wrong_signer = signed(signing_key=TEST_JOB_ASSERTION_PRIVATE_KEYS["signup-poll"])
    payload, signature = signed().split(".")
    tampered = f"{payload}.{('A' if signature[0] != 'A' else 'B') + signature[1:]}"

    for assertion in (staff_kid, wrong_signer, tampered):
        with pytest.raises(CarlosServiceAuthenticationError):
            verify(assertion)


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
        "a.b.c",
        "x" * 4097,
    ],
)
def test_a_malformed_or_oversized_envelope_is_refused_unattributed(assertion: str) -> None:
    with pytest.raises(CarlosServiceAuthenticationError):
        verify(assertion)


def test_expiry_and_issue_time_are_bounded() -> None:
    assert verify(signed(issued_at=NOW + 30)).assertion_expires_at == NOW + 90
    assert refusal_of(signed(issued_at=NOW + 31)).code == "invalid_claims"
    assert refusal_of(signed(issued_at=NOW - 60, expires_at=NOW)).code == "expired"
    assert refusal_of(signed(expires_at=NOW + 121)).code == "invalid_claims"
    assert refusal_of(signed(expires_at=NOW)).code == "invalid_claims"
    assert verify(signed(expires_at=NOW + 120)).assertion_expires_at == NOW + 120


def test_a_request_hash_mismatch_or_another_clinic_is_refused() -> None:
    other_request = staff_request_hash("GET", CHOICES_PATH.encode(), b"state=pending&limit=1", b"")

    assert refusal_of(signed(request_hash=other_request)).code == "request_mismatch"
    assert refusal_of(signed(clinic_id="clinic-b")).code == "clinic_mismatch"


def test_both_headers_are_refused_once_the_job_signature_verifies() -> None:
    assert refusal_of(signed(), staff_assertion_present=True).code == "both_headers"
    with pytest.raises(CarlosServiceAuthenticationError):
        verify(
            signed(signing_key=TEST_JOB_ASSERTION_PRIVATE_KEYS["signup-poll"]),
            staff_assertion_present=True,
        )


def test_a_refusal_keeps_the_assertion_id_only_when_it_is_a_canonical_uuid() -> None:
    assertion = signed(clinic_id="clinic-b")

    assert refusal_of(assertion).assertion_id == payload_of(assertion)["jti"]
    assert refusal_of(signed(claim_overrides={"jti": "not-a-uuid"})).assertion_id is None
    assert refusal_of(signed(claim_overrides={"jti": str(uuid4()).upper()})).assertion_id is None


def test_a_job_assertion_is_consumed_once_in_the_staff_nonce_table() -> None:
    app = internal_app()
    principal = verify(signed(issued_at=None), now=int(utc_now().timestamp()))

    consume_job_assertion(app.state.session_factory, principal)
    with pytest.raises(CarlosJobRefusal) as replay:
        consume_job_assertion(app.state.session_factory, principal)
    # One nonce namespace for both caller types.
    with pytest.raises(CarlosServiceAuthenticationError):
        consume_staff_assertion(
            app.state.session_factory,
            StaffPrincipal(
                provider_id="provider-42",
                display_name="CarlosDoc",
                clinic_id=CLINIC,
                permissions=frozenset({"portal.contact.review"}),
                assertion_id=principal.assertion_id,
                assertion_expires_at=principal.assertion_expires_at,
                request_bound=True,
            ),
        )

    assert (replay.value.code, replay.value.assertion_id) == ("replay", principal.assertion_id)
    with app.state.session_factory() as session:
        assert list(session.scalars(select(PatientPortalStaffAssertionUse.assertion_id))) == [
            principal.assertion_id
        ]


def test_a_job_assertion_that_expires_before_it_is_consumed_is_refused() -> None:
    app = internal_app()
    expired = JobPrincipal(
        job="booking-sync",
        display_name="Clinic booking",
        clinic_id=CLINIC,
        permission=SYNC,
        key_id=BOOKING_KID,
        assertion_id=str(uuid4()),
        assertion_expires_at=int((utc_now() - timedelta(seconds=1)).timestamp()),
    )

    with pytest.raises(CarlosJobRefusal) as caught:
        consume_job_assertion(app.state.session_factory, expired)

    assert caught.value.code == "expired"


# --------------------------------------------------------------------------------------
# Through the app: status codes and audit rows
# --------------------------------------------------------------------------------------


def job_headers(
    job: str = "booking-sync",
    permission: object = SYNC,
    *,
    method: str = "GET",
    path: str = CHOICES_URI,
    body: bytes = b"",
    **options: object,
) -> dict[str, str]:
    return carlos_job_headers(
        job, permission, method=method, path=path, body=body, clinic_id=CLINIC, **options
    )


def audit_rows(app) -> list[PatientPortalAuditEvent]:
    with app.state.session_factory() as session:
        return list(
            session.scalars(select(PatientPortalAuditEvent).order_by(PatientPortalAuditEvent.id))
        )


def refusal_rows(app) -> list[tuple[object, ...]]:
    return [
        (row.reason, row.actor, row.actor_id, row.resource_id, row.assertion_key_id)
        for row in audit_rows(app)
        if row.event_type == AUDIT_EVENT_JOB_AUTH_REFUSED
    ]


GENERIC_FAILURE = (
    AUDIT_EVENT_STAFF_ACTION,
    "failure",
    "staff",
    "carlos-service",
    None,
    None,
    "internal_api",
    None,
    "authentication_failed",
    None,
    None,
)


def generic_shape(row: PatientPortalAuditEvent) -> tuple[object, ...]:
    assert row.client_reference_hash is not None and len(row.client_reference_hash) == 64
    return (
        row.event_type,
        row.outcome,
        row.actor_type,
        row.actor,
        row.actor_id,
        row.clinic_id,
        row.resource_type,
        row.resource_id,
        row.reason,
        row.assertion_key_id,
        row.assertion_id,
    )


def test_the_booking_sync_job_can_poll_and_an_empty_poll_writes_nothing() -> None:
    app = internal_app()
    client = TestClient(app)
    with_limit = f"{CHOICES_URI}&limit=50"

    response = client.get(CHOICES_URI, headers=job_headers())
    limited = client.get(with_limit, headers=job_headers(path=with_limit))

    assert response.status_code == 200
    assert response.json() == {"items": [], "has_more": False}
    assert limited.status_code == 200
    assert audit_rows(app) == []


def test_a_job_replay_is_refused_and_recorded() -> None:
    app = internal_app()
    client = TestClient(app)
    headers = job_headers()

    first = client.get(CHOICES_URI, headers=headers)
    replay = client.get(CHOICES_URI, headers=headers)

    assert (first.status_code, replay.status_code) == (200, 404)
    assert replay.json() == {"detail": "not found"}
    (row,) = audit_rows(app)
    assert (row.event_type, row.reason, row.assertion_id) == (
        AUDIT_EVENT_JOB_AUTH_REFUSED,
        "replay",
        payload_of(headers["X-CARLOS-Job-Assertion"])["jti"],
    )


def test_a_job_call_needs_the_service_token() -> None:
    app = internal_app()
    client = TestClient(app)
    missing = {name: value for name, value in job_headers().items() if name != "Authorization"}

    responses = [
        client.get(CHOICES_URI, headers=missing),
        client.get(CHOICES_URI, headers=job_headers(token="x" * 32)),
        client.get(
            CHOICES_URI,
            headers={**job_headers(), "Authorization": f"Basic {INTERNAL_API_TOKEN}"},
        ),
    ]

    assert [response.status_code for response in responses] == [404, 404, 404]
    # Nothing about the assertion was looked at, so nothing is attributed.
    assert [generic_shape(row) for row in audit_rows(app)] == [GENERIC_FAILURE] * 3


def test_an_unsigned_or_invalid_job_header_keeps_one_generic_row_per_request() -> None:
    """A flood of bad job headers stays visible, exactly as a flood of bad staff headers does."""
    app = internal_app()
    client = TestClient(app)
    valid = job_headers()
    payload, signature = valid["X-CARLOS-Job-Assertion"].split(".")
    tampered = f"{payload}.{('A' if signature[0] != 'A' else 'B') + signature[1:]}"
    bad_headers = [
        {**valid, "X-CARLOS-Job-Assertion": "not-an-assertion"},
        {**valid, "X-CARLOS-Job-Assertion": ""},
        {**valid, "X-CARLOS-Job-Assertion": tampered},
        # An unknown key id, and a staff assertion sent as a job one.
        job_headers(key_id="nobody-2026"),
        {
            **valid,
            "X-CARLOS-Job-Assertion": carlos_staff_headers(SYNC, clinic_id=CLINIC)[
                "X-CARLOS-Staff-Assertion"
            ],
        },
    ]

    statuses = [client.get(CHOICES_URI, headers=headers).status_code for headers in bad_headers]

    assert statuses == [404] * len(bad_headers)
    assert [generic_shape(row) for row in audit_rows(app)] == [GENERIC_FAILURE] * len(bad_headers)


def test_both_headers_are_refused_and_recorded_when_the_job_signature_verifies() -> None:
    app = internal_app()
    client = TestClient(app)
    staff_header = carlos_staff_headers(SYNC, clinic_id=CLINIC)["X-CARLOS-Staff-Assertion"]
    tampered_job = job_headers(signing_key=TEST_JOB_ASSERTION_PRIVATE_KEYS["signup-poll"])

    both = client.get(
        CHOICES_URI, headers={**job_headers(), "X-CARLOS-Staff-Assertion": staff_header}
    )
    both_unsigned = client.get(
        CHOICES_URI, headers={**tampered_job, "X-CARLOS-Staff-Assertion": staff_header}
    )

    assert (both.status_code, both_unsigned.status_code) == (404, 404)
    first, second = audit_rows(app)
    assert (first.event_type, first.reason) == (AUDIT_EVENT_JOB_AUTH_REFUSED, "both_headers")
    assert generic_shape(second) == GENERIC_FAILURE


def test_refusals_after_the_signature_verified_name_the_key_owner_and_the_route() -> None:
    app = internal_app()
    client = TestClient(app)
    template = "/internal/carlos/booking-prompts/choices"
    cases = [
        ("unknown_job", job_headers("nightly-export")),
        (
            "wrong_key",
            job_headers(
                key_id=SIGNUP_KID,
                signing_key=TEST_JOB_ASSERTION_PRIVATE_KEYS["signup-poll"],
            ),
        ),
        ("invalid_claims", job_headers(audience="carlos-patient-portal-internal-api")),
        ("invalid_claims", job_headers(permission=[SYNC])),
        (
            "expired",
            job_headers(
                issued_at=int(utc_now().timestamp()) - 90,
                expires_at=int(utc_now().timestamp()) - 30,
            ),
        ),
        ("request_mismatch", job_headers(path=f"{CHOICES_URI}&limit=1")),
        ("clinic_mismatch", carlos_job_headers(method="GET", path=CHOICES_URI, clinic_id="b")),
        ("permission_not_held", job_headers(permission=INVITE)),
        ("route_not_open", job_headers("signup-poll", SIGNUP)),
    ]

    responses = [client.get(CHOICES_URI, headers=headers) for _, headers in cases]

    assert [response.status_code for response in responses] == [
        404,
        404,
        404,
        404,
        404,
        404,
        404,
        403,
        404,
    ]
    assert [response.json()["detail"] for response in responses][-2:] == [
        "permission denied",
        "not found",
    ]
    booking = ("Clinic booking", "job:booking-sync", template, BOOKING_KID)
    signup = ("Patient self sign-up", "job:signup-poll", template, SIGNUP_KID)
    assert refusal_rows(app) == [
        ("unknown_job", *booking),
        ("wrong_key", *signup),
        ("invalid_claims", *booking),
        ("invalid_claims", *booking),
        ("expired", *booking),
        ("request_mismatch", *booking),
        ("clinic_mismatch", *booking),
        ("permission_not_held", *booking),
        ("route_not_open", *signup),
    ]
    rows = audit_rows(app)
    assert {row.outcome for row in rows} == {"failure"}
    assert {row.actor_type for row in rows} == {"system"}
    # The portal's own clinic, never the one the caller claimed.
    assert {row.clinic_id for row in rows} == {CLINIC}
    assert all(row.assertion_id and UUID(row.assertion_id) for row in rows)


def test_job_audit_rows_carry_no_raw_path_query_or_patient_details() -> None:
    app = internal_app()
    client = TestClient(app)
    path = "/internal/carlos/patients/1234/invites?limit=7&offset=3"

    refused = client.get(path, headers=job_headers(path=path))
    failed = client.post(
        "/internal/carlos/booking-prompts/987/choice-result",
        headers={
            **job_headers(
                method="POST",
                path="/internal/carlos/booking-prompts/987/choice-result",
                body=b'{"choice_id":654,"result":"booked"}',
            ),
            "Content-Type": "application/json",
        },
        content=b'{"choice_id":654,"result":"booked"}',
    )

    assert (refused.status_code, failed.status_code) == (404, 404)
    rows = audit_rows(app)
    assert [row.resource_id for row in rows] == [
        "/internal/carlos/patients/{demographic_no}/invites",
        None,
    ]
    for row in rows:
        assert row.demographic_no is None and row.account_id is None and row.invite_id is None
        # Every stored text except the random ids and keyed hashes, which could hold any digits.
        stored = [
            value
            for column in PatientPortalAuditEvent.__table__.columns
            if column.name not in {"assertion_id", "client_reference_hash", "invite_token_hash"}
            and isinstance(value := getattr(row, column.name), str)
        ]
        for leaked in ("1234", "limit=7", "offset", "987", "654"):
            assert not any(leaked in value for value in stored), (leaked, stored)


def test_a_job_whose_handler_fails_is_audited_as_the_system_actor() -> None:
    app = internal_app()
    client = TestClient(app)
    path = "/internal/carlos/booking-prompts/987/choice-result"
    body = b'{"choice_id":654,"result":"booked"}'

    not_found = client.post(
        path,
        headers={
            **job_headers(method="POST", path=path, body=body),
            "Content-Type": "application/json",
        },
        content=body,
    )
    invalid = client.get(CHOICES_PATH, headers=job_headers(path=CHOICES_PATH))

    assert not_found.status_code == 404
    assert not_found.json() == {"detail": "booking prompt not found"}
    assert invalid.status_code == 422
    assert [
        (
            row.event_type,
            row.actor_type,
            row.actor,
            row.actor_id,
            row.clinic_id,
            row.reason,
            row.assertion_key_id,
            row.resource_id,
        )
        for row in audit_rows(app)
    ] == [
        (
            AUDIT_EVENT_STAFF_ACTION,
            "system",
            "Clinic booking",
            "job:booking-sync",
            CLINIC,
            reason,
            BOOKING_KID,
            None,
        )
        for reason in ("not_found", "validation_failed")
    ]
    assert all(len(row.assertion_id) == 36 for row in audit_rows(app))


def test_a_job_without_keys_is_off() -> None:
    off = internal_app(internal_job_assertion_public_keyring=None)
    only_signup = internal_app(
        internal_job_assertion_public_keyring=json.dumps(
            {"signup-poll": {SIGNUP_KID: TEST_JOB_ASSERTION_PUBLIC_KEYS["signup-poll"]}}
        )
    )

    for app in (off, only_signup):
        response = TestClient(app).get(CHOICES_URI, headers=job_headers())
        assert response.status_code == 404
        assert [generic_shape(row) for row in audit_rows(app)] == [GENERIC_FAILURE]


def test_a_job_key_can_be_rotated_with_both_keys_accepted_during_the_overlap() -> None:
    app = internal_app(
        internal_job_assertion_public_keyring=json.dumps(
            {
                "booking-sync": {
                    BOOKING_KID: TEST_JOB_ASSERTION_PUBLIC_KEYS["booking-sync"],
                    "booking-sync-next": TEST_JOB_ASSERTION_NEXT_PUBLIC_KEY,
                }
            }
        )
    )
    client = TestClient(app)

    current = client.get(CHOICES_URI, headers=job_headers())
    next_key = client.get(
        CHOICES_URI,
        headers=job_headers(
            key_id="booking-sync-next",
            signing_key=TEST_JOB_ASSERTION_NEXT_PRIVATE_KEY,
        ),
    )

    assert (current.status_code, next_key.status_code) == (200, 200)


def signup_test_app():
    """An app with one extra route open to the sign-up job, as its real routes will be.

    The booking-sync job holds a single permission, so only a job holding two can show the
    difference between a permission it does not hold and one it holds that the route does not
    take.
    """
    app = internal_app()
    deps = internal_routes.build_internal_dependencies(
        SimpleNamespace(settings=app.state.settings, session_factory=app.state.session_factory)
    )

    @app.get("/internal/carlos/test-only/signup-claims")
    def claim(
        principal: Annotated[
            JobPrincipal, Depends(deps.job_principal_requiring("signup-poll", SIGNUP))
        ],
    ) -> dict[str, str]:
        return {"job": principal.job, "permission": principal.permission}

    return app


def test_a_job_route_refuses_a_permission_not_held_or_not_the_routes_with_403() -> None:
    app = signup_test_app()
    client = TestClient(app)
    path = "/internal/carlos/test-only/signup-claims"

    def call(job: str, permission: str):
        return client.get(path, headers=job_headers(job, permission, path=path))

    accepted = call("signup-poll", SIGNUP)
    wrong_permission = call("signup-poll", INVITE)
    not_held = call("signup-poll", SYNC)
    other_job = call("booking-sync", SYNC)
    staff = client.get(path, headers=carlos_staff_headers(SIGNUP, INVITE, clinic_id=CLINIC))

    assert accepted.status_code == 200
    assert accepted.json() == {"job": "signup-poll", "permission": SIGNUP}
    assert [wrong_permission.status_code, not_held.status_code, other_job.status_code] == [
        403,
        403,
        404,
    ]
    assert staff.status_code == 403
    assert [row[:3] for row in refusal_rows(app)] == [
        ("wrong_permission", "Patient self sign-up", "job:signup-poll"),
        ("permission_not_held", "Patient self sign-up", "job:signup-poll"),
        ("route_not_open", "Clinic booking", "job:booking-sync"),
    ]
    assert [(row.event_type, row.actor_type, row.reason) for row in audit_rows(app)][-1] == (
        AUDIT_EVENT_STAFF_ACTION,
        "staff",
        "authorization_failed",
    )


# --------------------------------------------------------------------------------------
# Shared CARLOS/portal vectors
# --------------------------------------------------------------------------------------

CONTRACT_PATH = Path(__file__).parent / "fixtures" / "job-assertion-contract.json"
# RFC 8032 section 7.1, TEST 1: a published Ed25519 test key, used only for these vectors.
RFC_8032_TEST_1_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
RFC_8032_TEST_1_PUBLIC = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)


def decoded(value: str) -> bytes:
    return urlsafe_b64decode(value + "=" * (-len(value) % 4))


def test_the_shared_job_assertion_vectors_verify() -> None:
    """CARLOS copies this file byte for byte; both sides must hash and sign identically."""
    raw = CONTRACT_PATH.read_bytes()
    contract = json.loads(raw)
    # Stable form: sorted keys, two-space indent, ASCII only, one trailing newline.
    assert raw == (json.dumps(contract, indent=2, sort_keys=True) + "\n").encode("ascii")
    signing_key = Ed25519PrivateKey.from_private_bytes(RFC_8032_TEST_1_SEED)
    public_key = signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    assert public_key == RFC_8032_TEST_1_PUBLIC == decoded(contract["public_key"])
    assert encoded(public_key) == contract["public_key"]
    assert (contract["job"], contract["clinic_id"]) == ("booking-sync", "clinic-a")
    assert contract["audience"] == "carlos-patient-portal-job-api"
    assert contract["assertion_header"] == "X-CARLOS-Job-Assertion"
    assert contract["expires_at"] - contract["issued_at"] == 60
    keys = {contract["job"]: {contract["kid"]: contract["public_key"]}}
    methods = []

    for vector in contract["vectors"]:
        raw_path, _, query = vector["uri"].partition("?")
        body = vector["body"].encode("utf-8")
        assert vector["request_hash"] == staff_request_hash(
            vector["method"], raw_path.encode(), query.encode(), body
        )
        encoded_payload, encoded_signature = vector["assertion"].split(".")
        payload = decoded(encoded_payload)
        assert payload.decode("ascii") == vector["payload"]
        claims = json.loads(payload)
        assert json.dumps(claims, separators=(",", ":"), sort_keys=True) == vector["payload"]
        assert set(claims) == JOB_ASSERTION_FIELDS
        # Ed25519 is deterministic, so CARLOS's signer must produce these exact bytes.
        assert signing_key.sign(payload) == decoded(encoded_signature)
        principal = verify_job_assertion(
            keys,
            vector["assertion"],
            expected_request_hash=vector["request_hash"],
            expected_clinic_id=contract["clinic_id"],
            now=contract["issued_at"],
        )
        assert (principal.job, principal.key_id, principal.permission) == (
            contract["job"],
            contract["kid"],
            vector["permission"],
        )
        assert principal.assertion_id == vector["jti"] == claims["jti"]
        assert claims["iat"] == contract["issued_at"]
        methods.append((vector["method"], body.isascii()))
        # Verified only at its own time: an hour later it has expired.
        with pytest.raises(CarlosJobRefusal, match="expired"):
            verify_job_assertion(
                keys,
                vector["assertion"],
                expected_request_hash=vector["request_hash"],
                expected_clinic_id=contract["clinic_id"],
                now=contract["issued_at"] + 3600,
            )

    # One GET with a query, and one POST whose body has multi-byte UTF-8 text.
    assert methods == [("GET", True), ("POST", False)]


# --------------------------------------------------------------------------------------
# Migration 0016
# --------------------------------------------------------------------------------------


def test_job_audit_migration_adds_the_columns_and_downgrades_only_without_job_rows(
    tmp_path,
) -> None:
    config = Config()
    config.set_main_option("script_location", "carlos_patient_portal:migrations")
    database_url = f"sqlite+pysqlite:///{tmp_path / 'job-audit.db'}"
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0016_job_assertion_audit")
    engine = create_engine(database_url)
    now = utc_now()
    insert_event = text(
        "insert into patient_portal_audit_events (event_type, outcome, actor_type, "
        "assertion_key_id, assertion_id, created_at) values "
        "(:event_type, 'failure', 'system', :key_id, :assertion_id, :now)"
    )
    try:
        columns = {
            column["name"] for column in inspect(engine).get_columns("patient_portal_audit_events")
        }
        assert {"assertion_key_id", "assertion_id"} <= columns
        with engine.begin() as connection:
            connection.execute(
                insert_event,
                {
                    "event_type": "job.auth_refused",
                    "key_id": BOOKING_KID,
                    "assertion_id": str(uuid4()),
                    "now": now,
                },
            )
        # The database itself holds the shape: an unknown type or an over-long id is refused.
        for bad in (
            {"event_type": "job.made_up", "key_id": BOOKING_KID, "assertion_id": None},
            {"event_type": "job.auth_refused", "key_id": "k" * 65, "assertion_id": None},
            {"event_type": "job.auth_refused", "key_id": "", "assertion_id": None},
            {"event_type": "job.auth_refused", "key_id": None, "assertion_id": "short"},
        ):
            with pytest.raises(Exception, match="(?i)check"):
                with engine.begin() as connection:
                    connection.execute(insert_event, {**bad, "now": now})

        with pytest.raises(RuntimeError, match="job caller audit rows exist"):
            command.downgrade(config, "0015_booking_offered_slots")
        with engine.begin() as connection:
            connection.execute(text("delete from patient_portal_audit_events"))
            # A row of an older type that carries a key id is job evidence too.
            connection.execute(
                insert_event,
                {
                    "event_type": "staff.action",
                    "key_id": BOOKING_KID,
                    "assertion_id": None,
                    "now": now,
                },
            )
        with pytest.raises(RuntimeError, match="job caller audit rows exist"):
            command.downgrade(config, "0015_booking_offered_slots")
        with engine.begin() as connection:
            connection.execute(text("delete from patient_portal_audit_events"))

        command.downgrade(config, "0015_booking_offered_slots")
        assert not {"assertion_key_id", "assertion_id"} & {
            column["name"] for column in inspect(engine).get_columns("patient_portal_audit_events")
        }
        with pytest.raises(Exception, match="(?i)check"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "insert into patient_portal_audit_events "
                        "(event_type, outcome, actor_type, created_at) "
                        "values ('job.auth_refused', 'failure', 'system', :now)"
                    ),
                    {"now": now},
                )
        command.upgrade(config, "head")
        assert "assertion_id" in {
            column["name"] for column in inspect(engine).get_columns("patient_portal_audit_events")
        }
    finally:
        engine.dispose()
