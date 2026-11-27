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

"""The claim and result API CARLOS polls for self sign-up requests (carlos-portal#16)."""

import json
import logging
from datetime import date, timedelta

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.exc import IntegrityError

from carlos_patient_portal.identity import IdentityProof
from carlos_patient_portal.maintenance import cleanup_transient_auth_rows
from carlos_patient_portal.models import (
    AUDIT_EVENT_JOB_AUTH_REFUSED,
    AUDIT_EVENT_SIGNUP_CLAIM,
    AUDIT_EVENT_SIGNUP_RESULT,
    AUDIT_EVENT_STAFF_ACTION,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalSignupRequest,
    utc_now,
)
from carlos_patient_portal.self_signup import (
    SIGNUP_HEALTH_CARD_RESOURCE_TYPE,
    hash_signup_health_card,
    summarize_signup_backlog,
)
from carlos_patient_portal.signup_claims import hash_lease_token
from carlos_patient_portal.system_jobs import (
    JOB_BOOKING_SYNC,
    JOB_SIGNUP_POLL,
    PERMISSION_BOOKING_PROMPT_SYNC,
    PERMISSION_INVITE_MANAGE,
    PERMISSION_SIGNUP_MANAGE,
)
from tests.support import (
    AUDIT_HASH_SECRET,
    INTERNAL_API_TOKEN,
    OUTBOX_ENCRYPTION_SECRET,
    carlos_job_headers,
    carlos_staff_headers,
    create_service_invite,
)
from tests.test_internal_api import internal_app
from tests.test_self_signup import FAKE_DOB, FAKE_EMAIL, FAKE_HCN, client_at, sign_up

CLINIC = "clinic-a"
CLAIM_PATH = "/internal/carlos/signup-requests/claim"
FAKE_CARD_NORMALIZED = "9876543210XY"
# The fixed `detail` texts a caller may see; an error body never carries anything else.
KNOWN_DETAILS = {
    "not found",
    "permission denied",
    "sign-up request not found",
    "sign-up request lease expired",
    "sign-up request already has a different result",
    "sign-up result is invalid",
}


def result_path(request_id: int) -> str:
    return f"/internal/carlos/signup-requests/{request_id}/result"


def signup_app(**overrides: object):
    return internal_app(
        self_signup_enabled=True,
        self_signup_response_floor_ms=0,
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
        **overrides,
    )


def post_job(
    client,
    path: str,
    payload: object,
    *,
    job: str = JOB_SIGNUP_POLL,
    permission: str = PERMISSION_SIGNUP_MANAGE,
    **options: object,
):
    body = json.dumps(payload).encode()
    headers = carlos_job_headers(
        job, permission, method="POST", path=path, body=body, clinic_id=CLINIC, **options
    )
    return client.post(path, content=body, headers={**headers, "Content-Type": "application/json"})


def claim(client, limit: int | None = None, **options: object):
    return post_job(client, CLAIM_PATH, {} if limit is None else {"limit": limit}, **options)


def report(client, request_id: int, token: str, result: str, invite_id: int | None = None, **o):
    payload: dict[str, object] = {"lease_token": token, "result": result}
    if invite_id is not None:
        payload["invite_id"] = invite_id
    return post_job(client, result_path(request_id), payload, **o)


def store_requests(app, count: int = 1, *, first_card: int = 9876543210) -> None:
    """Store `count` requests through the public page, one card and one client address each."""
    for index in range(count):
        client = client_at(app, f"203.0.113.{10 + index}")
        response = sign_up(client, health_card_number=f"{first_card + index}XY")
        assert response.status_code == 202


def stored_rows(app) -> list[PatientPortalSignupRequest]:
    with app.state.session_factory() as session:
        return list(
            session.scalars(select(PatientPortalSignupRequest).order_by(PatientPortalSignupRequest.id))
        )


def audit_rows(app, *event_types: str) -> list[PatientPortalAuditEvent]:
    with app.state.session_factory() as session:
        statement = select(PatientPortalAuditEvent).order_by(PatientPortalAuditEvent.id)
        if event_types:
            statement = statement.where(PatientPortalAuditEvent.event_type.in_(event_types))
        return list(session.scalars(statement))


def recorded_results(app) -> list[PatientPortalAuditEvent]:
    """The `signup.result` rows of results that were recorded (refusals are audited as failures)."""
    return [row for row in audit_rows(app, AUDIT_EVENT_SIGNUP_RESULT) if row.outcome == "success"]


def make_account(app) -> int:
    """A portal account for an `accepted` invite to point at."""
    with app.state.session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id=CLINIC,
            demographic_no=2999,
            username="fake.patient",
            email=FAKE_EMAIL,
            password_hash="x" * 60,
            status="active",
        )
        session.add(account)
        session.flush()
        return account.id


def update_row(app, request_id: int, **values: object) -> None:
    with app.state.session_factory() as session, session.begin():
        row = session.get(PatientPortalSignupRequest, request_id)
        for name, value in values.items():
            setattr(row, name, value)


def typed_identity(**overrides: object) -> IdentityProof:
    """The details every request stored here carries (the first card, see `store_requests`)."""
    values: dict[str, object] = {
        "email": FAKE_EMAIL,
        "date_of_birth": date.fromisoformat(FAKE_DOB),
        "health_card_number": FAKE_HCN,
        **overrides,
    }
    return IdentityProof(**values)


_next_demographic_no = iter(range(2000, 3000))


def make_invite(
    app,
    *,
    clinic_id: str = CLINIC,
    identity: IdentityProof | None = None,
    for_request: int | None = 1,
    **columns: object,
) -> int:
    """An invite as the sign-up job makes it for a match: the identity hashed as an invite does.

    `for_request` is the request it is the prepared invite of (a match can only be reported with
    that one); None leaves it unlinked. Each invite is for a patient of its own, so creating one
    never supersedes another.
    """
    with app.state.session_factory() as session, session.begin():
        invite, _ = create_service_invite(
            session,
            next(_next_demographic_no),
            clinic_id=clinic_id,
            identity_proof=identity or typed_identity(),
        )
        for name, value in columns.items():
            setattr(invite, name, value)
        session.flush()
        if for_request is not None:
            session.get(PatientPortalSignupRequest, for_request).prepared_invite_id = invite.id
        return invite.id


def claimed(response) -> list[dict[str, object]]:
    assert response.status_code == 200, response.text
    return response.json()["items"]


def assert_known_error(response) -> None:
    assert set(response.json()) == {"detail"}
    assert response.json()["detail"] in KNOWN_DETAILS


# --------------------------------------------------------------------------------------------
# The claim
# --------------------------------------------------------------------------------------------


def test_a_claim_leases_the_oldest_requests_with_their_decrypted_details() -> None:
    app = signup_app()
    store_requests(app, 3)
    client = client_at(app, "198.51.100.1")

    items = claimed(claim(client, 2))

    assert [item["request_id"] for item in items] == [1, 2]
    first = items[0]
    assert set(first) == {
        "request_id",
        "lease_token",
        "lease_expires_at",
        "requested_at",
        "health_card_number",
        "date_of_birth",
        "email",
    }
    assert first["health_card_number"] == FAKE_CARD_NORMALIZED
    assert first["date_of_birth"] == FAKE_DOB
    assert first["email"] == FAKE_EMAIL
    assert len(first["lease_token"]) == 43
    assert items[0]["lease_token"] != items[1]["lease_token"]
    rows = stored_rows(app)
    assert [row.lease_token_hash is not None for row in rows] == [True, True, False]
    assert rows[0].lease_token_hash == hash_lease_token(first["lease_token"])
    # The default batch takes the one left.
    assert [item["request_id"] for item in claimed(claim(client))] == [3]


def test_two_claims_never_receive_the_same_request() -> None:
    app = signup_app()
    store_requests(app, 5)
    client = client_at(app, "198.51.100.1")

    first = claimed(claim(client, 3))
    second = claimed(claim(client, 3))
    third = claimed(claim(client, 3))

    ids = [item["request_id"] for item in first + second + third]
    assert sorted(ids) == [1, 2, 3, 4, 5]
    assert len(set(ids)) == 5
    assert third == []


def test_an_empty_claim_writes_nothing() -> None:
    app = signup_app()
    client = client_at(app, "198.51.100.1")

    assert claimed(claim(client)) == []
    assert audit_rows(app) == []


@pytest.mark.parametrize("limit", [0, -1, 51, "5", 1.5, True, None])
def test_the_batch_size_is_a_whole_number_from_one_to_fifty(limit: object) -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")

    response = post_job(client, CLAIM_PATH, {"limit": limit})

    assert response.status_code == 422
    assert stored_rows(app)[0].lease_token_hash is None


def test_a_claim_with_anything_else_in_the_body_is_refused() -> None:
    app = signup_app()
    client = client_at(app, "198.51.100.1")

    assert post_job(client, CLAIM_PATH, {"limit": 1, "clinic_id": "other"}).status_code == 422


def test_an_expired_lease_makes_a_request_claimable_again_under_a_new_token() -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    old = claimed(claim(client))[0]
    assert claimed(claim(client)) == []

    update_row(app, 1, lease_expires_at=utc_now() - timedelta(seconds=1))
    new = claimed(claim(client))[0]

    assert new["request_id"] == old["request_id"]
    assert new["lease_token"] != old["lease_token"]
    # Someone else's lease: the old holder's token no longer opens the request.
    late = report(client, 1, old["lease_token"], "no_match")
    assert late.status_code == 404
    assert stored_rows(app)[0].result is None
    assert report(client, 1, new["lease_token"], "no_match").status_code == 200


def test_a_request_past_its_ttl_is_never_returned() -> None:
    app = signup_app()
    store_requests(app, 2)
    long_ago = utc_now() - timedelta(days=3)
    update_row(app, 1, created_at=long_ago, expires_at=utc_now() - timedelta(minutes=1))
    client = client_at(app, "198.51.100.1")

    assert [item["request_id"] for item in claimed(claim(client, 10))] == [2]


def test_another_clinics_requests_are_not_claimed() -> None:
    app = signup_app()
    store_requests(app, 1)
    update_row(app, 1, clinic_id="clinic-b")
    client = client_at(app, "198.51.100.1")

    assert claimed(claim(client)) == []
    assert stored_rows(app)[0].lease_token_hash is None


def test_the_claim_is_closed_while_self_sign_up_is_off() -> None:
    app = internal_app(self_signup_enabled=False)
    client = client_at(app, "198.51.100.1")

    response = claim(client)

    assert response.status_code == 404
    assert response.json() == {"detail": "not found"}


def clone_requests(app, source_id: int, count: int, **overrides: object) -> None:
    """`count` more rows like `source_id`, for the head of the queue (ids after the source's)."""
    with app.state.session_factory() as session, session.begin():
        source = session.get(PatientPortalSignupRequest, source_id)
        values = {
            column.name: getattr(source, column.name)
            for column in PatientPortalSignupRequest.__table__.columns
            if column.name != "id"
        }
        for _ in range(count):
            session.add(PatientPortalSignupRequest(**{**values, **overrides}))


def test_a_request_under_a_key_the_keyring_lacks_waits_for_it_and_blocks_nothing() -> None:
    app = signup_app()
    store_requests(app, 1)
    update_row(app, 1, encryption_key_id="retired")
    # More of them than one batch can hold, ahead of a readable request.
    clone_requests(app, 1, 54)
    store_requests(app, 1, first_card=9000000000)
    client = client_at(app, "198.51.100.1")

    first = claimed(claim(client, 10))
    second = claimed(claim(client, 10))

    assert [item["request_id"] for item in first] == [56]
    assert second == []
    rows = stored_rows(app)
    # Nothing was leased or quarantined, and no audit row was written for any of them, however
    # often the poll runs: they only wait for the key, and are claimable the moment it is back.
    assert all(row.lease_token_hash is None for row in rows[:55])
    failed = [row for row in audit_rows(app, AUDIT_EVENT_SIGNUP_CLAIM) if row.outcome == "failure"]
    assert failed == []
    with app.state.session_factory() as session:
        # The leased one still waits for its result, so every row still counts.
        assert summarize_signup_backlog(session).pending == 56


def test_a_request_whose_payload_does_not_authenticate_is_quarantined_and_audited_once() -> None:
    app = signup_app()
    store_requests(app, 2)
    update_row(app, 1, encrypted_payload=b"x" * 64)
    client = client_at(app, "198.51.100.1")

    first = claimed(claim(client))
    second = claimed(claim(client))

    assert [item["request_id"] for item in first] == [2]
    assert second == []
    quarantined = stored_rows(app)[0]
    # A lease no caller holds the token of, until the request expires: never claimed again.
    assert quarantined.lease_token_hash is not None
    assert quarantined.lease_expires_at == quarantined.expires_at
    failed = [row for row in audit_rows(app, AUDIT_EVENT_SIGNUP_CLAIM) if row.outcome == "failure"]
    assert [(row.reason, row.resource_type) for row in failed] == [
        ("payload_unreadable", SIGNUP_HEALTH_CARD_RESOURCE_TYPE)
    ]
    # No token can report a result for it.
    assert report(client, 1, "A" * 43, "no_match").status_code == 404


# --------------------------------------------------------------------------------------------
# Who may call
# --------------------------------------------------------------------------------------------


def test_only_the_signup_job_claiming_the_signup_permission_is_accepted() -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")

    # Staff, whatever they hold, never reach a job's route.
    for permissions in (
        (PERMISSION_SIGNUP_MANAGE,),
        (PERMISSION_INVITE_MANAGE,),
        (PERMISSION_SIGNUP_MANAGE, PERMISSION_INVITE_MANAGE),
    ):
        body = b"{}"
        headers = carlos_staff_headers(*permissions, clinic_id=CLINIC, token=INTERNAL_API_TOKEN)
        refused = client.post(
            CLAIM_PATH, content=body, headers={**headers, "Content-Type": "application/json"}
        )
        assert refused.status_code in {403, 404}, permissions
        assert_known_error(refused)
    # Another job is refused, with its own permission and with this one's.
    other = claim(client, job=JOB_BOOKING_SYNC, permission=PERMISSION_BOOKING_PROMPT_SYNC)
    assert other.status_code == 404
    borrowed = claim(client, job=JOB_BOOKING_SYNC, permission=PERMISSION_SIGNUP_MANAGE)
    assert borrowed.status_code in {403, 404}
    # The signup job's other permission opens nothing here: the route wants signup.manage.
    wrong = claim(client, permission=PERMISSION_INVITE_MANAGE)
    assert wrong.status_code == 403
    for response in (other, borrowed, wrong):
        assert_known_error(response)
    assert stored_rows(app)[0].lease_token_hash is None
    assert [row.event_type for row in audit_rows(app, AUDIT_EVENT_SIGNUP_CLAIM)] == []
    # The refusals are on the audit trail as the job's refusals, not as claims.
    assert any(row.event_type == AUDIT_EVENT_JOB_AUTH_REFUSED for row in audit_rows(app))


def test_a_staff_assertion_carrying_the_signup_permission_is_refused_on_every_route() -> None:
    """`portal.signup.manage` is a job's right: it never rides on a person's login, even beside a
    right a staff route does take (carlos-portal#16)."""
    app = signup_app()
    client = client_at(app, "198.51.100.1")
    path = "/internal/carlos/patients/1234/invites"
    headers = carlos_staff_headers(
        PERMISSION_INVITE_MANAGE, PERMISSION_SIGNUP_MANAGE, clinic_id=CLINIC
    )

    refused = client.get(path, headers=headers)
    allowed_without = client.get(
        path, headers=carlos_staff_headers(PERMISSION_INVITE_MANAGE, clinic_id=CLINIC)
    )

    assert refused.status_code == 403
    assert refused.json() == {"detail": "permission denied"}
    assert allowed_without.status_code != 403


def test_a_call_without_a_job_assertion_or_with_the_wrong_token_is_one_plain_404() -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")

    plain = client.post(CLAIM_PATH, json={})
    wrong_token = post_job(client, CLAIM_PATH, {}, token="x" * 32)

    assert plain.status_code == wrong_token.status_code == 404
    assert plain.json() == wrong_token.json() == {"detail": "not found"}
    assert stored_rows(app)[0].lease_token_hash is None


def test_a_jobs_call_for_another_clinic_is_refused() -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    body = b"{}"
    headers = carlos_job_headers(
        JOB_SIGNUP_POLL,
        PERMISSION_SIGNUP_MANAGE,
        method="POST",
        path=CLAIM_PATH,
        body=body,
        clinic_id="clinic-b",
    )

    response = client.post(CLAIM_PATH, content=body, headers=headers)

    assert response.status_code in {403, 404}
    assert stored_rows(app)[0].lease_token_hash is None


# --------------------------------------------------------------------------------------------
# The result
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("result", ["matched", "no_match", "ineligible"])
def test_a_result_deletes_the_stored_details_and_keeps_only_the_outcome(result: str) -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    item = claimed(claim(client))[0]
    invite_id = make_invite(app) if result == "matched" else None

    response = report(client, 1, item["lease_token"], result, invite_id)

    assert response.status_code == 200
    assert response.json() == {
        "request_id": 1,
        "result": result,
        "invite_id": invite_id,
        "recorded": True,
    }
    row = stored_rows(app)[0]
    assert row.encrypted_payload is None
    assert row.encryption_nonce is None
    assert row.result == result
    assert row.invite_id == invite_id
    assert row.resulted_at is not None
    # The details are gone from the database, not only unreadable.
    with app.state.session_factory() as session:
        stored = session.connection().exec_driver_sql(
            "select * from patient_portal_signup_requests"
        )
        dump = json.dumps([[str(value) for value in record] for record in stored])
    assert FAKE_EMAIL not in dump
    assert FAKE_CARD_NORMALIZED not in dump
    assert FAKE_DOB not in dump
    # A reported request no longer counts as waiting, and cannot be claimed again.
    with app.state.session_factory() as session:
        assert summarize_signup_backlog(session).pending == 0
    update_row(app, 1, lease_expires_at=utc_now() - timedelta(seconds=1))
    assert claimed(claim(client)) == []


def test_the_same_result_again_is_a_repeat_that_changes_and_audits_nothing() -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    token = claimed(claim(client))[0]["lease_token"]
    invite_id = make_invite(app)
    first = report(client, 1, token, "matched", invite_id)
    row_after_first = stored_rows(app)[0]
    events_after_first = len(audit_rows(app))

    second = report(client, 1, token, "matched", invite_id)

    assert first.json()["recorded"] is True
    assert second.status_code == 200
    assert second.json() == {**first.json(), "recorded": False}
    assert stored_rows(app)[0].resulted_at == row_after_first.resulted_at
    assert len(audit_rows(app)) == events_after_first


def test_a_different_result_for_a_reported_request_is_a_conflict() -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    token = claimed(claim(client))[0]["lease_token"]
    invite_id = make_invite(app)
    other_invite_id = make_invite(app, for_request=None)
    assert report(client, 1, token, "matched", invite_id).status_code == 200

    for attempt in (
        report(client, 1, token, "no_match"),
        report(client, 1, token, "ineligible"),
        report(client, 1, token, "matched", other_invite_id),
    ):
        assert attempt.status_code == 409
        assert attempt.json() == {"detail": "sign-up request already has a different result"}
    row = stored_rows(app)[0]
    assert (row.result, row.invite_id) == ("matched", invite_id)
    assert len(recorded_results(app)) == 1


def test_a_result_after_the_lease_ran_out_is_refused_and_the_details_stay() -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    token = claimed(claim(client))[0]["lease_token"]
    update_row(app, 1, lease_expires_at=utc_now() - timedelta(seconds=1))

    response = report(client, 1, token, "no_match")

    assert response.status_code == 409
    assert response.json() == {"detail": "sign-up request lease expired"}
    row = stored_rows(app)[0]
    assert row.result is None
    assert row.encrypted_payload is not None
    assert recorded_results(app) == []


def test_unknown_ids_wrong_tokens_and_other_clinics_all_answer_alike() -> None:
    app = signup_app()
    store_requests(app, 2)
    update_row(app, 2, clinic_id="clinic-b")
    client = client_at(app, "198.51.100.1")
    token = claimed(claim(client))[0]["lease_token"]

    unknown = report(client, 999, token, "no_match")
    wrong_token = report(client, 1, "A" * 43, "no_match")
    other_clinic = report(client, 2, token, "no_match")
    # A request that was never leased has no token to match.
    update_row(app, 2, clinic_id=CLINIC)
    never_leased = report(client, 2, token, "no_match")

    responses = (unknown, wrong_token, other_clinic, never_leased)
    assert {response.status_code for response in responses} == {404}
    assert {response.content for response in responses} == {
        json.dumps({"detail": "sign-up request not found"}, separators=(",", ":")).encode()
    }
    assert all(row.result is None for row in stored_rows(app))


def test_a_match_must_name_an_invite_made_for_this_request() -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    token = claimed(claim(client))[0]["lease_token"]
    refused = {
        "no such invite": 424242,
        "another clinic's invite": make_invite(app, clinic_id="clinic-b", for_request=None),
        "another patient's email": make_invite(
            app, identity=typed_identity(email="someone.else@example.test"), for_request=None
        ),
        "another date of birth": make_invite(
            app, identity=typed_identity(date_of_birth=date(1975, 3, 15)), for_request=None
        ),
        "another health card": make_invite(
            app, identity=typed_identity(health_card_number="1111 222 333 AB"), for_request=None
        ),
        "an invite older than the request": make_invite(
            app, created_at=utc_now() - timedelta(days=2), for_request=None
        ),
        # Live, and made for exactly these details, but not the one prepared for this request.
        "an invite that is not the request's own": make_invite(app, for_request=None),
    }

    for reason, invite_id in refused.items():
        # Each one is the request's prepared invite in turn, so the link is never the reason,
        # except for the one that is not linked at all.
        if reason != "an invite that is not the request's own":
            update_row(app, 1, prepared_invite_id=invite_id)
        response = report(client, 1, token, "matched", invite_id)
        assert response.status_code == 422, reason
        # One answer for every reason: it says nothing about which check failed.
        assert response.json() == {"detail": "sign-up result is invalid"}, reason
    row = stored_rows(app)[0]
    assert row.result is None
    assert row.encrypted_payload is not None
    assert recorded_results(app) == []
    # The invite made for these details (a version code typed or left off alike) is accepted.
    good = make_invite(app, identity=typed_identity(health_card_number="9876543210"))  # linked
    assert report(client, 1, token, "matched", good).status_code == 200


PREPARED_COLUMNS = {
    "delivery_operation_id": "op-0001",
    "encrypted_invite_token": b"opaque",
    "invite_token_nonce": b"n" * 12,
    "invite_token_key_id": "primary",
}


@pytest.mark.parametrize(
    ("status", "columns", "accepted"),
    [
        ("pending", {}, True),
        ("accepted", {"accepted_at": "now", "accepted_account_id": "account"}, True),
        ("pending", {"created_at": "ago", "expires_at": "past"}, False),
        ("prepared", PREPARED_COLUMNS, False),
        ("revoked", {"revoked_at": "now", "revoked_by": "FAKE Staff"}, False),
        ("superseded", {}, False),
    ],
)
def test_a_match_must_name_an_invite_that_can_still_stand_for_the_answer(
    status: str, columns: dict[str, object], accepted: bool
) -> None:
    """`pending` (unexpired) and `accepted` are live; `prepared` was never delivered, `revoked` and
    `superseded` were replaced: the patient would wait for an email whose link cannot be used."""
    app = signup_app()
    store_requests(app, 1)
    # A request stored long enough ago for an invite to have been made, and to have expired since.
    update_row(app, 1, created_at=utc_now() - timedelta(days=3))
    client = client_at(app, "198.51.100.1")
    token = claimed(claim(client))[0]["lease_token"]
    moments = {
        "now": utc_now(),
        "ago": utc_now() - timedelta(days=2),
        "past": utc_now() - timedelta(hours=1),
    }
    moments["account"] = make_account(app) if status == "accepted" else 0
    resolved = {
        name: moments.get(value, value) if isinstance(value, str) else value
        for name, value in columns.items()
    }
    invite_id = make_invite(app, status=status, **resolved)

    response = report(client, 1, token, "matched", invite_id)

    assert response.status_code == (200 if accepted else 422), (status, columns)
    assert (stored_rows(app)[0].result == "matched") is accepted


def test_every_refused_result_leaves_an_audit_row_the_caller_never_sees() -> None:
    app = signup_app()
    store_requests(app, 3)
    client = client_at(app, "198.51.100.1")
    items = claimed(claim(client, 3))
    tokens = {item["request_id"]: item["lease_token"] for item in items}
    update_row(app, 3, lease_expires_at=utc_now() - timedelta(seconds=1))
    done_invite = make_invite(app)
    assert report(client, 1, tokens[1], "matched", done_invite).status_code == 200
    stranger = make_invite(
        app, identity=typed_identity(email="someone.else@example.test"), for_request=2
    )
    before = len(audit_rows(app, AUDIT_EVENT_SIGNUP_RESULT))

    attempts = {
        "request_not_found": report(client, 999, tokens[2], "no_match"),
        "lease_token_mismatch": report(client, 2, "A" * 43, "no_match"),
        "lease_expired": report(client, 3, tokens[3], "no_match"),
        "result_conflict": report(client, 1, tokens[1], "no_match"),
        "invite_not_for_request": report(client, 2, tokens[2], "matched", stranger),
    }

    for response in attempts.values():
        assert_known_error(response)
    refusals = audit_rows(app, AUDIT_EVENT_SIGNUP_RESULT)[before:]
    assert [row.reason for row in refusals] == list(attempts)
    assert {row.outcome for row in refusals} == {"failure"}
    assert {(row.actor_type, row.actor_id) for row in refusals} == {("system", "job:signup-poll")}
    assert all(row.assertion_key_id and row.assertion_id for row in refusals)
    hashes = {
        row.reason: (row.resource_type, row.resource_id)
        for row in refusals
    }
    # An unknown id names no request; the others carry only the keyed health-card hash.
    assert hashes["request_not_found"] == (None, None)
    for reason in list(attempts)[1:]:
        resource_type, resource_id = hashes[reason]
        assert resource_type == SIGNUP_HEALTH_CARD_RESOURCE_TYPE
        assert resource_id is not None and len(resource_id) == 64
    everything = json.dumps(
        [
            {column.name: str(getattr(row, column.name)) for column in row.__table__.columns}
            for row in refusals
        ]
    )
    for secret in (FAKE_EMAIL, FAKE_CARD_NORMALIZED, FAKE_DOB, *tokens.values(), "A" * 43):
        assert secret not in everything
    # The refusals changed nothing about the requests they were about.
    rows = stored_rows(app)
    assert [row.result for row in rows] == ["matched", None, None]


@pytest.mark.parametrize(
    "payload",
    [
        {"result": "matched"},
        {"result": "no_match", "invite_id": 1},
        {"result": "ineligible", "invite_id": 1},
        {"result": "matched", "invite_id": 0},
        {"result": "matched", "invite_id": "1"},
        {"result": "maybe"},
        {"result": "no_match", "extra": 1},
    ],
)
def test_a_result_body_that_does_not_fit_is_refused_before_anything_is_read(payload) -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    token = claimed(claim(client))[0]["lease_token"]

    response = post_job(client, result_path(1), {"lease_token": token, **payload})

    assert response.status_code == 422
    assert stored_rows(app)[0].result is None


@pytest.mark.parametrize("token", ["", "short", "A" * 42, "A" * 44, "!" * 43])
def test_a_lease_token_that_cannot_be_one_is_refused(token: str) -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    claimed(claim(client))

    assert post_job(
        client, result_path(1), {"lease_token": token, "result": "no_match"}
    ).status_code == 422


def test_a_result_is_taken_while_self_sign_up_is_off_so_leased_details_can_be_deleted() -> None:
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    token = claimed(claim(client))[0]["lease_token"]
    # The same database, with the feature switched off.
    off_app = internal_app(self_signup_enabled=False)
    with app.state.session_factory() as source, off_app.state.session_factory() as target:
        for row in source.scalars(select(PatientPortalSignupRequest)):
            target.merge(
                PatientPortalSignupRequest(
                    **{
                        column.name: getattr(row, column.name)
                        for column in PatientPortalSignupRequest.__table__.columns
                    }
                )
            )
        target.commit()
    off_client = client_at(off_app, "198.51.100.1")

    response = report(off_client, 1, token, "no_match")

    assert response.status_code == 200
    with off_app.state.session_factory() as session:
        assert session.get(PatientPortalSignupRequest, 1).encrypted_payload is None


# --------------------------------------------------------------------------------------------
# What is recorded, and what is not
# --------------------------------------------------------------------------------------------


def test_audit_rows_carry_only_keyed_hashes_the_actor_and_the_invite(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    item = claimed(claim(client))[0]
    invite_id = make_invite(app)
    assert report(client, 1, item["lease_token"], "matched", invite_id).status_code == 200

    expected_hash = hash_signup_health_card(AUDIT_HASH_SECRET, FAKE_CARD_NORMALIZED)
    claim_row, result_row = audit_rows(app, AUDIT_EVENT_SIGNUP_CLAIM, AUDIT_EVENT_SIGNUP_RESULT)

    for row, event in (
        (claim_row, AUDIT_EVENT_SIGNUP_CLAIM),
        (result_row, AUDIT_EVENT_SIGNUP_RESULT),
    ):
        assert row.event_type == event
        assert row.outcome == "success"
        assert row.actor_type == "system"
        assert row.actor == "Patient self sign-up"
        assert row.actor_id == "job:signup-poll"
        assert row.clinic_id == CLINIC
        assert row.resource_type == SIGNUP_HEALTH_CARD_RESOURCE_TYPE
        assert row.resource_id == expected_hash
        assert row.assertion_key_id and row.assertion_id
    assert claim_row.invite_id is None
    assert (result_row.invite_id, result_row.reason) == (invite_id, "matched")
    everything = json.dumps(
        [
            {column.name: str(getattr(row, column.name)) for column in row.__table__.columns}
            for row in audit_rows(app)
        ]
    )
    for secret in (FAKE_EMAIL, FAKE_CARD_NORMALIZED, FAKE_HCN, FAKE_DOB, item["lease_token"]):
        assert secret not in everything
        assert secret not in caplog.text


def test_failed_calls_audit_and_say_nothing_about_the_request(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    app = signup_app()
    store_requests(app, 1)
    client = client_at(app, "198.51.100.1")
    item = claimed(claim(client))[0]

    refused = [
        report(client, 999, item["lease_token"], "no_match"),
        report(client, 1, "A" * 43, "no_match"),
        report(client, 1, item["lease_token"], "matched", 424242),
    ]

    for response in refused:
        assert_known_error(response)
    failures = [
        row
        for row in audit_rows(app, AUDIT_EVENT_STAFF_ACTION)
        if row.outcome == "failure" and row.actor_id == "job:signup-poll"
    ]
    assert len(failures) == 3
    everything = json.dumps(
        [
            {column.name: str(getattr(row, column.name)) for column in row.__table__.columns}
            for row in audit_rows(app)
        ]
    )
    for secret in (FAKE_EMAIL, FAKE_CARD_NORMALIZED, FAKE_DOB, item["lease_token"]):
        assert secret not in everything
        assert secret not in caplog.text


def test_cleanup_keeps_a_running_lease_past_the_ttl_and_deletes_the_rest() -> None:
    app = signup_app()
    store_requests(app, 3)
    client = client_at(app, "198.51.100.1")
    leased = claimed(claim(client, 1))[0]
    token_two = claimed(claim(client, 1))[0]["lease_token"]
    invite_id = make_invite(
        app, identity=typed_identity(health_card_number="9876543211XY"), for_request=2
    )
    assert report(client, 2, token_two, "matched", invite_id).status_code == 200
    long_ago = utc_now() - timedelta(days=3)
    gone = utc_now() - timedelta(minutes=1)
    for request_id in (1, 2, 3):
        update_row(app, request_id, created_at=long_ago, expires_at=gone)
    update_row(app, 1, lease_expires_at=utc_now() + timedelta(minutes=2))

    with app.state.session_factory() as session, session.begin():
        cleanup_transient_auth_rows(session, before=utc_now() - timedelta(days=30))

    # Request 1 is under a running lease: kept, and its result can still be recorded.
    assert [row.id for row in stored_rows(app)] == [1]
    assert report(client, 1, leased["lease_token"], "no_match").status_code == 200


def test_the_database_refuses_a_result_that_leaves_the_details_in_place() -> None:
    app = signup_app()
    store_requests(app, 1)

    with pytest.raises(IntegrityError):
        update_row(app, 1, result="no_match", resulted_at=utc_now(), lease_token_hash="a" * 64,
                   lease_expires_at=utc_now())
    with pytest.raises(IntegrityError):
        update_row(app, 1, lease_token_hash="a" * 64)  # a token without an expiry
    with pytest.raises(IntegrityError):
        update_row(app, 1, lease_token_hash="short", lease_expires_at=utc_now())
    with pytest.raises(IntegrityError):
        update_row(app, 1, result="maybe")
    with pytest.raises(IntegrityError):
        update_row(app, 1, invite_id=5)  # an invite only with a match


# --------------------------------------------------------------------------------------------
# The migration
# --------------------------------------------------------------------------------------------


def alembic_config(url: str) -> Config:
    config = Config()
    config.set_main_option("script_location", "carlos_patient_portal:migrations")
    config.set_main_option("sqlalchemy.url", url)
    return config


def test_the_migration_keeps_stored_requests_and_refuses_to_downgrade_over_reported_ones(
    tmp_path,
) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'claim.db'}"
    config = alembic_config(url)
    command.upgrade(config, "0024_avail_device_removed")
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "insert into patient_portal_signup_requests (clinic_id, health_card_hash, "
                    "encrypted_payload, encryption_nonce, encryption_key_id, created_at, "
                    "expires_at) values ('c', :hash, :payload, :nonce, 'primary', :now, :later)"
                ),
                {
                    "hash": "h" * 64,
                    "payload": b"opaque",
                    "nonce": b"n" * 12,
                    "now": utc_now(),
                    "later": utc_now() + timedelta(hours=24),
                },
            )
        command.upgrade(config, "head")
        columns = {column["name"] for column in inspect(engine).get_columns(
            "patient_portal_signup_requests"
        )}
        assert {
            "lease_token_hash",
            "lease_expires_at",
            "result",
            "invite_id",
            "resulted_at",
        } <= columns
        with engine.begin() as connection:
            assert connection.scalar(
                text("select count(*) from patient_portal_signup_requests where result is null")
            ) == 1
            connection.execute(
                text(
                    "update patient_portal_signup_requests set result = 'no_match', "
                    "encrypted_payload = null, encryption_nonce = null, resulted_at = :now, "
                    "lease_token_hash = :hash, lease_expires_at = :now"
                ),
                {"now": utc_now(), "hash": "t" * 64},
            )
        with pytest.raises(RuntimeError, match="reported sign-up requests exist"):
            command.downgrade(config, "0024_avail_device_removed")
    finally:
        engine.dispose()


def test_the_migration_refuses_a_downgrade_over_claim_audit_events_and_otherwise_round_trips(
    tmp_path,
) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'events.db'}"
    config = alembic_config(url)
    command.upgrade(config, "head")
    engine = create_engine(url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "insert into patient_portal_audit_events "
                    "(event_type, outcome, actor_type, created_at) "
                    "values ('signup.claim', 'success', 'system', :now)"
                ),
                {"now": utc_now()},
            )
        with pytest.raises(RuntimeError, match="claim or result audit events exist"):
            command.downgrade(config, "0024_avail_device_removed")
        with engine.begin() as connection:
            connection.execute(text("delete from patient_portal_audit_events"))
        command.downgrade(config, "0024_avail_device_removed")
        columns = {column["name"] for column in inspect(engine).get_columns(
            "patient_portal_signup_requests"
        )}
        assert "lease_token_hash" not in columns
        with pytest.raises(Exception, match="(?i)constraint"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "insert into patient_portal_audit_events "
                        "(event_type, outcome, actor_type, created_at) "
                        "values ('signup.result', 'success', 'system', :now)"
                    ),
                    {"now": utc_now()},
                )
        command.upgrade(config, "head")
    finally:
        engine.dispose()
