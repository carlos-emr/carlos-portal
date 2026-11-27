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

"""The job-only invite route for self sign-up (carlos-portal#16's follow-up).

The `signup-poll` job prepares and commits the one invite of a sign-up request it holds a lease on.
The identity proof is the request's own, the invite is tied to the request, and a match can only be
reported with it.
"""

import json
import logging
from datetime import date, timedelta

import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, select, text

from carlos_patient_portal.identity import verify_identity_proof
from carlos_patient_portal.models import (
    AUDIT_EVENT_SIGNUP_RESULT,
    AUDIT_EVENT_STAFF_ACTION,
    PatientPortalAccount,
    PatientPortalInvite,
    utc_now,
)
from carlos_patient_portal.system_jobs import (
    JOB_BOOKING_SYNC,
    PERMISSION_BOOKING_PROMPT_SYNC,
    PERMISSION_INVITE_MANAGE,
    PERMISSION_SIGNUP_MANAGE,
)
from tests.support import (
    IDENTITY_PROOF_SECRET,
    INTERNAL_API_TOKEN,
    carlos_staff_headers,
)
from tests.test_signup_claims import (
    CLAIM_PATH,
    CLINIC,
    FAKE_CARD_NORMALIZED,
    FAKE_DOB,
    FAKE_EMAIL,
    FAKE_HCN,
    alembic_config,
    audit_rows,
    claim,
    claimed,
    client_at,
    make_invite,
    post_job,
    recorded_results,
    report,
    sign_up,
    signup_app,
    store_requests,
    stored_rows,
    typed_identity,
    update_row,
)

KNOWN_DETAILS = {
    "not found",
    "permission denied",
    "sign-up request not found",
    "sign-up request lease expired",
    "sign-up request already has a result",
    "sign-up request invite conflicts",
    "sign-up request already has a different result",
    "sign-up result is invalid",
    "invite preparation unavailable",
    "portal account already exists",
    "pending invite already exists",
    "invite delivery conflicts",
}
PATIENT = 3100


def assert_known_error(response, details: set[str]) -> None:
    assert set(response.json()) == {"detail"}
    assert response.json()["detail"] in details


OPERATION = "op-signup-0001"
REFERENCE = "carlos-email-0001"


def prepare_path(request_id: int) -> str:
    return f"/internal/carlos/signup-requests/{request_id}/invite/prepare"


def commit_path(request_id: int) -> str:
    return f"/internal/carlos/signup-requests/{request_id}/invite/commit-delivery"


def invite_permission() -> dict[str, str]:
    return {"permission": PERMISSION_INVITE_MANAGE}


def prepare(
    client, request_id: int, token: str, *, patient: int = PATIENT, op: str = OPERATION, **o
):
    payload = {"lease_token": token, "demographic_no": patient, "delivery_operation_id": op}
    return post_job(client, prepare_path(request_id), payload, **{**invite_permission(), **o})


def commit(client, request_id: int, token: str, *, op: str = OPERATION, ref: str = REFERENCE, **o):
    payload = {"lease_token": token, "delivery_operation_id": op, "delivery_reference": ref}
    return post_job(client, commit_path(request_id), payload, **{**invite_permission(), **o})


def leased(app, count: int = 1):
    """`count` stored requests, leased by one claim: [(request id, lease token)]."""
    store_requests(app, count)
    client = client_at(app, "198.51.100.1")
    items = claimed(claim(client, count))
    return client, [(item["request_id"], item["lease_token"]) for item in items]


def invites(app) -> list[PatientPortalInvite]:
    with app.state.session_factory() as session:
        return list(session.scalars(select(PatientPortalInvite).order_by(PatientPortalInvite.id)))


# --------------------------------------------------------------------------------------------
# What it makes
# --------------------------------------------------------------------------------------------


def test_prepare_makes_the_requests_own_invite_with_the_identity_the_patient_typed() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)

    response = prepare(client, request_id, token)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "prepared"
    assert body["demographic_no"] == PATIENT
    assert body["delivery_operation_id"] == OPERATION
    assert body["created_by"] == "Patient self sign-up"
    assert body["created_by_id"] == "job:signup-poll"
    assert len(body["invite_token"]) > 20
    [invite] = invites(app)
    assert invite.id == body["id"]
    # Tied to the request: its id is on the request, and a match can only be reported with it.
    assert stored_rows(app)[0].prepared_invite_id == invite.id
    # The proof is the request's own, copied from what was typed: the activation's own comparison
    # accepts exactly those details against the invite's hashes, and no others.
    typed = typed_identity()
    assert verify_identity_proof(
        typed,
        IDENTITY_PROOF_SECRET,
        salt=invite.proof_salt,
        email_hash=invite.proof_email_hash,
        date_of_birth_hash=invite.proof_date_of_birth_hash,
        health_card_hash=invite.proof_health_card_hash,
    )
    for other in (
        typed_identity(email="someone.else@example.test"),
        typed_identity(date_of_birth=date(1975, 3, 15)),
        typed_identity(health_card_number="1111 222 333 AB"),
    ):
        assert not verify_identity_proof(
            other,
            IDENTITY_PROOF_SECRET,
            salt=invite.proof_salt,
            email_hash=invite.proof_email_hash,
            date_of_birth_hash=invite.proof_date_of_birth_hash,
            health_card_hash=invite.proof_health_card_hash,
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"email": "chart.address@example.test"},
        {"date_of_birth": "1980-01-01"},
        {"health_card_number": "1111 222 333"},
        {"identity_proof": {"email": "x@example.test"}},
        {"invite_id": 1},
        {"clinic_id": "other"},
    ],
)
def test_the_caller_can_name_the_patient_but_never_the_identity_or_an_invite(extra) -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)

    response = post_job(
        client,
        prepare_path(request_id),
        {"lease_token": token, "demographic_no": PATIENT, "delivery_operation_id": OPERATION}
        | extra,
        **invite_permission(),
    )

    assert response.status_code == 422
    assert invites(app) == []


def test_preparing_again_with_the_same_operation_returns_the_same_invite_and_token() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    first = prepare(client, request_id, token)

    again = prepare(client, request_id, token)

    assert again.status_code == 201
    assert again.json()["id"] == first.json()["id"]
    assert again.json()["invite_token"] == first.json()["invite_token"]
    assert len(invites(app)) == 1


def test_a_request_has_one_invite_another_operation_for_it_is_a_conflict() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    assert prepare(client, request_id, token).status_code == 201

    other = prepare(client, request_id, token, op="op-signup-0002")
    other_patient = prepare(client, request_id, token, patient=PATIENT + 1)

    assert (other.status_code, other.json()) == (
        409,
        {"detail": "sign-up request invite conflicts"},
    )
    # The same operation for another patient is the invite layer's own conflict.
    assert (other_patient.status_code, other_patient.json()) == (
        409,
        {"detail": "invite preparation conflicts"},
    )
    assert len(invites(app)) == 1


def test_a_reused_operation_of_another_request_is_a_conflict_and_writes_nothing() -> None:
    app = signup_app()
    # Two requests with the very same typed details (the portal allows a few per health card).
    for address in ("203.0.113.10", "203.0.113.11"):
        assert sign_up(client_at(app, address)).status_code == 202
    client = client_at(app, "198.51.100.1")
    (first, first_token), (second, second_token) = [
        (item["request_id"], item["lease_token"]) for item in claimed(claim(client, 2))
    ]
    first_answer = prepare(client, first, first_token)
    assert first_answer.status_code == 201
    [invite] = invites(app)
    owners = {row.id: row.prepared_invite_id for row in stored_rows(app)}
    disclosures = len(audit_rows(AUDIT_EVENT_STAFF_ACTION))

    # The second request reuses the first one's operation id, for the same patient and details.
    reused = prepare(client, second, second_token)

    assert (reused.status_code, reused.json()) == (
        409,
        {"detail": "sign-up request invite conflicts"},
    )
    assert "invite_token" not in reused.text
    # Nothing changed: one invite, still the first request's, no second owner, and no token was
    # disclosed again (that is an audit row of its own).
    assert [(row.id, row.status) for row in invites(app)] == [(invite.id, invite.status)]
    assert {row.id: row.prepared_invite_id for row in stored_rows(app)} == owners
    assert len(audit_rows(AUDIT_EVENT_STAFF_ACTION)) == disclosures
    # The first request still recovers its own invite and token.
    again = prepare(client, first, first_token)
    assert (again.status_code, again.json()["id"]) == (201, invite.id)
    assert again.json()["invite_token"] == first_answer.json()["invite_token"]


def test_commit_releases_the_requests_own_invite_and_nothing_else() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    prepared = prepare(client, request_id, token).json()

    response = commit(client, request_id, token)

    assert response.status_code == 200, response.text
    body = response.json()
    assert (body["id"], body["status"], body["delivery_reference"]) == (
        prepared["id"],
        "pending",
        REFERENCE,
    )
    # The route names no invite: a payload that does is refused outright.
    assert (
        post_job(
            client,
            commit_path(request_id),
            {
                "lease_token": token,
                "delivery_operation_id": OPERATION,
                "delivery_reference": REFERENCE,
                "invite_id": prepared["id"] + 1,
            },
            **invite_permission(),
        ).status_code
        == 422
    )


def test_commit_before_prepare_or_for_another_operation_is_a_conflict() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)

    unprepared = commit(client, request_id, token)
    assert prepare(client, request_id, token).status_code == 201
    wrong_operation = commit(client, request_id, token, op="op-signup-0002")

    assert unprepared.status_code == 409
    assert unprepared.json() == {"detail": "sign-up request invite conflicts"}
    assert wrong_operation.status_code == 409
    assert wrong_operation.json() == {"detail": "invite delivery conflicts"}
    assert invites(app)[0].status == "prepared"


def test_the_whole_flow_from_claim_to_a_reported_match() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    invite_id = prepare(client, request_id, token).json()["id"]
    assert commit(client, request_id, token).status_code == 200

    result = report(client, request_id, token, "matched", invite_id)

    assert result.status_code == 200
    assert result.json() == {
        "request_id": request_id,
        "result": "matched",
        "invite_id": invite_id,
        "recorded": True,
    }
    row = stored_rows(app)[0]
    assert (row.result, row.prepared_invite_id, row.encrypted_payload) == (
        "matched",
        invite_id,
        None,
    )
    assert [event.invite_id for event in recorded_results(app)] == [invite_id]


def test_a_match_can_only_be_reported_with_the_invite_prepared_for_the_request() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    prepared = prepare(client, request_id, token).json()["id"]
    assert commit(client, request_id, token).status_code == 200
    # Live, and made for exactly these details, but not this request's own.
    other = make_invite(app, for_request=None)

    refused = report(client, request_id, token, "matched", other)
    accepted = report(client, request_id, token, "matched", prepared)

    assert refused.status_code == 422
    assert refused.json() == {"detail": "sign-up result is invalid"}
    assert accepted.status_code == 200


# --------------------------------------------------------------------------------------------
# Who may call, and for which request
# --------------------------------------------------------------------------------------------


def test_only_the_signup_job_claiming_the_invite_permission_may_use_it() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    body = json.dumps(
        {"lease_token": token, "demographic_no": PATIENT, "delivery_operation_id": OPERATION}
    ).encode()
    path = prepare_path(request_id)

    # Staff holding the invite right (which the staff invite routes take) never reach it.
    for permissions in (
        (PERMISSION_INVITE_MANAGE,),
        (PERMISSION_INVITE_MANAGE, PERMISSION_SIGNUP_MANAGE),
    ):
        headers = carlos_staff_headers(*permissions, clinic_id=CLINIC, token=INTERNAL_API_TOKEN)
        refused = client.post(
            path, content=body, headers={**headers, "Content-Type": "application/json"}
        )
        assert refused.status_code in {403, 404}, permissions
        assert_known_error(refused, KNOWN_DETAILS)
    # Another job, and this job with the claim permission, are refused.
    assert (
        prepare(
            client,
            request_id,
            token,
            job=JOB_BOOKING_SYNC,
            permission=PERMISSION_BOOKING_PROMPT_SYNC,
        ).status_code
        == 404
    )
    wrong = prepare(client, request_id, token, permission=PERMISSION_SIGNUP_MANAGE)
    assert wrong.status_code == 403
    assert_known_error(wrong, KNOWN_DETAILS)
    assert commit(client, request_id, token, permission=PERMISSION_SIGNUP_MANAGE).status_code == 403
    assert invites(app) == []
    # And the sign-up routes still refuse the invite permission.
    assert post_job(client, CLAIM_PATH, {}, **invite_permission()).status_code == 403


def test_only_a_request_the_caller_holds_a_lease_on_can_have_an_invite() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    store_requests(app, 1, first_card=9000000000)  # request 2, never leased
    store_requests(app, 1, first_card=9100000000)  # request 3, another clinic's
    update_row(app, 3, clinic_id="clinic-b")

    attempts = [
        prepare(client, 999, token),
        prepare(client, request_id, "A" * 43),
        prepare(client, 2, token),
        prepare(client, 3, token),
    ]
    commits = [
        commit(client, 999, token),
        commit(client, request_id, "A" * 43),
        commit(client, 2, token),
        commit(client, 3, token),
    ]

    # One answer for an unknown id, a wrong token, a request never leased and another clinic's.
    for response in attempts + commits:
        assert response.status_code == 404
        assert (
            response.content
            == json.dumps({"detail": "sign-up request not found"}, separators=(",", ":")).encode()
        )
    assert invites(app) == []
    # Each refusal is on the audit trail with its real reason, which the caller is never told.
    reasons = [row.reason for row in audit_rows(app, AUDIT_EVENT_SIGNUP_RESULT)]
    assert reasons.count("request_not_found") == 4
    assert reasons.count("lease_token_mismatch") == 4


def test_an_expired_lease_a_reported_request_and_a_lost_lease_are_refused() -> None:
    app = signup_app()
    client, [(first, token_one), (second, token_two)] = leased(app, 2)
    # Request 1: reported (so closed). Request 2: the lease runs out.
    assert report(client, first, token_one, "no_match").status_code == 200
    update_row(app, second, lease_expires_at=utc_now() - timedelta(seconds=1))

    closed = prepare(client, first, token_one)
    expired = prepare(client, second, token_two)
    closed_commit = commit(client, first, token_one)
    expired_commit = commit(client, second, token_two)

    assert (closed.status_code, closed.json()) == (
        409,
        {"detail": "sign-up request already has a result"},
    )
    assert (closed_commit.status_code, closed_commit.json()) == (
        409,
        {"detail": "sign-up request already has a result"},
    )
    for response in (expired, expired_commit):
        assert response.status_code == 409
        assert response.json() == {"detail": "sign-up request lease expired"}
    assert invites(app) == []
    # Claimed again, the request can have its invite under the new lease.
    reclaimed = claimed(claim(client))[0]
    assert prepare(client, second, reclaimed["lease_token"]).status_code == 201


def test_the_patient_must_not_already_have_an_account_or_a_pending_invite() -> None:
    app = signup_app()
    client, [(first, token_one), (second, token_two)] = leased(app, 2)
    with app.state.session_factory() as session, session.begin():
        session.add(
            PatientPortalAccount(
                clinic_id=CLINIC,
                demographic_no=PATIENT,
                username="fake.patient",
                email=FAKE_EMAIL,
                password_hash="x" * 60,
                status="active",
            )
        )
    has_account = prepare(client, first, token_one)
    pending_invite = make_invite(app, for_request=None)  # a staff invite for another patient
    with app.state.session_factory() as session, session.begin():
        invite = session.get(PatientPortalInvite, pending_invite)
        patient = invite.demographic_no
    has_pending = prepare(client, second, token_two, patient=patient)

    assert (has_account.status_code, has_account.json()) == (
        409,
        {"detail": "portal account already exists"},
    )
    assert (has_pending.status_code, has_pending.json()) == (
        409,
        {"detail": "pending invite already exists"},
    )
    assert [row.prepared_invite_id for row in stored_rows(app)] == [None, None]


def test_details_that_cannot_be_read_make_no_invite() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    update_row(app, request_id, encrypted_payload=b"x" * 64)

    response = prepare(client, request_id, token)

    assert response.status_code == 503
    assert response.json() == {"detail": "invite preparation unavailable"}
    assert invites(app) == []


def test_nothing_identifying_reaches_the_audit_trail_or_the_logs(caplog) -> None:
    caplog.set_level(logging.DEBUG)
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    prepared = prepare(client, request_id, token)
    commit(client, request_id, token)
    prepare(client, request_id, "A" * 43)  # a refusal

    everything = json.dumps(
        [
            {column.name: str(getattr(row, column.name)) for column in row.__table__.columns}
            for row in audit_rows(app)
        ]
    )
    for secret in (
        FAKE_EMAIL,
        FAKE_CARD_NORMALIZED,
        FAKE_HCN,
        FAKE_DOB,
        token,
        prepared.json()["invite_token"],
    ):
        assert secret not in everything
        assert secret not in caplog.text


# --------------------------------------------------------------------------------------------
# Who the audit trail says made the invite
# --------------------------------------------------------------------------------------------


def test_an_invite_the_job_makes_is_audited_as_the_system_never_as_staff() -> None:
    app = signup_app()
    client, [(request_id, token)] = leased(app)
    assert prepare(client, request_id, token).status_code == 201
    # A retry that is handed the same token again is audited too.
    assert prepare(client, request_id, token).status_code == 201
    assert commit(client, request_id, token).status_code == 200

    [invite] = invites(app)
    rows = [row for row in audit_rows(app) if row.invite_id == invite.id]
    # Preparation, its token handed out again, and the delivery that released it.
    assert len(rows) >= 3
    for row in rows:
        assert row.actor_type == "system", (row.event_type, row.reason)
        assert row.actor_id == "job:signup-poll"
        assert row.actor == "Patient self sign-up"
    assert not [row for row in audit_rows(app) if row.actor_type == "staff"]


def test_the_invite_layer_keeps_staff_as_the_default_and_takes_only_staff_or_system() -> None:
    from carlos_patient_portal.invites import activate_prepared_invite, prepare_create_invite

    app = signup_app()
    keys = {"primary": "k" * 32}

    def prepare_as(actor_type: str | None, operation: str, demographic_no: int):
        extra = {} if actor_type is None else {"actor_type": actor_type}
        with app.state.session_factory() as session, session.begin():
            invite, _token = prepare_create_invite(
                session,
                demographic_no,
                "Front Desk",
                delivery_operation_id=operation,
                identity_proof=typed_identity(),
                proof_secret=IDENTITY_PROOF_SECRET,
                encryption_secret="k" * 32,
                encryption_key_id="primary",
                encryption_keys=keys,
                clinic_id=CLINIC,
                **extra,
            )
            return invite.id

    staff_id = prepare_as(None, "op-staff", 7001)
    system_id = prepare_as("system", "op-system", 7002)
    by_invite = {row.invite_id: row.actor_type for row in audit_rows(app)}
    assert by_invite[staff_id] == "staff"
    assert by_invite[system_id] == "system"
    for refused in ("patient", "", "STAFF", "job"):
        with pytest.raises(ValueError, match="staff or system"):
            prepare_as(refused, f"op-{refused}", 7003)
    with pytest.raises(ValueError, match="staff or system"):
        with app.state.session_factory() as session, session.begin():
            activate_prepared_invite(
                session,
                system_id,
                delivery_operation_id="op-system",
                delivery_reference="ref",
                clinic_id=CLINIC,
                actor="Front Desk",
                actor_type="patient",
            )


# --------------------------------------------------------------------------------------------
# One request per invite
# --------------------------------------------------------------------------------------------


def test_two_requests_can_never_share_a_prepared_invite() -> None:
    from sqlalchemy.exc import IntegrityError

    app = signup_app()
    client, [(first, first_token), (second, _second_token)] = leased(app, 2)
    assert prepare(client, first, first_token).status_code == 201
    [invite] = invites(app)
    assert {row.id: row.prepared_invite_id for row in stored_rows(app)}[first] == invite.id

    with pytest.raises(IntegrityError):
        update_row(app, second, prepared_invite_id=invite.id)
    # Requests that hold none do not collide with each other.
    assert [row.prepared_invite_id for row in stored_rows(app)].count(None) == 1


# --------------------------------------------------------------------------------------------
# The migration
# --------------------------------------------------------------------------------------------


def test_the_migration_round_trips_and_refuses_a_downgrade_over_a_prepared_invite(tmp_path) -> None:
    url = f"sqlite+pysqlite:///{tmp_path / 'invite.db'}"
    config = alembic_config(url)
    command.upgrade(config, "0026_mycarlos_push_handles")
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
        columns = {c["name"] for c in inspect(engine).get_columns("patient_portal_signup_requests")}
        assert "prepared_invite_id" in columns
        indexes = {
            i["name"]: i for i in inspect(engine).get_indexes("patient_portal_signup_requests")
        }
        assert indexes["uq_pp_signup_requests_prepared_invite"]["unique"]
        with engine.begin() as connection:
            connection.execute(
                text("update patient_portal_signup_requests set prepared_invite_id = 5")
            )
        with pytest.raises(RuntimeError, match="hold a prepared invite"):
            command.downgrade(config, "0026_mycarlos_push_handles")
        with engine.begin() as connection:
            connection.execute(
                text("update patient_portal_signup_requests set prepared_invite_id = null")
            )
        command.downgrade(config, "0026_mycarlos_push_handles")
        columns = {c["name"] for c in inspect(engine).get_columns("patient_portal_signup_requests")}
        assert "prepared_invite_id" not in columns
        command.upgrade(config, "head")
    finally:
        engine.dispose()
