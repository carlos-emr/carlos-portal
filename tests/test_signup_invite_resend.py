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

"""A new code for the invite a sign-up patient already holds (the job-only resend).

The sign-up job may ask for a new code for the patient's pending invite, once the cool-down has
passed (measured by the portal's clock), for a request it holds a lease on, and only when the invite
carries exactly the details that request holds. The old code works until the delivery of the new
one is committed, then stops; the replacement becomes the request's own invite, and a match can
still only be reported with the invite that belongs to the request.
"""

import json
from datetime import timedelta

from sqlalchemy import select

from carlos_patient_portal.identity import verify_identity_proof
from carlos_patient_portal.invites import hash_invite_token
from carlos_patient_portal.models import (
    INVITE_STATUS_PENDING,
    INVITE_STATUS_PREPARED,
    INVITE_STATUS_SUPERSEDED,
    PatientPortalInvite,
    utc_now,
)
from carlos_patient_portal.system_jobs import (
    JOB_BOOKING_SYNC,
    PERMISSION_BOOKING_PROMPT_SYNC,
    PERMISSION_INVITE_MANAGE,
    PERMISSION_SIGNUP_MANAGE,
)
from tests.support import IDENTITY_PROOF_SECRET, INTERNAL_API_TOKEN, carlos_staff_headers
from tests.test_signup_claims import (
    CLINIC,
    audit_rows,
    claim,
    claimed,
    client_at,
    post_job,
    report,
    sign_up,
    signup_app,
    stored_rows,
    typed_identity,
    update_row,
)
from tests.test_signup_invite import (
    KNOWN_DETAILS,
    OPERATION,
    PATIENT,
    assert_known_error,
    commit,
    invite_permission,
    invites,
    leased,
    prepare,
)

RESEND_OPERATION = "op-signup-resend-0001"
RESEND_REFERENCE = "carlos-email-resend-0001"
COOLDOWN = timedelta(minutes=30)


def resend_path(request_id: int) -> str:
    return f"/internal/carlos/signup-requests/{request_id}/invite/resend"


def resend_commit_path(request_id: int) -> str:
    return f"/internal/carlos/signup-requests/{request_id}/invite/resend/commit-delivery"


def resend(client, request_id: int, token: str, *, op: str = RESEND_OPERATION, **o):
    payload = {"lease_token": token, "demographic_no": PATIENT, "delivery_operation_id": op}
    return post_job(client, resend_path(request_id), payload, **{**invite_permission(), **o})


def resend_commit(
    client,
    request_id: int,
    token: str,
    *,
    op: str = RESEND_OPERATION,
    ref: str = RESEND_REFERENCE,
    **o,
):
    payload = {"lease_token": token, "delivery_operation_id": op, "delivery_reference": ref}
    return post_job(client, resend_commit_path(request_id), payload, **{**invite_permission(), **o})


def sent_invite(app, count: int = 1):
    """`count` leased requests; the first has its own invite prepared and delivered."""
    client, leases = leased(app, count)
    (request_id, token) = leases[0]
    assert prepare(client, request_id, token).status_code == 201
    assert commit(client, request_id, token).status_code == 200
    return client, leases


def backdate(app, invite_id: int, ago: timedelta) -> None:
    with app.state.session_factory() as session, session.begin():
        session.get(PatientPortalInvite, invite_id).last_sent_at = utc_now() - ago


def by_id(app) -> dict[int, PatientPortalInvite]:
    return {invite.id: invite for invite in invites(app)}


# --------------------------------------------------------------------------------------------
# The cool-down
# --------------------------------------------------------------------------------------------


def test_inside_the_cooldown_nothing_is_prepared_and_the_wait_is_told() -> None:
    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)

    response = resend(client, request_id, token)

    assert response.status_code == 429
    assert response.json() == {"detail": "invite resend too soon"}
    wait = int(response.headers["Retry-After"])
    assert 1 <= wait <= COOLDOWN.total_seconds()
    assert len(invites(app)) == 1


def test_the_wait_is_measured_by_the_portals_own_clock_from_when_it_was_sent() -> None:
    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)

    backdate(app, original.id, COOLDOWN - timedelta(minutes=5))
    wait = int(resend(client, request_id, token).headers["Retry-After"])
    # About five minutes are left, whatever CARLOS thinks the time is.
    assert 250 <= wait <= 300

    backdate(app, original.id, COOLDOWN + timedelta(seconds=5))
    assert resend(client, request_id, token).status_code == 201


def test_the_cooldown_comes_from_the_setting() -> None:
    app = signup_app(self_signup_invite_resend_cooldown_seconds=120)
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)
    backdate(app, original.id, timedelta(seconds=90))
    assert resend(client, request_id, token).status_code == 429
    backdate(app, original.id, timedelta(seconds=130))
    assert resend(client, request_id, token).status_code == 201


# --------------------------------------------------------------------------------------------
# What a resend does
# --------------------------------------------------------------------------------------------


def test_the_old_code_works_until_the_delivery_is_committed_then_the_new_one_replaces_it() -> None:
    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)
    old_hash = original.token_hash
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))

    prepared = resend(client, request_id, token)

    assert prepared.status_code == 201, prepared.text
    body = prepared.json()
    assert body["status"] == "prepared"
    assert body["demographic_no"] == PATIENT
    assert body["created_by"] == "Patient self sign-up"
    assert body["created_by_id"] == "job:signup-poll"
    new_token = body["invite_token"]
    assert len(new_token) > 20
    rows = by_id(app)
    assert rows[original.id].status == INVITE_STATUS_PENDING  # the old code still works
    replacement = rows[body["id"]]
    assert replacement.status == INVITE_STATUS_PREPARED
    assert replacement.supersedes_invite_id == original.id
    assert replacement.token_hash == hash_invite_token(new_token) != old_hash
    # The request still holds the old invite until the new one is released.
    assert stored_rows(app)[0].prepared_invite_id == original.id

    released = resend_commit(client, request_id, token)

    assert released.status_code == 200, released.text
    assert (released.json()["id"], released.json()["status"]) == (replacement.id, "pending")
    rows = by_id(app)
    assert rows[original.id].status == INVITE_STATUS_SUPERSEDED  # the old code no longer works
    assert rows[original.id].token_hash == old_hash
    assert rows[replacement.id].status == INVITE_STATUS_PENDING
    assert rows[replacement.id].delivery_reference == RESEND_REFERENCE
    assert rows[replacement.id].last_sent_at is not None
    # One live invite, and it is the request's own now.
    assert [r.status for r in rows.values()].count(INVITE_STATUS_PENDING) == 1
    assert stored_rows(app)[0].prepared_invite_id == replacement.id
    # It carries exactly what the patient typed, copied from the invite it replaces.
    assert verify_identity_proof(
        typed_identity(),
        IDENTITY_PROOF_SECRET,
        salt=replacement.proof_salt,
        email_hash=replacement.proof_email_hash,
        date_of_birth_hash=replacement.proof_date_of_birth_hash,
        health_card_hash=replacement.proof_health_card_hash,
    )


def test_a_match_is_reported_with_the_invite_that_belongs_to_the_request_now() -> None:
    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))
    replacement_id = resend(client, request_id, token).json()["id"]
    assert resend_commit(client, request_id, token).status_code == 200

    # The retired invite can no longer stand for the request; the replacement can.
    refused = report(client, request_id, token, "matched", original.id)
    assert refused.status_code == 422
    assert report(client, request_id, token, "matched", replacement_id).status_code == 200


def test_preparing_and_committing_again_return_the_same_invite_and_token() -> None:
    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))

    first = resend(client, request_id, token)
    again = resend(client, request_id, token)
    assert again.status_code == 201
    assert (again.json()["id"], again.json()["invite_token"]) == (
        first.json()["id"],
        first.json()["invite_token"],
    )
    assert len(invites(app)) == 2

    one = resend_commit(client, request_id, token)
    two = resend_commit(client, request_id, token)
    assert (one.status_code, two.status_code) == (200, 200)
    assert one.json()["id"] == two.json()["id"]
    assert resend_commit(client, request_id, token, ref="another-reference").status_code == 409


def test_every_audit_row_of_the_resend_names_the_system() -> None:
    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))
    assert resend(client, request_id, token).status_code == 201
    assert resend_commit(client, request_id, token).status_code == 200

    invite_rows = [row for row in audit_rows(app) if row.invite_id is not None]
    assert len(invite_rows) >= 5  # first invite (2 or more), the resend and the retired original
    for row in invite_rows:
        assert row.actor_type == "system", (row.event_type, row.reason)
        assert row.actor_id == "job:signup-poll"


# --------------------------------------------------------------------------------------------
# What it refuses
# --------------------------------------------------------------------------------------------


def test_a_repeat_request_with_the_same_details_adopts_the_replacement_of_the_first_invite() -> (
    None
):
    app = signup_app()
    # Two requests with the very same details (the portal allows a few per health card).
    for address in ("203.0.113.10", "203.0.113.11"):
        assert sign_up(client_at(app, address)).status_code == 202
    client = client_at(app, "198.51.100.1")
    leases = [(item["request_id"], item["lease_token"]) for item in claimed(claim(client, 2))]
    (first, first_token), (second, second_token) = leases
    # The first request had its invite made and its match reported.
    assert prepare(client, first, first_token).status_code == 201
    assert commit(client, first, first_token).status_code == 200
    [original] = invites(app)
    assert report(client, first, first_token, "matched", original.id).status_code == 200
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))

    # The repeat asks for a new code for that invite.
    prepared = resend(client, second, second_token)
    assert prepared.status_code == 201, prepared.text
    assert resend_commit(client, second, second_token).status_code == 200

    owners = {row.id: row.prepared_invite_id for row in stored_rows(app)}
    replacement_id = prepared.json()["id"]
    assert owners == {first: original.id, second: replacement_id}
    rows = by_id(app)
    assert rows[original.id].status == INVITE_STATUS_SUPERSEDED
    assert rows[replacement_id].status == INVITE_STATUS_PENDING
    # The repeat reports its match with the replacement, the first request's report stands.
    assert report(client, second, second_token, "matched", original.id).status_code == 422
    assert report(client, second, second_token, "matched", replacement_id).status_code == 200


def test_a_replacement_a_staff_member_prepared_is_never_released_as_the_systems() -> None:
    from carlos_patient_portal.invites import prepare_resend_invite

    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))
    with app.state.session_factory() as session, session.begin():
        prepare_resend_invite(
            session,
            original.id,
            "Front Desk",
            delivery_operation_id=RESEND_OPERATION,
            encryption_secret="k" * 32,
            encryption_key_id="primary",
            encryption_keys={"primary": "k" * 32},
            clinic_id=CLINIC,
        )

    refused = resend_commit(client, request_id, token)

    assert refused.status_code == 409
    assert refused.json() == {"detail": "sign-up request invite conflicts"}
    assert by_id(app)[original.id].status == INVITE_STATUS_PENDING


def test_another_persons_invite_and_no_invite_are_the_same_refusal() -> None:
    app = signup_app()
    client, [(first, first_token), (second, second_token)] = sent_invite(app, 2)
    [original] = invites(app)
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))

    # The second request holds other details (another health card): the patient's invite is not
    # its person's, and the answer is the same as for a patient with no invite at all.
    other = resend(client, second, second_token)
    assert other.status_code == 409
    assert other.json() == {"detail": "sign-up request invite conflicts"}
    nothing = post_job(
        client,
        resend_path(second),
        {
            "lease_token": second_token,
            "demographic_no": PATIENT + 1,
            "delivery_operation_id": "op-x",
        },
        **invite_permission(),
    )
    assert nothing.status_code == 409
    assert nothing.json() == other.json()
    assert len(invites(app)) == 1


def test_a_revoked_invite_cannot_be_resent_and_the_answer_is_the_same_refusal() -> None:
    from carlos_patient_portal.invites import revoke_invite

    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))
    with app.state.session_factory() as session, session.begin():
        revoke_invite(session, original.id, "Front Desk", clinic_id=CLINIC)

    response = resend(client, request_id, token)

    assert response.status_code == 409
    assert response.json() == {"detail": "sign-up request invite conflicts"}
    assert len(invites(app)) == 1


def test_committing_needs_a_replacement_prepared_for_this_request() -> None:
    app = signup_app()
    client, [(first, first_token), (second, second_token)] = sent_invite(app, 2)
    [original] = invites(app)
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))
    assert resend(client, first, first_token).status_code == 201

    # No replacement was prepared for this operation; another request's cannot be committed; a
    # first invite's operation is not a resend.
    assert resend_commit(client, first, first_token, op="op-unknown").status_code == 409
    assert resend_commit(client, second, second_token).status_code == 409
    assert resend_commit(client, first, first_token, op=OPERATION).status_code == 409
    assert by_id(app)[original.id].status == INVITE_STATUS_PENDING
    assert stored_rows(app)[0].prepared_invite_id == original.id


def test_only_the_signup_job_with_the_invite_permission_and_a_running_lease_may_resend() -> None:
    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))
    body = json.dumps(
        {
            "lease_token": token,
            "demographic_no": PATIENT,
            "delivery_operation_id": RESEND_OPERATION,
        }
    ).encode()

    for permissions in (
        (PERMISSION_INVITE_MANAGE,),
        (PERMISSION_INVITE_MANAGE, PERMISSION_SIGNUP_MANAGE),
    ):
        headers = carlos_staff_headers(*permissions, clinic_id=CLINIC, token=INTERNAL_API_TOKEN)
        for path in (resend_path(request_id), resend_commit_path(request_id)):
            refused = client.post(
                path, content=body, headers={**headers, "Content-Type": "application/json"}
            )
            assert refused.status_code in {403, 404}, permissions
            assert_known_error(refused, KNOWN_DETAILS | {"invite resend too soon"})
    assert (
        resend(
            client,
            request_id,
            token,
            job=JOB_BOOKING_SYNC,
            permission=PERMISSION_BOOKING_PROMPT_SYNC,
        ).status_code
        == 404
    )
    wrong = resend(client, request_id, token, permission=PERMISSION_SIGNUP_MANAGE)
    assert wrong.status_code == 403
    assert (
        resend_commit(client, request_id, token, permission=PERMISSION_SIGNUP_MANAGE).status_code
        == 403
    )
    assert resend(client, request_id, "x" * 43).status_code == 404
    # A lease that ran out, and a request that has its result, are refused.
    update_row(app, request_id, lease_expires_at=utc_now() - timedelta(seconds=1))
    assert resend(client, request_id, token).status_code == 409
    assert resend(client, request_id, token).json() == {"detail": "sign-up request lease expired"}
    update_row(app, request_id, lease_expires_at=utc_now() + timedelta(minutes=5))
    assert report(client, request_id, token, "no_match").status_code == 200
    closed = resend(client, request_id, token)
    assert closed.status_code == 409
    assert closed.json() == {"detail": "sign-up request already has a result"}
    assert resend_commit(client, request_id, token).status_code == 409
    assert len(invites(app)) == 1


def test_the_caller_can_name_the_patient_but_never_the_identity_or_an_invite() -> None:
    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    for extra in ({"email": "x@example.test"}, {"invite_id": 1}, {"identity_proof": {}}):
        payload = {
            "lease_token": token,
            "demographic_no": PATIENT,
            "delivery_operation_id": RESEND_OPERATION,
            **extra,
        }
        assert (
            post_job(client, resend_path(request_id), payload, **invite_permission()).status_code
            == 422
        )
    commit_payload = {
        "lease_token": token,
        "delivery_operation_id": RESEND_OPERATION,
        "delivery_reference": RESEND_REFERENCE,
        "invite_id": 1,
    }
    assert (
        post_job(
            client, resend_commit_path(request_id), commit_payload, **invite_permission()
        ).status_code
        == 422
    )


def test_a_resend_leaves_no_detail_in_the_answers_or_the_audit_trail(caplog) -> None:
    app = signup_app()
    client, [(request_id, token)] = sent_invite(app)
    [original] = invites(app)
    backdate(app, original.id, COOLDOWN + timedelta(minutes=1))
    prepared = resend(client, request_id, token)
    resend_commit(client, request_id, token)
    secrets = ["example.test", "9876543210", "1980", token, prepared.json()["invite_token"]]
    haystack = repr([(r.reason, r.resource_id, r.actor) for r in audit_rows(app)]) + caplog.text
    for secret in secrets:
        assert secret not in haystack
    with app.state.session_factory() as session:
        assert len(list(session.scalars(select(PatientPortalInvite)))) == 2
