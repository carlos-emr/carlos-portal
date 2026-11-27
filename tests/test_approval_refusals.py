# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""What the device-approval routes refuse, and with which code (FAKE contract fixtures only)."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import func, select

from carlos_patient_portal import mailbox
from carlos_patient_portal.approval_models import ApprovalRequest
from carlos_patient_portal.mailbox_codec import MailboxRefusal
from carlos_patient_portal.models import PatientPortalMyCarlosDevice
from tests import delivery_contract_reference as ref
from tests.test_approval_http import (
    FLOW,
    INTERNAL,
    KEY,
    PRIVATE,
    PUBLIC,
    REQUEST,
    F,
    body,
    device_headers,
    job_headers,
    make_approval_http,
    post_intent,
    put_challenge,
)


@pytest.fixture
def approval_http(monkeypatch):
    return make_approval_http(monkeypatch)


def signed_intent(private=PRIVATE, **changes):
    """The fixture's intent with `changes`, signed by the device's own FAKE key."""
    claims = dict(FLOW["intent"]["claims"]) | changes
    return ref.compact_ed25519(private, claims)


def post(client, intent):
    raw = body({"intent": intent})
    return client.post(PUBLIC, content=raw, headers=device_headers(PUBLIC, "POST", raw))


def code(response):
    return response.json().get("code")


def test_a_request_id_cannot_be_reused_for_a_different_intent(approval_http):
    _, client = approval_http
    assert post_intent(client).status_code == 201
    changed = signed_intent(iat=FLOW["intent"]["claims"]["iat"] + 1)
    refused = post(client, changed)
    assert (refused.status_code, code(refused)) == (409, "approval_conflict")
    # The first request is unchanged, and still answers an exact retry.
    assert post_intent(client).status_code == 200


def test_an_intent_naming_another_device_than_the_one_signing_the_request_is_a_conflict(
    approval_http,
):
    _, client = approval_http
    other = F["keys"]["candidate"]
    other_private = ref.private_key_from_seed_text(other["ed25519_seed_text"], "ed25519")
    intent = signed_intent(
        private=other_private,
        candidate_device_key_id=other["device_key_id"],
        candidate_ed25519_public_key=other["ed25519_public_key"],
        candidate_x25519_public_key=other["x25519_public_key"],
    )
    refused = post(client, intent)
    assert (refused.status_code, code(refused)) == (409, "approval_conflict")


def test_an_intent_that_has_already_ended_is_expired_and_stores_nothing(approval_http):
    app, client = approval_http
    now = F["now"]
    refused = post(client, signed_intent(iat=now - 1200, exp=now - 600, request_id=str(uuid4())))
    assert (refused.status_code, code(refused)) == (410, "approval_expired")
    # Nor one that begins well after this portal's clock.
    refused = post(client, signed_intent(iat=now + 500, exp=now + 600, request_id=str(uuid4())))
    assert (refused.status_code, code(refused)) == (410, "approval_expired")
    listing = client.get(INTERNAL, headers=job_headers(INTERNAL, "requests.read"))
    assert listing.json()["requests"] == []


def test_a_device_that_asks_too_often_is_told_to_wait(approval_http):
    _, client = approval_http
    statuses = []
    for _ in range(7):
        statuses.append(post(client, signed_intent(request_id=str(uuid4()))).status_code)
    # The sixth request in the window is the first one told to wait, and it stays refused.
    assert statuses == [201] * 5 + [429] * 2


def test_reading_a_request_that_is_not_there_or_not_asked_properly_says_not_found(approval_http):
    _, client = approval_http
    assert post_intent(client).status_code == 201
    for path in (
        PUBLIC + "/" + str(uuid4()),
        PUBLIC + "/not-a-uuid",
        PUBLIC + "/" + REQUEST + "?extra=1",
    ):
        read = client.get(path, headers=device_headers(path))
        assert read.status_code == 404, path
    # A GET that carries a body is refused as too large: a read has none.
    path = PUBLIC + "/" + REQUEST
    carried = client.request("GET", path, content=b"{}", headers=device_headers(path, raw=b"{}"))
    assert carried.status_code == 413


def test_an_approval_for_a_challenge_nobody_issued_is_not_found(approval_http):
    _, client = approval_http
    challenge = FLOW["challenge"]["claims"]["challenge_id"]
    path = PUBLIC.replace("device-approval-requests", "device-approvals") + "/" + challenge
    raw = body({"approval": "FAKE.approval"})
    missing = client.post(path, content=raw, headers=device_headers(path, "POST", raw))
    assert missing.status_code == 404
    bad = PUBLIC.replace("device-approval-requests", "device-approvals") + "/not-a-challenge-id"
    refused = client.post(bad, content=raw, headers=device_headers(bad, "POST", raw))
    assert refused.status_code == 400


def test_a_request_signed_for_another_recipient_is_refused(approval_http):
    _, client = approval_http
    assert post_intent(client).status_code == 201
    path = PUBLIC + "/" + REQUEST
    claims = {
        "aud": ref.DEVICE_AUDIENCE,
        "iss": "mycarlos",
        "kid": KEY["device_key_id"],
        "recipient_id": "FAKE-someone-else",
        "jti": str(uuid4()),
        "iat": F["now"],
        "exp": F["now"] + 60,
        "request_hash": ref.request_hash("GET", path.encode(), b"", b""),
    }
    wrong = client.get(
        path,
        headers={
            "X-MyCarlos-Device-Assertion": ref.compact_ed25519(PRIVATE, claims),
            "Content-Type": "application/json",
        },
    )
    assert (wrong.status_code, code(wrong)) == (403, "recipient_mismatch")


def test_a_removed_device_is_told_so(approval_http):
    app, client = approval_http
    assert post_intent(client).status_code == 201
    path = PUBLIC + "/" + REQUEST
    with app.state.session_factory() as s, s.begin():
        device = s.scalar(select(PatientPortalMyCarlosDevice))
        device.status, device.removed_by = "removed", "staff"
        device.removed_at = datetime.fromtimestamp(F["now"], UTC)
    removed = client.get(path, headers=device_headers(path))
    assert (removed.status_code, code(removed)) == (403, "device_removed")


def test_the_clinic_cannot_publish_an_answer_for_a_removed_device_or_an_unknown_request(
    approval_http,
):
    app, client = approval_http
    assert post_intent(client).status_code == 201
    assert put_challenge(client).status_code == 200
    unknown = INTERNAL + "/" + str(uuid4()) + "/challenge"
    raw = body({"intent": FLOW["intent"]["compact"], "challenge": FLOW["challenge"]["compact"]})
    missing = client.put(
        unknown, content=raw, headers=job_headers(unknown, "challenges.publish", "PUT", raw)
    )
    assert (missing.status_code, code(missing)) == (404, "approval_not_found")
    with app.state.session_factory() as s, s.begin():
        device = s.scalar(select(PatientPortalMyCarlosDevice))
        device.status, device.removed_by = "removed", "staff"
        device.removed_at = datetime.fromtimestamp(F["now"], UTC)
    decision = body(
        {
            "challenge_id": FLOW["challenge"]["claims"]["challenge_id"],
            "status": "accepted",
            "acceptance": FLOW["acceptance"]["compact"],
            "reason": None,
        }
    )
    target = INTERNAL + "/" + REQUEST + "/decision"
    refused = client.put(
        target,
        content=decision,
        headers=job_headers(target, "decisions.publish", "PUT", decision),
    )
    assert (refused.status_code, code(refused)) == (403, "device_removed")


def test_a_listing_with_a_cursor_that_is_not_one_is_refused(approval_http):
    _, client = approval_http
    path = INTERNAL + "?cursor=not-a-cursor"
    refused = client.get(path, headers=job_headers(path, "requests.read"))
    assert refused.status_code == 400
    assert code(refused) == "invalid_cursor"


def test_an_account_with_fifty_open_requests_is_told_to_wait_before_the_device_rate_limit(
    approval_http,
):
    app, client = approval_http
    now = F["now"]
    with app.state.session_factory() as session, session.begin():
        device = session.scalars(select(PatientPortalMyCarlosDevice)).one()
        for number in range(1, 51):
            session.add(
                ApprovalRequest(
                    clinic_id=F["clinic_id"],
                    request_id=str(uuid4()),
                    account_id=device.account_id,
                    device_id=device.id,
                    demographic_no=6001,
                    recipient_id=F["recipient_id"],
                    candidate_kid=device.device_key_id,
                    request_sequence=1000 + number,
                    intent="FAKE-intent",
                    intent_body_hash="a" * 64,
                    expires_at=now + 3600,
                    status="pending",
                )
            )
    refused = post(client, signed_intent(request_id=str(uuid4())))
    assert (refused.status_code, code(refused)) == (429, "approval_unavailable")
    # Nothing was added by the refused request.
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(ApprovalRequest)) == 50


def test_requests_that_have_ended_do_not_count_toward_the_fifty(approval_http):
    app, client = approval_http
    now = F["now"]
    with app.state.session_factory() as session, session.begin():
        device = session.scalars(select(PatientPortalMyCarlosDevice)).one()
        for number in range(1, 51):
            session.add(
                ApprovalRequest(
                    clinic_id=F["clinic_id"],
                    request_id=str(uuid4()),
                    account_id=device.account_id,
                    device_id=device.id,
                    demographic_no=6001,
                    recipient_id=F["recipient_id"],
                    candidate_kid=device.device_key_id,
                    # Far from the sequence the next real request takes (a unique index).
                    request_sequence=1000 + number,
                    intent="FAKE-intent",
                    intent_body_hash="a" * 64,
                    # Already past, or no longer open: neither is an open request.
                    expires_at=now - 1 if number % 2 else now + 3600,
                    status="pending" if number % 2 else "accepted",
                )
            )
    assert post(client, signed_intent(request_id=str(uuid4()))).status_code == 201


def test_an_unexpected_refusal_from_the_rate_check_is_passed_on_unchanged(
    approval_http, monkeypatch
):
    _, client = approval_http

    def refuse(*_args, **_kwargs):
        raise MailboxRefusal("mailbox_unavailable", 503)

    monkeypatch.setattr(mailbox, "rate", refuse)
    refused = post(client, signed_intent(request_id=str(uuid4())))
    # Not turned into "wait": only the quota refusal is.
    assert (refused.status_code, code(refused)) == (503, "mailbox_unavailable")
