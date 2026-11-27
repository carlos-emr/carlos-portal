# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Refusals of the myCarlos device-approval routes that the signed-HTTP tests never drove.

Test-only. Real signed HTTP through the shared approval fixtures (FAKE accounts, FAKE keys from
`device-approval-contract-v1.json`, an owned synthetic database, no network). Each case asserts
the exact status and refusal code the device or CARLOS would see, and that the refused call left
the stored request unchanged.
"""

# The two fixtures are imported from the shared approval module and named as arguments below,
# which ruff reads as a redefinition (the same reuse as `test_approval_code.py`).
# ruff: noqa: F811

from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from sqlalchemy import select

from carlos_patient_portal.approval_models import ApprovalRequest
from carlos_patient_portal.models import PatientPortalAccount
from carlos_patient_portal.routes import mycarlos_approval
from tests.test_approval_http import (  # noqa: F401 -- the shared fixtures, reused
    FLOW,
    INTERNAL,
    PREFIX,
    PUBLIC,
    REQUEST,
    F,
    approval_http,
    body,
    device_headers,
    job_headers,
    later_approval_http,
    post_intent,
)

APPROVALS_INTERNAL = "/internal/carlos/mycarlos/device-approvals"
APPROVALS_PUBLIC = PREFIX + "/api/mycarlos/device-approvals"


def stored_request(app, request_id=REQUEST):
    with app.state.session_factory() as session:
        return session.get(ApprovalRequest, (F["clinic_id"], request_id))


def test_a_get_that_carries_a_body_is_refused_as_too_large(approval_http):  # noqa: F811
    # The status route reads no body (limit 0), so even one byte is refused before the device is
    # looked up; the later "GET with a body is not found" branch is never reached from here.
    app, client = approval_http
    assert post_intent(client).status_code == 201
    path = PUBLIC + "/" + REQUEST

    result = client.request("GET", path, content=b"x", headers=device_headers(path))

    assert result.status_code == 413
    assert result.json() == {"detail": "request too large"}


def test_a_new_request_with_a_query_string_is_refused_and_stores_nothing(approval_http):  # noqa: F811
    app, client = approval_http
    path = PUBLIC + "?x=1"
    raw = body({"intent": FLOW["intent"]["compact"]})

    result = client.post(path, content=raw, headers=device_headers(path, "POST", raw))

    assert result.status_code == 400
    assert result.json() == {"code": "invalid_approval"}
    assert stored_request(app) is None


def test_a_status_read_with_a_query_string_is_not_found(approval_http):  # noqa: F811
    app, client = approval_http
    assert post_intent(client).status_code == 201
    path = PUBLIC + "/" + REQUEST + "?x=1"

    result = client.get(path, headers=device_headers(path))

    assert result.status_code == 404
    assert result.json() == {"code": "approval_not_found"}


def test_a_disabled_account_is_refused_as_recipient_mismatch(approval_http):  # noqa: F811
    app, client = approval_http
    assert post_intent(client).status_code == 201
    with app.state.session_factory() as session, session.begin():
        account = session.scalar(select(PatientPortalAccount))
        account.status = "disabled"
        account.disabled_at = datetime.fromtimestamp(F["now"], UTC)
        account.disabled_by = "FAKE staff"
    path = PUBLIC + "/" + REQUEST

    result = client.get(path, headers=device_headers(path))

    assert result.status_code == 403
    assert result.json() == {"code": "recipient_mismatch"}


def test_another_device_of_the_same_account_cannot_read_a_request_status(  # noqa: F811
    later_approval_http,
):
    app, client, later, candidate, candidate_private, predecessor, predecessor_private = (
        later_approval_http
    )
    path = PUBLIC + "/" + later["intent"]["claims"]["request_id"]

    own = client.get(path, headers=device_headers(path, key=candidate, private=candidate_private))
    other = client.get(
        path, headers=device_headers(path, key=predecessor, private=predecessor_private)
    )

    assert own.status_code == 200, own.text
    assert other.status_code == 404
    assert other.json() == {"code": "approval_not_found"}


@pytest.mark.parametrize(
    "change",
    [{"expires_at": F["now"]}, {"status": "pending"}],
    ids=["expired", "not_challenge_ready"],
)
def test_a_proof_for_an_expired_or_unready_challenge_is_a_410_and_stored_nowhere(  # noqa: F811
    later_approval_http, change
):
    app, client, later, candidate, candidate_private, predecessor, private = later_approval_http
    request_id = later["intent"]["claims"]["request_id"]
    with app.state.session_factory() as session, session.begin():
        row = session.get(ApprovalRequest, (F["clinic_id"], request_id))
        for name, value in change.items():
            setattr(row, name, value)
    target = APPROVALS_PUBLIC + "/" + later["challenge"]["claims"]["challenge_id"]
    raw = body({"approval": later["approval"]["compact"]})

    result = client.post(
        target, content=raw, headers=device_headers(target, "POST", raw, predecessor, private)
    )

    assert result.status_code == 410
    assert result.json() == {"code": "approval_expired"}
    assert stored_request(app, request_id).approval is None


@pytest.mark.parametrize(
    "path,permission,field",
    [(INTERNAL, "requests.read", "requests"), (APPROVALS_INTERNAL, "approvals.read", "approvals")],
    ids=["requests", "approvals"],
)
def test_a_cursor_past_the_clinics_last_sequence_is_refused(  # noqa: F811
    approval_http, path, permission, field
):
    app, client = approval_http
    target = path + "?after=1"

    result = client.get(target, headers=job_headers(target, permission))

    assert result.status_code == 400
    assert result.json() == {"code": "invalid_cursor"}
    empty = client.get(path, headers=job_headers(path, permission))
    assert empty.status_code == 200
    assert empty.json() == {field: [], "last_sequence": "0", "next_cursor": None}


def test_the_approvals_listing_returns_a_stored_proof_once_and_then_nothing(  # noqa: F811
    later_approval_http,
):
    app, client, later, candidate, candidate_private, predecessor, private = later_approval_http
    challenge_id = later["challenge"]["claims"]["challenge_id"]
    target = APPROVALS_PUBLIC + "/" + challenge_id
    raw = body({"approval": later["approval"]["compact"]})
    stored = client.post(
        target, content=raw, headers=device_headers(target, "POST", raw, predecessor, private)
    )
    assert stored.status_code == 200, stored.text

    listing = client.get(
        APPROVALS_INTERNAL, headers=job_headers(APPROVALS_INTERNAL, "approvals.read")
    )
    after = APPROVALS_INTERNAL + "?after=1"
    drained = client.get(after, headers=job_headers(after, "approvals.read"))

    assert listing.status_code == 200, listing.text
    assert listing.json() == {
        "approvals": [
            {
                "sequence": "1",
                "request_id": later["intent"]["claims"]["request_id"],
                "challenge_id": challenge_id,
                "approval": later["approval"]["compact"],
            }
        ],
        "last_sequence": "1",
        "next_cursor": None,
    }
    assert drained.status_code == 200
    assert drained.json() == {"approvals": [], "last_sequence": "1", "next_cursor": None}


@pytest.mark.parametrize(
    "suffix,query",
    [("/not-a-uuid", ""), ("/" + REQUEST, "?x=1")],
    ids=["request_id_not_a_uuid", "query_string"],
)
def test_publishing_a_challenge_to_a_bad_address_is_a_400(approval_http, suffix, query):  # noqa: F811
    app, client = approval_http
    assert post_intent(client).status_code == 201
    path = INTERNAL + suffix + "/challenge" + query
    raw = body({"intent": FLOW["intent"]["compact"], "challenge": FLOW["challenge"]["compact"]})

    result = client.put(
        path, content=raw, headers=job_headers(path, "challenges.publish", "PUT", raw)
    )

    assert result.status_code == 400
    assert result.json() == {"code": "invalid_approval"}
    assert stored_request(app).challenge is None


@pytest.mark.parametrize("base", [None, "", "http://portal.example.invalid/patient"])
@pytest.mark.parametrize("which", ["public", "internal"])
def test_the_approval_routes_refuse_to_start_without_a_usable_public_base_url(
    monkeypatch, which, base
):
    # `normalize_portal` raises on anything unusable, so the routes' own `is None` check after it
    # cannot fire; what a misconfigured portal sees is this ValueError at startup.
    monkeypatch.setattr(mycarlos_approval, "limits_from_settings", lambda settings: None)
    settings = SimpleNamespace(public_base_url=base, mycarlos_approval_contract_v2_enabled=False)
    runtime = SimpleNamespace(settings=settings)
    register = (
        mycarlos_approval.register_device_approval_routes
        if which == "public"
        else lambda app, rt: mycarlos_approval.register_internal_approval_routes(app, rt, None)
    )

    with pytest.raises(ValueError, match="^myCarlos public portal base is invalid$"):
        register(FastAPI(), runtime)
