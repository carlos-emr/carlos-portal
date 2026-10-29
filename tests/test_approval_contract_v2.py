# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Device approval contract v2 (myCarlos #144): the shared FAKE fixture, the expiry rules and
the versions route. v2 changes only lifetimes; v1 stays as it was."""

import hashlib
import json
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select

from carlos_patient_portal.approval_codec import (
    CONTRACT_VERSIONS,
    challenge_expiry,
    unanswered_until,
    verify_approval,
    verify_clinic,
    verify_intent,
)
from carlos_patient_portal.approval_models import ApprovalRequest
from carlos_patient_portal.mailbox_codec import MailboxRefusal
from carlos_patient_portal.mycarlos_devices import strict_b64url_decode
from carlos_patient_portal.routes import mycarlos_approval
from tests import delivery_contract_reference as ref
from tests.test_approval_http import (  # noqa: F401 (approval_http is a fixture)
    INTERNAL,
    KEY,
    PREFIX,
    PRIVATE,
    approval_http,
    body,
    device_headers,
    job_headers,
)

FIXTURES = Path(__file__).parent / "fixtures"
V1 = json.loads((FIXTURES / "device-approval-contract-v1.json").read_bytes())
V2 = json.loads((FIXTURES / "device-approval-contract-v2.json").read_bytes())
SCOPE = {
    "clinic": V2["clinic_id"],
    "recipient": V2["recipient_id"],
    "public_base": V2["public_portal_base_url"],
}
DEVICES = {key["device_key_id"]: key for key in V1["keys"].values() if "device_key_id" in key}
STAFF = V2["flows"]["staff_first"]
PUBLIC = PREFIX + "/api/mycarlos/device-approval-requests"
VERSIONS = PREFIX + V2["versions_endpoint"]["path"]


def verify(kind, compact):
    if kind == "intent":
        return verify_intent(compact, **SCOPE)
    if kind == "approval":
        claims = json.loads(strict_b64url_decode(compact.split(".")[0]))
        key = DEVICES[claims["predecessor_device_key_id"]]
        return verify_approval(
            compact,
            predecessor_kid=key["device_key_id"],
            predecessor_ed=strict_b64url_decode(key["ed25519_public_key"]),
            **SCOPE,
        )
    return verify_clinic(
        kind, compact, spki=strict_b64url_decode(V1["keys"]["clinic"]["spki"]), **SCOPE
    )


def test_the_portal_takes_the_versions_the_contract_names():
    assert (
        list(CONTRACT_VERSIONS) == V2["versions"] == V2["versions_endpoint"]["response"]["versions"]
    )


def test_v2_was_signed_with_this_repos_v1_public_keys():
    public = {
        role: {k: w for k, w in key.items() if not k.startswith("FAKE_") and "seed" not in k}
        for role, key in V1["keys"].items()
    }
    raw = json.dumps(public, sort_keys=True, separators=(",", ":")).encode()
    assert hashlib.sha256(raw).hexdigest() == V2["v1_public_keys_sha256"]


@pytest.mark.parametrize("flow", sorted(V2["flows"]))
def test_v2_flows_verify(flow):
    for kind, value in V2["flows"][flow].items():
        assert verify(kind, value["compact"]) == value["claims"]


@pytest.mark.parametrize("vector", V2["signed_object_vectors"], ids=lambda vector: vector["id"])
def test_every_v2_signed_object_vector(vector):
    if vector["valid"]:
        verify(vector["kind"], vector["compact"])
    else:
        with pytest.raises(MailboxRefusal):
            verify(vector["kind"], vector["compact"])


@pytest.mark.parametrize("case", V2["challenge_expiry_cases"], ids=lambda case: case["id"])
def test_challenge_expiry_rule(case):
    same_version = case.get("intent_version", case["version"]) == case["version"]
    rule = challenge_expiry(
        case["version"], case["approval_kind"], case["issued_at"], case["intent_exp"]
    )
    assert (same_version and case["expires_at"] == rule) == case["valid"]


@pytest.mark.parametrize("case", V2["open_request_cases"], ids=lambda case: case["id"])
def test_open_request_rule(case):
    if case["status"] == "challenge_ready":
        until = case["challenge_expires_at"]
    else:
        until = unanswered_until(case["intent_iat"], case["intent_exp"])
    assert (case["now"] < until) == case["open"]


def post_staff_intent(client):
    raw = body({"intent": STAFF["intent"]["compact"]})
    return client.post(PUBLIC, content=raw, headers=device_headers(PUBLIC, "POST", raw))


def device_headers_at(path, method, raw, now):
    """device_headers, signed at `now` instead of the fixture's time."""
    claims = {
        "aud": ref.DEVICE_AUDIENCE,
        "iss": "mycarlos",
        "kid": KEY["device_key_id"],
        "recipient_id": V2["recipient_id"],
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + 60,
        "request_hash": ref.request_hash(method, path.encode(), b"", raw),
    }
    return {
        "X-MyCarlos-Device-Assertion": ref.compact_ed25519(PRIVATE, claims),
        "Content-Type": "application/json",
    }


def put_staff_challenge(client):
    raw = body({"intent": STAFF["intent"]["compact"], "challenge": STAFF["challenge"]["compact"]})
    path = INTERNAL + "/" + STAFF["intent"]["claims"]["request_id"] + "/challenge"
    return client.put(
        path, content=raw, headers=job_headers(path, "challenges.publish", "PUT", raw)
    )


def test_versions_route_lists_both_versions(request):
    _, client = request.getfixturevalue("approval_http")
    result = client.get(VERSIONS, headers=device_headers(VERSIONS))
    assert result.status_code == 200, result.text
    assert result.json() == {"versions": [1, 2]}


def test_versions_route_needs_a_device(request):
    _, client = request.getfixturevalue("approval_http")
    assert client.get(VERSIONS).status_code == 404


def test_v2_staff_request_is_open_10_minutes_until_answered_then_24_hours(request):
    app, client = request.getfixturevalue("approval_http")
    posted = post_staff_intent(client)
    assert posted.status_code == 201, posted.text
    iat = STAFF["intent"]["claims"]["iat"]
    with app.state.session_factory() as s:
        assert s.scalar(select(ApprovalRequest.expires_at)) == iat + 600
    published = put_staff_challenge(client)
    assert published.status_code == 200, published.text
    challenge = STAFF["challenge"]["claims"]
    with app.state.session_factory() as s:
        row = s.scalar(select(ApprovalRequest))
        assert row.status == "challenge_ready"
        assert row.expires_at == challenge["expires_at"]
    assert challenge["expires_at"] - challenge["issued_at"] > 23 * 3600


def test_v2_challenge_after_the_unanswered_10_minutes_is_refused(request, monkeypatch):
    _, client = request.getfixturevalue("approval_http")
    assert post_staff_intent(client).status_code == 201
    # The device may have replaced this request by now: a late answer must not revive it.
    monkeypatch.setattr(mycarlos_approval, "time", lambda: STAFF["intent"]["claims"]["iat"] + 600)
    published = put_staff_challenge(client)
    assert published.status_code == 410, published.text
    assert "approval_expired" in published.text


def test_a_v2_intent_older_than_10_minutes_is_not_taken(request, monkeypatch):
    _, client = request.getfixturevalue("approval_http")
    late = STAFF["intent"]["claims"]["iat"] + 600
    monkeypatch.setattr(mycarlos_approval, "time", lambda: late)
    raw = body({"intent": STAFF["intent"]["compact"]})
    posted = client.post(PUBLIC, content=raw, headers=device_headers_at(PUBLIC, "POST", raw, late))
    assert posted.status_code == 410, posted.text
    assert "approval_expired" in posted.text
