# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Device approval contract v2 (myCarlos #144): the shared FAKE fixture, the expiry rules, the
versions route and the switch. v2 changes only lifetimes; v1 stays as it was."""

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
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
from carlos_patient_portal.models import PatientPortalAccount, PatientPortalMyCarlosDevice
from carlos_patient_portal.mycarlos_devices import strict_b64url_decode
from tests import delivery_contract_reference as ref
from tests.test_approval_http import (
    INTERNAL,
    PREFIX,
    body,
    device_headers,
    job_headers,
    make_approval_http,
)
from tests.test_approval_http import F as HTTP_FIXTURE

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
LATER = V2["flows"]["accepted_device"]
PUBLIC = PREFIX + "/api/mycarlos/device-approval-requests"
VERSIONS = PREFIX + V2["versions_endpoint"]["path"]
# FAKE clinic key, from the v1 fixture's seed text (the fixture holds no key material).
CLINIC = ref.private_key_from_seed_text(V1["keys"]["clinic"]["seed_text"], "p256")
P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


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


def clinic_signed(claims):
    """Claims signed with the FAKE clinic key, as CARLOS signs them (P1363, low s)."""
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    r, s = decode_dss_signature(CLINIC.sign(payload, ec.ECDSA(hashes.SHA256())))
    s = min(s, P256_N - s)
    return ref.b64url(payload) + "." + ref.b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def test_the_portal_knows_the_versions_the_contract_names():
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


# A version mismatch is the portal's to refuse (the HTTP tests below), not the rule's.
@pytest.mark.parametrize(
    "case",
    [case for case in V2["challenge_expiry_cases"] if "intent_version" not in case],
    ids=lambda case: case["id"],
)
def test_challenge_expiry_rule(case):
    rule = challenge_expiry(
        case["version"], case["approval_kind"], case["issued_at"], case["intent_exp"]
    )
    assert (case["expires_at"] == rule) == case["valid"]


# A request with a challenge ends at the challenge's expires_at (stored as the row's end, below).
@pytest.mark.parametrize(
    "case",
    [case for case in V2["open_request_cases"] if case["status"] == "pending"],
    ids=lambda case: case["id"],
)
def test_unanswered_request_rule(case):
    until = unanswered_until(case["intent_iat"], case["intent_exp"])
    assert (case["now"] < until) == case["open"]


@pytest.fixture
def v2_http(monkeypatch):
    return make_approval_http(monkeypatch, mycarlos_approval_contract_v2_enabled=True)


@pytest.fixture
def v1_only_http(monkeypatch):
    return make_approval_http(monkeypatch)


def post_staff_intent(client):
    raw = body({"intent": STAFF["intent"]["compact"]})
    return client.post(PUBLIC, content=raw, headers=device_headers(PUBLIC, "POST", raw))


def put_challenge(client, flow, challenge):
    raw = body({"intent": flow["intent"]["compact"], "challenge": challenge})
    path = INTERNAL + "/" + flow["intent"]["claims"]["request_id"] + "/challenge"
    return client.put(
        path, content=raw, headers=job_headers(path, "challenges.publish", "PUT", raw)
    )


def test_versions_route_lists_v2_only_when_switched_on(v2_http, v1_only_http):
    for (_, client), expected in [(v2_http, [1, 2]), (v1_only_http, [1])]:
        result = client.get(VERSIONS, headers=device_headers(VERSIONS))
        assert result.status_code == 200, result.text
        assert result.json() == {"versions": expected}


def test_versions_route_needs_a_device_and_no_query(v2_http):
    _, client = v2_http
    assert client.get(VERSIONS).status_code == 404
    query = VERSIONS + "?v=2"
    assert client.get(query, headers=device_headers(query)).status_code == 400


def test_a_v2_intent_is_refused_while_the_switch_is_off(v1_only_http):
    _, client = v1_only_http
    posted = post_staff_intent(client)
    assert posted.status_code == 400, posted.text
    assert "invalid_approval" in posted.text


def test_v2_staff_request_is_open_10_minutes_until_answered_then_24_hours(v2_http):
    app, client = v2_http
    posted = post_staff_intent(client)
    assert posted.status_code == 201, posted.text
    iat = STAFF["intent"]["claims"]["iat"]
    with app.state.session_factory() as s:
        assert s.scalar(select(ApprovalRequest.expires_at)) == iat + 600
    published = put_challenge(client, STAFF, STAFF["challenge"]["compact"])
    assert published.status_code == 200, published.text
    challenge = STAFF["challenge"]["claims"]
    with app.state.session_factory() as s:
        row = s.scalar(select(ApprovalRequest))
        assert row.status == "challenge_ready"
        assert row.expires_at == challenge["expires_at"]
    assert challenge["expires_at"] - challenge["issued_at"] > 23 * 3600


def test_v2_challenge_after_the_unanswered_10_minutes_is_refused(v2_http, monkeypatch):
    _, client = v2_http
    assert post_staff_intent(client).status_code == 201
    # The device may have replaced this request by now: a late answer must not revive it.
    monkeypatch.setitem(HTTP_FIXTURE, "now", STAFF["intent"]["claims"]["iat"] + 600)
    published = put_challenge(client, STAFF, STAFF["challenge"]["compact"])
    assert published.status_code == 410, published.text
    assert "approval_expired" in published.text


def test_a_v2_intent_older_than_10_minutes_is_not_taken(v2_http, monkeypatch):
    _, client = v2_http
    monkeypatch.setitem(HTTP_FIXTURE, "now", STAFF["intent"]["claims"]["iat"] + 600)
    posted = post_staff_intent(client)
    assert posted.status_code == 410, posted.text
    assert "approval_expired" in posted.text


def test_a_v1_challenge_for_a_v2_intent_is_refused(v2_http):
    _, client = v2_http
    assert post_staff_intent(client).status_code == 201
    claims = dict(STAFF["challenge"]["claims"], v=1)
    claims["expires_at"] = min(claims["issued_at"] + 600, STAFF["intent"]["claims"]["exp"])
    published = put_challenge(client, STAFF, clinic_signed(claims))
    assert published.status_code == 409, published.text


def test_a_v1_acceptance_for_a_v2_challenge_is_refused(v2_http):
    app, client = v2_http
    assert post_staff_intent(client).status_code == 201
    assert put_challenge(client, STAFF, STAFF["challenge"]["compact"]).status_code == 200
    acceptance = clinic_signed(dict(STAFF["acceptance"]["claims"], v=1))
    request = STAFF["intent"]["claims"]["request_id"]
    decision = body(
        {
            "challenge_id": STAFF["challenge"]["claims"]["challenge_id"],
            "status": "accepted",
            "acceptance": acceptance,
            "reason": None,
        }
    )
    route = INTERNAL + "/" + request + "/decision"
    result = client.put(
        route, content=decision, headers=job_headers(route, "decisions.publish", "PUT", decision)
    )
    assert result.status_code == 409, result.text
    with app.state.session_factory() as s:
        assert s.scalar(select(ApprovalRequest.status)) == "challenge_ready"


def test_a_v1_device_approval_for_a_v2_challenge_is_refused(v2_http):
    app, client = v2_http
    candidate, predecessor = V1["keys"]["candidate"], V1["keys"]["predecessor"]
    with app.state.session_factory() as s, s.begin():
        account = s.scalar(select(PatientPortalAccount))
        for key in [candidate, predecessor]:
            s.add(
                PatientPortalMyCarlosDevice(
                    account_id=account.id,
                    device_key_id=key["device_key_id"],
                    ed25519_public_key=strict_b64url_decode(key["ed25519_public_key"]),
                    x25519_public_key=strict_b64url_decode(key["x25519_public_key"]),
                    device_name="FAKE v2 later approval device",
                    status="active",
                    linked_at=datetime.fromtimestamp(V2["now"], UTC),
                )
            )
    candidate_private = ref.private_key_from_seed_text(candidate["ed25519_seed_text"], "ed25519")
    private = ref.private_key_from_seed_text(predecessor["ed25519_seed_text"], "ed25519")
    raw = body({"intent": LATER["intent"]["compact"]})
    posted = client.post(
        PUBLIC,
        content=raw,
        headers=device_headers(PUBLIC, "POST", raw, candidate, candidate_private),
    )
    assert posted.status_code == 201, posted.text
    assert put_challenge(client, LATER, LATER["challenge"]["compact"]).status_code == 200
    target = (
        PREFIX + "/api/mycarlos/device-approvals/" + LATER["challenge"]["claims"]["challenge_id"]
    )
    v1_proof = ref.compact_ed25519(private, dict(LATER["approval"]["claims"], v=1))
    raw = body({"approval": v1_proof})
    result = client.post(
        target, content=raw, headers=device_headers(target, "POST", raw, predecessor, private)
    )
    assert result.status_code == 409, result.text
    raw = body({"approval": LATER["approval"]["compact"]})
    result = client.post(
        target, content=raw, headers=device_headers(target, "POST", raw, predecessor, private)
    )
    assert result.status_code == 200, result.text
