# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Actual signed HTTP against an owned synthetic database; no native custody claim."""

import json
from base64 import urlsafe_b64encode
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.approval_models import ApprovalRequest
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
)
from carlos_patient_portal.mycarlos_devices import strict_b64url_decode
from carlos_patient_portal.routes import mycarlos_approval
from tests import delivery_contract_reference as ref
from tests.support import carlos_job_headers
from tests.test_internal_api import internal_app
from tests.test_mycarlos_mailbox_http import SplitIngressProxy

F = json.loads((Path(__file__).parent / "fixtures/device-approval-contract-v1.json").read_bytes())
FLOW = F["flows"]["first"]
KEY = F["keys"]["first"]
PRIVATE = serialization.load_der_private_key(
    strict_b64url_decode(KEY["FAKE_ed25519_private_pkcs8_b64url"]), None
)
JOB = Ed25519PrivateKey.generate()
JOB_KID = "FAKE-approval-job"
PREFIX = "/patient"
PUBLIC = PREFIX + "/api/mycarlos/device-approval-requests"
INTERNAL = "/internal/carlos/mycarlos/device-approval-requests"
REQUEST = FLOW["intent"]["claims"]["request_id"]


def body(value):
    return json.dumps(value, separators=(",", ":")).encode()


def device_headers(path, method="GET", raw=b"", key=KEY, private=PRIVATE, anchor=None):
    route, _, query = path.partition("?")
    claims = {
        "aud": ref.DEVICE_AUDIENCE,
        "iss": "mycarlos",
        "kid": key["device_key_id"],
        "recipient_id": F["recipient_id"],
        "jti": str(uuid4()),
        "iat": F["now"],
        "exp": F["now"] + 60,
        "request_hash": ref.request_hash(method, route.encode(), query.encode(), raw),
    }
    if anchor:
        claims["vault_head_link"] = anchor
    return {
        "X-MyCarlos-Device-Assertion": ref.compact_ed25519(private, claims),
        "Content-Type": "application/json",
    }


def job_headers(path, permission, method="GET", raw=b""):
    route, _, query = path.partition("?")
    return carlos_job_headers(
        "device-approval-sync",
        "portal.mycarlos.device_approval." + permission,
        method=method,
        path=route,
        query=query.encode(),
        body=raw,
        clinic_id=F["clinic_id"],
        key_id=JOB_KID,
        signing_key=JOB,
    ) | {"Content-Type": "application/json"}


@pytest.fixture
def approval_http(monkeypatch):
    monkeypatch.setattr(mycarlos_approval, "time", lambda: F["now"])
    app = internal_app(
        clinic_id=F["clinic_id"],
        mycarlos_delivery_enabled=True,
        mycarlos_mailbox_enabled=True,
        mycarlos_approval_enabled=True,
        public_base_url="https://PORTAL.example.invalid:443/patient",
        internal_job_assertion_public_keyring=json.dumps(
            {
                "device-approval-sync": {
                    JOB_KID: urlsafe_b64encode(JOB.public_key().public_bytes_raw())
                    .rstrip(b"=")
                    .decode()
                }
            }
        ),
    )
    with app.state.session_factory() as s, s.begin():
        account = PatientPortalAccount(
            clinic_id=F["clinic_id"],
            demographic_no=6001,
            username="fake.approval",
            email="fake.approval@example.invalid",
            password_hash="FAKE-unused",
            status="active",
        )
        s.add(account)
        s.flush()
        s.add(PatientPortalMyCarlosRecipient(account_id=account.id, recipient_id=F["recipient_id"]))
        s.add(
            PatientPortalMyCarlosDevice(
                account_id=account.id,
                device_key_id=KEY["device_key_id"],
                ed25519_public_key=strict_b64url_decode(KEY["ed25519_public_key"]),
                x25519_public_key=strict_b64url_decode(KEY["x25519_public_key"]),
                device_name="FAKE actual approval device",
                status="active",
                linked_at=datetime.fromtimestamp(F["now"], UTC),
            )
        )
        s.add(
            PatientPortalClinicKey(
                clinic_id=F["clinic_id"],
                kid=F["keys"]["clinic"]["kid"],
                spki=strict_b64url_decode(F["keys"]["clinic"]["spki"]),
                status="active",
                published_at=datetime.fromtimestamp(F["now"], UTC),
            )
        )
    proxy = SplitIngressProxy(app, PREFIX, PREFIX)
    return app, TestClient(proxy, base_url="https://portal.example.invalid")


def post_intent(client):
    raw = body({"intent": FLOW["intent"]["compact"]})
    return client.post(PUBLIC, content=raw, headers=device_headers(PUBLIC, "POST", raw))


def put_challenge(client, challenge=None):
    raw = body(
        {
            "intent": FLOW["intent"]["compact"],
            "challenge": challenge or FLOW["challenge"]["compact"],
        }
    )
    path = INTERNAL + "/" + REQUEST + "/challenge"
    return client.put(
        path, content=raw, headers=job_headers(path, "challenges.publish", "PUT", raw)
    )


def test_real_first_approval_roundtrip_and_exact_retries_after_key_revocation(approval_http):
    app, client = approval_http
    posted = post_intent(client)
    assert posted.status_code == 201, posted.text
    assert posted.json() == {
        "request_id": REQUEST,
        "status": "pending",
        "challenge": None,
        "acceptance": None,
        "reason": None,
    }
    assert post_intent(client).status_code == 200
    listing = client.get(INTERNAL, headers=job_headers(INTERNAL, "requests.read"))
    assert listing.status_code == 200, listing.text
    assert listing.json()["requests"][0]["intent"] == FLOW["intent"]["compact"]
    assert put_challenge(client).status_code == 200
    path = PUBLIC + "/" + REQUEST
    read = client.get(path, headers=device_headers(path, anchor="11" * 32))
    assert read.status_code == 200, read.text
    assert read.json()["challenge"] == FLOW["challenge"]["compact"]
    raw = body(
        {
            "challenge_id": FLOW["challenge"]["claims"]["challenge_id"],
            "status": "accepted",
            "acceptance": FLOW["acceptance"]["compact"],
            "reason": None,
        }
    )
    target = INTERNAL + "/" + REQUEST + "/decision"
    accepted = client.put(
        target, content=raw, headers=job_headers(target, "decisions.publish", "PUT", raw)
    )
    assert accepted.status_code == 200, accepted.text
    assert (
        client.get(path, headers=device_headers(path)).json()["acceptance"]
        == FLOW["acceptance"]["compact"]
    )
    with app.state.session_factory() as s, s.begin():
        key = s.get(PatientPortalClinicKey, F["keys"]["clinic"]["kid"])
        key.status, key.revoked_at = "revoked", datetime.fromtimestamp(F["now"], UTC)
    assert put_challenge(client).status_code == 200
    assert (
        client.put(
            target, content=raw, headers=job_headers(target, "decisions.publish", "PUT", raw)
        ).status_code
        == 200
    )
    with app.state.session_factory() as s:
        assert len(list(s.scalars(select(ApprovalRequest)))) == 1


@pytest.mark.parametrize(
    "field,bad", [("approval_kind", []), ("approval_kind", {}), ("kid", []), ("kid", {})]
)
def test_bad_signed_object_field_type_returns_controlled_400(approval_http, field, bad):
    _, client = approval_http
    assert post_intent(client).status_code == 201
    claims = dict(FLOW["challenge"]["claims"])
    claims[field] = bad
    compact = (
        urlsafe_b64encode(body(claims)).rstrip(b"=").decode()
        + "."
        + FLOW["challenge"]["compact"].split(".")[1]
    )
    result = put_challenge(client, compact)
    assert result.status_code == 400, result.text
    assert result.json() == {"code": "invalid_approval"}


def test_outer_signature_binds_actual_public_prefix_and_body(approval_http):
    _, client = approval_http
    raw = body({"intent": FLOW["intent"]["compact"]})
    assert (
        client.post(
            PUBLIC, content=raw, headers=device_headers(PUBLIC.removeprefix(PREFIX), "POST", raw)
        ).status_code
        == 404
    )
    assert (
        client.post(
            PUBLIC, content=raw + b" ", headers=device_headers(PUBLIC, "POST", raw)
        ).status_code
        == 404
    )


def test_late_challenge_publication_remains_visible_after_approver_cursor(approval_http):
    app, client = approval_http
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    from carlos_patient_portal.approval_codec import compact_hash

    predecessor = F["keys"]["predecessor"]
    predecessor_private = serialization.load_der_private_key(
        strict_b64url_decode(predecessor["FAKE_ed25519_private_pkcs8_b64url"]), None
    )
    other = ref.DeviceKeys("FAKE second candidate committed challenge cursor")
    other_key = {
        "device_key_id": other.device_key_id,
        "ed25519_public_key": ref.b64url(other.ed25519_public),
        "x25519_public_key": ref.b64url(other.x25519_public),
    }
    with app.state.session_factory() as s, s.begin():
        account = s.scalar(select(PatientPortalAccount))
        for key in [predecessor, other_key]:
            s.add(
                PatientPortalMyCarlosDevice(
                    account_id=account.id,
                    device_key_id=key["device_key_id"],
                    ed25519_public_key=strict_b64url_decode(key["ed25519_public_key"]),
                    x25519_public_key=strict_b64url_decode(key["x25519_public_key"]),
                    device_name="FAKE challenge cursor device",
                    status="active",
                    linked_at=datetime.fromtimestamp(F["now"], UTC),
                )
            )
    clinic_private = serialization.load_der_private_key(
        strict_b64url_decode(F["keys"]["clinic"]["FAKE_private_pkcs8_b64url"]), None
    )
    candidates = []
    for key, private in [(KEY, PRIVATE), (other_key, other.ed25519)]:
        request_id = str(uuid4())
        intent_claims = dict(
            FLOW["intent"]["claims"],
            request_id=request_id,
            candidate_device_key_id=key["device_key_id"],
            candidate_x25519_public_key=key["x25519_public_key"],
            candidate_ed25519_public_key=key["ed25519_public_key"],
            predecessor_device_key_id=predecessor["device_key_id"],
        )
        intent = ref.compact_ed25519(private, intent_claims)
        raw = body({"intent": intent})
        result = client.post(
            PUBLIC, content=raw, headers=device_headers(PUBLIC, "POST", raw, key, private)
        )
        assert result.status_code == 201, result.text
        claims = dict(
            F["flows"]["later"]["challenge"]["claims"],
            request_id=request_id,
            challenge_id=ref.b64url(uuid4().bytes + uuid4().bytes),
            candidate_device_key_id=key["device_key_id"],
            candidate_x25519_public_key=key["x25519_public_key"],
            candidate_ed25519_public_key=key["ed25519_public_key"],
            candidate_intent_sha256=compact_hash(intent),
        )
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        r, ss = decode_dss_signature(clinic_private.sign(payload, ec.ECDSA(hashes.SHA256())))
        challenge = (
            ref.b64url(payload) + "." + ref.b64url(r.to_bytes(32, "big") + ss.to_bytes(32, "big"))
        )
        candidates.append((request_id, intent, challenge))
    seen = []
    for request_id, intent, challenge in reversed(candidates):
        raw = body({"intent": intent, "challenge": challenge})
        target = INTERNAL + "/" + request_id + "/challenge"
        result = client.put(
            target, content=raw, headers=job_headers(target, "challenges.publish", "PUT", raw)
        )
        assert result.status_code == 200, result.text
        after = seen[-1] if seen else "0"
        target = PREFIX + "/api/mycarlos/device-approvals?after=" + after
        result = client.get(
            target, headers=device_headers(target, key=predecessor, private=predecessor_private)
        )
        assert result.status_code == 200, result.text
        assert [row["request_id"] for row in result.json()["requests"]] == [request_id]
        seen.append(result.json()["last_sequence"])
    assert seen == ["1", "2"]


@pytest.mark.parametrize("encoding", ["utf-8-sig", "utf-16"])
def test_existing_signed_outer_json_encodings_do_not_trigger_second_parse_failure(
    approval_http, encoding
):
    _, client = approval_http
    raw = body({"intent": FLOW["intent"]["compact"]})
    claims = {
        "aud": ref.DEVICE_AUDIENCE,
        "iss": "mycarlos",
        "kid": KEY["device_key_id"],
        "recipient_id": F["recipient_id"],
        "jti": str(uuid4()),
        "iat": F["now"],
        "exp": F["now"] + 60,
        "request_hash": ref.request_hash("POST", PUBLIC.encode(), b"", raw),
    }
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode(encoding)
    compact = ref.b64url(payload) + "." + ref.b64url(PRIVATE.sign(payload))
    result = client.post(PUBLIC, content=raw, headers={"X-MyCarlos-Device-Assertion": compact})
    assert result.status_code == 201, result.text


def test_saved_decision_retry_survives_removal_without_new_state_revival(approval_http):
    app, client = approval_http
    assert post_intent(client).status_code == 201
    assert put_challenge(client).status_code == 200
    raw = body(
        {
            "challenge_id": FLOW["challenge"]["claims"]["challenge_id"],
            "status": "accepted",
            "acceptance": FLOW["acceptance"]["compact"],
            "reason": None,
        }
    )
    target = INTERNAL + "/" + REQUEST + "/decision"
    assert (
        client.put(
            target, content=raw, headers=job_headers(target, "decisions.publish", "PUT", raw)
        ).status_code
        == 200
    )
    with app.state.session_factory() as s, s.begin():
        device = s.scalar(select(PatientPortalMyCarlosDevice))
        device.status, device.removed_by, device.removed_at = (
            "removed",
            "patient",
            datetime.fromtimestamp(F["now"], UTC),
        )
    retry = client.put(
        target, content=raw, headers=job_headers(target, "decisions.publish", "PUT", raw)
    )
    assert retry.status_code == 200, retry.text
    changed = body(
        {
            "challenge_id": FLOW["challenge"]["claims"]["challenge_id"],
            "status": "cancelled",
            "acceptance": None,
            "reason": "challenge_cancelled",
        }
    )
    assert (
        client.put(
            target,
            content=changed,
            headers=job_headers(target, "decisions.publish", "PUT", changed),
        ).status_code
        == 409
    )
    with app.state.session_factory() as s:
        assert s.scalar(select(PatientPortalMyCarlosDevice.status)) == "removed"
        assert s.scalar(select(ApprovalRequest.status)) == "accepted"
    public = PUBLIC + "/" + REQUEST
    assert client.get(public, headers=device_headers(public)).status_code == 403
