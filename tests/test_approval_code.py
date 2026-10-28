# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Clinic code v1 (mycarlos#141): device code submission, CARLOS's job routes and storage.

Actual signed HTTP against an owned synthetic database. Clinic objects are signed at run time
with the FAKE clinic key already in the shared approval fixture; no new key material.
"""

import hashlib
import json
import re
from pathlib import Path
from uuid import uuid4

import pytest
from alembic import command
from alembic.autogenerate import produce_migrations
from alembic.migration import MigrationContext
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from sqlalchemy import inspect, select

from carlos_patient_portal.approval_codec import compact_hash, object_claims
from carlos_patient_portal.approval_models import (
    ApprovalBase,
    ApprovalClinic,
    ApprovalCode,
    ApprovalRequest,
)
from carlos_patient_portal.mailbox_codec import MailboxRefusal
from carlos_patient_portal.mailbox_models import MailboxBase
from carlos_patient_portal.models import Base, PatientPortalAccount, PatientPortalMyCarlosDevice
from carlos_patient_portal.mycarlos_devices import strict_b64url_decode
from tests import delivery_contract_reference as ref
from tests.support import alembic_config_for_tests
from tests.test_approval_http import (  # noqa: F401 -- reused owned migrated fixture
    FLOW,
    INTERNAL,
    KEY,
    PREFIX,
    PRIVATE,
    REQUEST,
    F,
    approval_http,
    body,
    device_headers,
    job_headers,
    post_intent,
    put_challenge,
)
from tests.test_internal_api import internal_app

VECTORS = json.loads((Path(__file__).parent / "fixtures/clinic-code-v1.json").read_bytes())
CODES = "/internal/carlos/mycarlos/device-approval-codes"
# Derived from the fixture's seed text (the reference rule), not read from stored key bytes.
CLINIC_PRIVATE = ref.ClinicKey(
    F["keys"]["clinic"]["seed_text"].removeprefix(ref.SEED_PREFIX), F["clinic_id"]
).private
SCOPE = {
    "clinic": F["clinic_id"],
    "recipient": F["recipient_id"],
    "public_base": F["public_portal_base_url"],
}


def clinic_signed(claims):
    payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    r, s = decode_dss_signature(CLINIC_PRIVATE.sign(payload, ec.ECDSA(hashes.SHA256())))
    return ref.b64url(payload) + "." + ref.b64url(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


CODE_CHALLENGE = clinic_signed(dict(FLOW["challenge"]["claims"], approval_kind="code"))


def code_acceptance(kind="code", challenge=CODE_CHALLENGE):
    return clinic_signed(
        dict(
            FLOW["acceptance"]["claims"],
            approval_kind=kind,
            challenge_sha256=compact_hash(challenge),
        )
    )


def submit_path(request_id=REQUEST):
    return PREFIX + "/api/mycarlos/device-approvals/" + request_id + "/code"


def submit(
    client, code="482193", request_id=REQUEST, raw=None, key=KEY, private=PRIVATE, anchor=None
):
    path = submit_path(request_id)
    raw = body({"code_r": code}) if raw is None else raw
    headers = device_headers(path, "POST", raw, key, private, anchor=anchor)
    return client.post(path, content=raw, headers=headers)


def list_codes(client, query="after=0"):
    path = CODES + ("?" + query if query else "")
    return client.get(path, headers=job_headers(path, "codes.read"))


def consume(client, attempt="1", request_id=REQUEST, permission="codes.consume"):
    path = INTERNAL + "/" + request_id + "/codes/" + attempt + "/consumed"
    return client.put(path, content=b"", headers=job_headers(path, permission, "PUT", b""))


def decide(client, status, acceptance=None, reason=None):
    raw = body(
        {
            "challenge_id": FLOW["challenge"]["claims"]["challenge_id"],
            "status": status,
            "acceptance": acceptance,
            "reason": reason,
        }
    )
    path = INTERNAL + "/" + REQUEST + "/decision"
    return client.put(path, content=raw, headers=job_headers(path, "decisions.publish", "PUT", raw))


def device_status(client):
    path = PREFIX + "/api/mycarlos/device-approval-requests/" + REQUEST
    return client.get(path, headers=device_headers(path)).json()


def stored(app):
    with app.state.session_factory() as s:
        return [
            (row.attempt, row.code_r, row.consumed_at)
            for row in s.scalars(select(ApprovalCode).order_by(ApprovalCode.attempt))
        ]


@pytest.fixture
def code_request(approval_http):  # noqa: F811 -- the reused fixture
    app, client = approval_http
    assert post_intent(client).status_code == 201
    published = put_challenge(client, CODE_CHALLENGE)
    assert published.status_code == 200, published.text
    return app, client


def test_every_shared_vector_recomputes_check_t_and_the_fixture_holds_no_digest():
    raw = (Path(__file__).parent / "fixtures/clinic-code-v1.json").read_text()
    assert not re.search(r"[0-9a-f]{64}", raw)
    assert VECTORS["label"] == "carlos-mycarlos-clinic-code-check-v1"
    assert len(VECTORS["vectors"]) == 5
    for vector in VECTORS["vectors"]:
        fields = (
            VECTORS["label"],
            vector["clinic_kid"],
            vector["device_key_id"],
            vector["request_id"],
            vector["code_r"],
        )
        digest = hashlib.sha256("\n".join(fields).encode()).digest()
        check_t = f"{int.from_bytes(digest[:8], 'big') % 1000:03d}"
        assert check_t == vector["check_t"]
        assert vector["code"] == vector["code_r"] + check_t
        assert vector["display"] == " ".join(re.findall("...", vector["code"]))


def test_code_kind_has_no_predecessor_and_its_acceptance_no_approval_hash():
    challenge, _, _ = object_claims("challenge", CODE_CHALLENGE, **SCOPE)
    assert challenge["approval_kind"] == "code" and challenge["predecessor_device_key_id"] is None
    accepted, _, _ = object_claims("acceptance", code_acceptance(), **SCOPE)
    assert accepted["approval_sha256"] is None
    later = F["flows"]["later"]
    with_predecessor = clinic_signed(dict(later["challenge"]["claims"], approval_kind="code"))
    with pytest.raises(MailboxRefusal):
        object_claims("challenge", with_predecessor, **SCOPE)
    with pytest.raises(MailboxRefusal):
        object_claims(
            "acceptance",
            clinic_signed(
                dict(FLOW["acceptance"]["claims"], approval_kind="code", approval_sha256="ab" * 32)
            ),
            **SCOPE,
        )
    for unknown in ["Code", "code_and_staff", "staff_only"]:
        claims = dict(FLOW["challenge"]["claims"], approval_kind=unknown)
        with pytest.raises(MailboxRefusal):
            object_claims("challenge", clinic_signed(claims), **SCOPE)


def test_code_roundtrip_submit_list_consume_and_accept(code_request):
    app, client = code_request
    assert device_status(client)["challenge"] == CODE_CHALLENGE
    # myCarlos sends its vault_head_link anchor here, as on device-approval-requests.
    submitted = submit(client, anchor="11" * 32)
    assert submitted.status_code == 202, submitted.text
    assert submitted.json() == {"status": "submitted"}
    listed = list_codes(client)
    assert listed.status_code == 200, listed.text
    assert listed.json() == {
        "codes": [
            {
                "sequence": "1",
                "request_id": REQUEST,
                "challenge_id": FLOW["challenge"]["claims"]["challenge_id"],
                "attempt": 1,
                "code_r": "482193",
                "submitted_at": F["now"],
            }
        ],
        "last_sequence": "1",
        "next_cursor": None,
    }
    for _ in range(2):
        result = consume(client)
        assert result.status_code == 200, result.text
        assert result.json() == {"status": "consumed"}
    assert stored(app) == [(1, None, F["now"])]
    assert list_codes(client).json()["codes"][0]["code_r"] is None
    acceptance = code_acceptance()  # ECDSA signatures differ each time: sign once
    accepted = decide(client, "accepted", acceptance=acceptance)
    assert accepted.status_code == 200, accepted.text
    status = device_status(client)
    assert status["status"] == "accepted" and status["acceptance"] == acceptance
    late = submit(client, "000000")
    assert late.status_code == 409 and late.json() == {"code": "approval_not_pending"}
    assert len(stored(app)) == 1


def test_acceptance_of_another_kind_cannot_close_a_code_request(code_request):
    _, client = code_request
    wrong = decide(client, "accepted", acceptance=code_acceptance(kind="staff_first"))
    assert wrong.status_code == 409, wrong.text
    assert device_status(client)["status"] == "challenge_ready"


def test_five_attempts_then_code_attempts_and_a_refusal_erases_codes(code_request):
    app, client = code_request
    for code in ["111111", "111111", "222222", "333333", "444444"]:
        assert submit(client, code).status_code == 202
    sixth = submit(client, "555555")
    assert sixth.status_code == 429, sixth.text
    assert sixth.json() == {"code": "code_attempts"}
    assert [row[:2] for row in stored(app)] == [
        (1, "111111"),
        (2, "111111"),
        (3, "222222"),
        (4, "333333"),
        (5, "444444"),
    ]
    refused = decide(client, "refused", reason="code_attempts")
    assert refused.status_code == 200, refused.text
    assert [row[1] for row in stored(app)] == [None] * 5
    status = device_status(client)
    assert (status["status"], status["reason"]) == ("refused", "code_attempts")
    after = submit(client, "666666")
    assert after.status_code == 409 and after.json() == {"code": "approval_not_pending"}


def test_only_a_code_challenge_takes_codes(approval_http):  # noqa: F811
    app, client = approval_http
    assert post_intent(client).status_code == 201
    early = submit(client)
    assert early.status_code == 409 and early.json() == {"code": "approval_not_code"}
    assert put_challenge(client).status_code == 200  # the fixture's staff_first challenge
    staff = submit(client)
    assert staff.status_code == 409 and staff.json() == {"code": "approval_not_code"}
    assert stored(app) == []


def test_expired_code_request_is_410_and_the_listing_erases_its_codes(code_request, monkeypatch):
    app, client = code_request
    assert submit(client).status_code == 202
    monkeypatch.setitem(F, "now", FLOW["challenge"]["claims"]["expires_at"])
    late = submit(client, "000000")
    assert late.status_code == 410 and late.json() == {"code": "approval_expired"}
    assert list_codes(client).json()["codes"][0]["code_r"] is None
    assert stored(app) == [(1, None, None)]


def test_another_device_or_request_gets_the_same_404(code_request):
    app, client = code_request
    other = F["keys"]["candidate"]
    with app.state.session_factory() as s, s.begin():
        account = s.scalar(select(PatientPortalAccount))
        s.add(
            PatientPortalMyCarlosDevice(
                account_id=account.id,
                device_key_id=other["device_key_id"],
                ed25519_public_key=strict_b64url_decode(other["ed25519_public_key"]),
                x25519_public_key=strict_b64url_decode(other["x25519_public_key"]),
                device_name="FAKE second device",
                status="active",
                linked_at=s.scalar(select(PatientPortalMyCarlosDevice.linked_at)),
            )
        )
    label = other["ed25519_seed_text"].removeprefix(ref.SEED_PREFIX).removesuffix(" ed25519")
    other_private = ref.DeviceKeys(label).ed25519
    for result in [
        submit(client, key=other, private=other_private),
        submit(client, request_id=str(uuid4())),
        submit(client, request_id="not-a-request"),
        submit(client, request_id=REQUEST.upper()),
    ]:
        assert result.status_code == 404, result.text
        assert result.json() == {"code": "approval_not_found"}
    assert stored(app) == []


@pytest.mark.parametrize(
    "raw",
    [
        body({"code_r": "48219"}),
        body({"code_r": "4821930"}),
        body({"code_r": "48219a"}),
        body({"code_r": " 82193"}),
        body({"code_r": "４８２１９３"}),  # full-width digits
        body({"code_r": 482193}),
        body({"code_r": None}),
        body({"code_r": "482193", "check_t": "644"}),
        body({"code": "482193644"}),
        body({}),
        body(["482193"]),
        b"482193",
    ],
)
def test_only_exactly_six_ascii_digits_are_stored(code_request, raw):
    app, client = code_request
    result = submit(client, raw=raw)
    assert result.status_code == 400, result.text
    assert result.json() == {"code": "invalid_approval"}
    assert stored(app) == []


def test_query_string_and_oversized_body_are_refused(code_request):
    app, client = code_request
    path = submit_path() + "?code_r=482193"
    raw = body({"code_r": "482193"})
    result = client.post(path, content=raw, headers=device_headers(path, "POST", raw))
    assert result.status_code == 400 and result.json() == {"code": "invalid_approval"}
    big = body({"code_r": "482193", "pad": "x" * 256})
    result = submit(client, raw=big)
    assert result.status_code == 413 and result.json() == {"detail": "request too large"}
    assert stored(app) == []


def test_assertion_binds_body_path_and_is_single_use(code_request):
    app, client = code_request
    path = submit_path()
    raw = body({"code_r": "482193"})
    assert client.post(path, content=raw).status_code == 404
    signed_other = device_headers(path, "POST", body({"code_r": "000000"}))
    assert client.post(path, content=raw, headers=signed_other).json() == {"detail": "not found"}
    unprefixed = device_headers(path.removeprefix(PREFIX), "POST", raw)
    assert client.post(path, content=raw, headers=unprefixed).status_code == 404
    headers = device_headers(path, "POST", raw)
    assert client.post(path, content=raw, headers=headers).status_code == 202
    replay = client.post(path, content=raw, headers=headers)
    assert replay.status_code == 404 and replay.json() == {"detail": "not found"}
    assert stored(app) == [(1, "482193", None)]


def test_job_routes_take_only_their_own_permission(code_request):
    _, client = code_request
    assert submit(client).status_code == 202
    path = CODES + "?after=0"
    wrong = client.get(path, headers=job_headers(path, "requests.read"))
    assert wrong.status_code == 403, wrong.text
    assert consume(client, permission="codes.read").status_code == 403
    assert list_codes(client).json()["codes"][0]["code_r"] == "482193"


def test_consume_refuses_unknown_attempts_and_requests(code_request):
    _, client = code_request
    assert submit(client).status_code == 202
    for attempt in ["2", "0", "6", "01", "1x", "+1"]:
        result = consume(client, attempt)
        assert result.status_code == 404, (attempt, result.text)
        assert result.json() == {"code": "approval_not_found"}
    assert consume(client, request_id=str(uuid4())).status_code == 404
    path = INTERNAL + "/" + REQUEST + "/codes/1/consumed"
    body_sent = client.put(
        path, content=b"{}", headers=job_headers(path, "codes.consume", "PUT", b"{}")
    )
    assert body_sent.status_code == 413
    path += "?x=1"
    query = client.put(path, content=b"", headers=job_headers(path, "codes.consume", "PUT"))
    assert query.status_code == 400 and query.json() == {"code": "invalid_approval"}
    assert list_codes(client).json()["codes"][0]["code_r"] == "482193"


def test_code_listing_pages_by_cursor(code_request):
    _, client = code_request
    for code in ["111111", "222222", "333333"]:
        assert submit(client, code).status_code == 202
    first = list_codes(client, "after=0&limit=2").json()
    assert [c["attempt"] for c in first["codes"]] == [1, 2]
    assert (first["last_sequence"], first["next_cursor"]) == ("2", "2")
    rest = list_codes(client, "after=2&limit=2").json()
    assert [c["code_r"] for c in rest["codes"]] == ["333333"]
    assert (rest["last_sequence"], rest["next_cursor"]) == ("3", None)
    assert list_codes(client, "").json()["last_sequence"] == "3"
    for query in ["after=4", "after=-1", "limit=21", "after=0&after=1", "other=1"]:
        result = list_codes(client, query)
        assert result.status_code == 400, (query, result.text)
        assert result.json() == {"code": "invalid_cursor"}


def migrate(engine, direction, revision):
    with engine.begin() as connection:
        config = alembic_config_for_tests()
        config.attributes["connection"] = connection
        getattr(command, direction)(config, revision)


def test_0020_downgrades_empty_and_reupgrades_without_drift():
    app = internal_app()
    engine = app.state.database_engine
    assert "patient_portal_mycarlos_approval_codes" in inspect(engine).get_table_names()
    migrate(engine, "downgrade", "0018_mycarlos_mailbox_approval")
    assert "patient_portal_mycarlos_approval_codes" not in inspect(engine).get_table_names()
    columns = {c["name"] for c in inspect(engine).get_columns(ApprovalClinic.__tablename__)}
    assert "code_sequence" not in columns
    migrate(engine, "upgrade", "head")
    columns = {c["name"] for c in inspect(engine).get_columns(ApprovalClinic.__tablename__)}
    assert "code_sequence" in columns
    with engine.connect() as connection:
        generated = produce_migrations(
            MigrationContext.configure(connection),
            [Base.metadata, MailboxBase.metadata, ApprovalBase.metadata],
        )
    approval_tables = set(ApprovalBase.metadata.tables)
    assert not [
        op for op in generated.upgrade_ops.ops if getattr(op, "table_name", None) in approval_tables
    ]


def test_a_stored_code_attempt_refuses_downgrade(code_request):
    app, client = code_request
    assert submit(client).status_code == 202
    assert consume(client).status_code == 200
    engine = app.state.database_engine
    with pytest.raises(RuntimeError, match="retained proof/history"):
        migrate(engine, "downgrade", "0018_mycarlos_mailbox_approval")
    assert stored(app) == [(1, None, F["now"])]
    with app.state.session_factory() as s:
        assert s.scalar(select(ApprovalRequest.status)) == "challenge_ready"
