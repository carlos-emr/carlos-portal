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

"""Signed actual HTTP through a stripping proxy; FAKE custody is not native proof."""

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select

from carlos_patient_portal.database import Base
from carlos_patient_portal.mailbox_codec import parse_upload
from carlos_patient_portal.mailbox_models import MailboxAnchor, MailboxBlob, MailboxCopy
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
)
from carlos_patient_portal.routes import mycarlos_mailbox
from tests import delivery_contract_reference as ref
from tests.support import carlos_job_headers
from tests.test_internal_api import internal_app

M4 = json.loads((Path(__file__).parent / "fixtures/mailbox-contract-v1.json").read_bytes())
M0 = json.loads((Path(__file__).parent / "fixtures/delivery-contract.json").read_bytes())
BODY = bytes.fromhex(M4["uploads"][0]["body"]["hex"])
OUTER = parse_upload(BODY).outer
NOW = M0["portal"]["state"]["now"]
DEVICE = ref.DeviceKeys("device 1")
JOB = ref.DeviceKeys("FAKE independent M4 delivery job")
JOB_KID = "FAKE-delivery-sync-key"
PREFIX = "/patients"
UPLOAD_PATH = "/internal/carlos/patients/6001/mycarlos/deliveries"
LIST_PATH = PREFIX + "/api/mycarlos/deliveries"
COPY_PATH = LIST_PATH + "/" + OUTER["delivery_id"]


class SplitIngressProxy:
    """Current CARLOS internal origin is root; patient device ingress strips public prefix."""

    def __init__(self, app, configured_prefix=PREFIX, wire_prefix=PREFIX):
        self.app = app
        self.configured_prefix = configured_prefix
        self.decoded_prefix = unquote(configured_prefix)
        self.wire_prefix = wire_prefix
        self.observed_paths = []
        self.forwarded_scopes = []

    async def __call__(self, scope, receive, send):
        forwarded = dict(scope)
        if scope["type"] == "http":
            self.observed_paths.append(scope["raw_path"])
            if scope["raw_path"].startswith(b"/internal/carlos/"):
                assert scope["path"].startswith("/internal/carlos/")
            else:
                assert scope["raw_path"].startswith(self.wire_prefix.encode("ascii") + b"/api/")
                assert scope["path"].startswith(self.decoded_prefix + "/api/")
                forwarded["path"] = scope["path"][len(self.decoded_prefix) :]
                forwarded["raw_path"] = scope["raw_path"][len(self.wire_prefix) :]
        await self.app(forwarded, receive, send)
        if scope["type"] == "http":
            self.forwarded_scopes.append((scope["raw_path"], dict(forwarded)))


@pytest.fixture
def http_mailbox(monkeypatch, request):
    monkeypatch.setattr(mycarlos_mailbox, "time", lambda: NOW)
    configured_prefix, wire_prefix = getattr(request, "param", (PREFIX, PREFIX))
    app = internal_app(
        mycarlos_delivery_enabled=True,
        mycarlos_mailbox_enabled=True,
        public_base_url="https://portal.example.test" + configured_prefix,
        internal_job_assertion_public_keyring=json.dumps(
            {"delivery-sync": {JOB_KID: ref.b64url(JOB.ed25519_public)}}
        ),
    )
    tables = [table for name, table in Base.metadata.tables.items() if "mycarlos_mailbox_" in name]
    Base.metadata.create_all(app.state.database_engine, tables=tables)
    with app.state.session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id="clinic-a",
            demographic_no=6001,
            username="fake.mailbox",
            email="fake.mailbox@example.test",
            password_hash="FAKE-unused",
            status="active",
        )
        session.add(account)
        session.flush()
        session.add(
            PatientPortalMyCarlosRecipient(
                account_id=account.id, recipient_id=OUTER["recipient_id"]
            )
        )
        session.add(
            PatientPortalMyCarlosDevice(
                account_id=account.id,
                device_key_id=DEVICE.device_key_id,
                ed25519_public_key=DEVICE.ed25519_public,
                x25519_public_key=DEVICE.x25519_public,
                device_name="FAKE M4 actual HTTP device",
                status="active",
                linked_at=datetime.fromtimestamp(NOW, tz=UTC),
            )
        )
    proxy = SplitIngressProxy(app, configured_prefix, wire_prefix)
    return app, TestClient(proxy, base_url="https://portal.example.test"), proxy


def job_headers(
    path=UPLOAD_PATH, *, body=BODY, permission="portal.mycarlos.delivery.upload", method="POST"
):
    return carlos_job_headers(
        "delivery-sync",
        permission,
        method=method,
        path=path,
        body=body,
        clinic_id="clinic-a",
        key_id=JOB_KID,
        signing_key=JOB.ed25519,
    ) | {"Content-Type": "application/octet-stream"}


def device_headers(path, *, method="GET", body=b"", anchor=None):
    raw, _, query = path.partition("?")
    claims = {
        "aud": ref.DEVICE_AUDIENCE,
        "iss": "mycarlos",
        "kid": DEVICE.device_key_id,
        "recipient_id": OUTER["recipient_id"],
        "jti": str(uuid4()),
        "iat": NOW,
        "exp": NOW + 60,
        "request_hash": ref.request_hash(method, raw.encode(), query.encode(), body),
    }
    if anchor is not None:
        claims["vault_head_link"] = anchor
    return {"X-MyCarlos-Device-Assertion": ref.compact_ed25519(DEVICE.ed25519, claims)}


def test_binary_job_upload_binds_internal_origin_root_independently_of_public_prefix(http_mailbox):
    app, client, proxy = http_mailbox
    bad = client.post(UPLOAD_PATH, content=BODY, headers=job_headers(PREFIX + UPLOAD_PATH))
    assert bad.status_code == 404
    changed = BODY[:-1] + bytes([BODY[-1] ^ 1])
    assert client.post(UPLOAD_PATH, content=changed, headers=job_headers()).status_code == 404
    assert client.post(UPLOAD_PATH, content=BODY, headers=job_headers()).status_code == 201
    assert proxy.observed_paths[-1] == UPLOAD_PATH.encode()
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(MailboxCopy)) == 1
        assert session.scalar(select(MailboxBlob.sealed)) == parse_upload(BODY).sealed


def test_signed_list_download_receipt_and_anchor_survive_actual_http(http_mailbox, monkeypatch):
    app, client, _proxy = http_mailbox
    assert client.post(UPLOAD_PATH, content=BODY, headers=job_headers()).status_code == 201
    listed = client.get(LIST_PATH, headers=device_headers(LIST_PATH, anchor="11" * 32))
    assert listed.status_code == 200
    assert listed.json()["deliveries"] == [OUTER]
    assert listed.json()["anchor_recorded"] is True
    downloaded = client.get(COPY_PATH, headers=device_headers(COPY_PATH))
    assert downloaded.status_code == 200 and downloaded.content == parse_upload(BODY).sealed
    assert downloaded.headers["cache-control"] == "no-store"
    receipt = next(
        value["receipt"] for value in M0["portal"]["receipts"] if value["expect"] == "accept"
    )
    body = json.dumps({"receipt": receipt}, separators=(",", ":")).encode()
    path = COPY_PATH + "/receipt"
    # This server test has no actual native custody. Its fixture receipt is public FAKE evidence.
    from carlos_patient_portal import mailbox

    original = mailbox.accept_receipt
    monkeypatch.setattr(
        mycarlos_mailbox,
        "accept_receipt",
        lambda *args, **kwargs: original(*args, **kwargs, clock=lambda: NOW),
    )
    accepted = client.post(
        path, content=body, headers=device_headers(path, method="POST", body=body)
    )
    assert accepted.status_code == 200 and accepted.json() == {"status": "picked_up"}
    assert client.get(COPY_PATH, headers=device_headers(COPY_PATH)).status_code == 404
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count()).select_from(MailboxBlob)) == 0
        assert session.scalar(select(MailboxCopy.status)) == "picked_up"
        assert session.scalar(select(func.count()).select_from(MailboxAnchor)) == 2
    anchors_path = PREFIX + "/api/mycarlos/anchors"
    anchors = client.get(anchors_path, headers=device_headers(anchors_path))
    assert anchors.status_code == 200
    assert [value["proof_kind"] for value in anchors.json()["anchors"]] == ["request", "receipt"]


def test_mailbox_routes_are_absent_with_only_m2_linking_enabled():
    app = internal_app(mycarlos_delivery_enabled=True, mycarlos_mailbox_enabled=False)
    paths = {route.path for route in app.routes}
    assert "/api/mycarlos/deliveries" not in paths
    assert "/internal/carlos/patients/{demographic_no}/mycarlos/deliveries" not in paths


@pytest.mark.parametrize(
    "http_mailbox",
    [
        pytest.param(("/café", "/caf%C3%A9"), id="latin-accent"),
        pytest.param(("/患者", "/%E6%82%A3%E8%80%85"), id="cjk"),
        pytest.param(("/cafe\u0301", "/cafe%CC%81"), id="decomposed-unicode"),
        pytest.param(("/caf%C3%A9", "/caf%C3%A9"), id="already-escaped"),
    ],
    indirect=True,
)
def test_unicode_public_mailbox_auth_stays_separate_from_internal_root(
    http_mailbox, monkeypatch, record_property
):
    app, client, proxy = http_mailbox
    captured = []
    original_path = mycarlos_mailbox.signed_path

    def capture_path(runtime, request):
        signed = original_path(runtime, request)
        captured.append((signed, dict(request.scope)))
        return signed

    monkeypatch.setattr(mycarlos_mailbox, "signed_path", capture_path)
    # A public prefix never belongs to the independently configured internal job target.
    wrong_internal = {
        proxy.configured_prefix + UPLOAD_PATH,
        proxy.wire_prefix + UPLOAD_PATH,
    }
    for signed_target in wrong_internal:
        assert (
            client.post(UPLOAD_PATH, content=BODY, headers=job_headers(signed_target)).status_code
            == 404
        )
    assert client.post(UPLOAD_PATH, content=BODY, headers=job_headers()).status_code == 201
    internal_external, internal_scope = proxy.forwarded_scopes[-1]
    assert internal_external == internal_scope["raw_path"] == UPLOAD_PATH.encode("ascii")
    assert internal_scope["path"] == UPLOAD_PATH
    assert internal_scope["root_path"] == app.root_path == proxy.configured_prefix

    def wire_trace(method, external_target, body=b""):
        signed, scope = captured[-1]
        assert scope["method"] == method
        assert signed == external_target.encode("ascii")
        assert scope["raw_path"] == external_target[len(proxy.wire_prefix) :].encode("ascii")
        assert scope["path"] == scope["raw_path"].decode("ascii")
        assert scope["root_path"] == app.root_path == proxy.configured_prefix
        assert scope["query_string"] == b""
        return {
            "method": method,
            "external_target_ascii": external_target,
            "asgi_path": scope["path"],
            "asgi_raw_path_hex": scope["raw_path"].hex(),
            "root_path_preserved": scope["root_path"],
            "server_signed_path_hex": signed.hex(),
            "expected_request_hash": ref.request_hash(method, signed, b"", body),
            "body_hex": body.hex(),
        }

    route = "/api/mycarlos/deliveries"
    public_list = proxy.wire_prefix + route
    wrong_public = {route}
    if proxy.configured_prefix != proxy.wire_prefix:
        wrong_public.add(proxy.configured_prefix + route)
    for signed_target in wrong_public:
        assert client.get(public_list, headers=device_headers(signed_target)).status_code == 404
    listed = client.get(public_list, headers=device_headers(public_list))
    assert listed.status_code == 200 and listed.json()["deliveries"] == [OUTER]
    list_trace = wire_trace("GET", public_list)
    public_copy = public_list + "/" + OUTER["delivery_id"]
    downloaded = client.get(public_copy, headers=device_headers(public_copy))
    assert downloaded.status_code == 200 and downloaded.content == parse_upload(BODY).sealed

    receipt = next(
        value["receipt"] for value in M0["portal"]["receipts"] if value["expect"] == "accept"
    )
    body = json.dumps({"receipt": receipt}, separators=(",", ":")).encode()
    receipt_path = public_copy + "/receipt"
    # Reuse the real server receipt verifier/state transition with the fixture clock only.
    # This remains public FAKE receipt evidence, not native custody or clinical verification.
    from carlos_patient_portal import mailbox

    original_receipt = mailbox.accept_receipt
    monkeypatch.setattr(
        mycarlos_mailbox,
        "accept_receipt",
        lambda *args, **kwargs: original_receipt(*args, **kwargs, clock=lambda: NOW),
    )
    missing_prefix = receipt_path[len(proxy.wire_prefix) :]
    assert (
        client.post(
            receipt_path,
            content=body,
            headers=device_headers(missing_prefix, method="POST", body=body),
        ).status_code
        == 404
    )
    assert (
        client.post(
            receipt_path,
            content=body + b" ",
            headers=device_headers(receipt_path, method="POST", body=body),
        ).status_code
        == 404
    )
    good = device_headers(receipt_path, method="POST", body=body)
    accepted = client.post(receipt_path, content=body, headers=good)
    assert accepted.status_code == 200 and accepted.json() == {"status": "picked_up"}
    receipt_trace = wire_trace("POST", receipt_path, body)
    assert client.post(receipt_path, content=body, headers=good).status_code == 404
    with app.state.session_factory() as session:
        assert session.scalar(select(MailboxCopy.status)) == "picked_up"
        assert session.scalar(select(func.count()).select_from(MailboxBlob)) == 0
    record_property(
        "m4_boundary_trace",
        json.dumps(
            {
                "configured_public_prefix": proxy.configured_prefix,
                "internal_external_target": internal_external.decode("ascii"),
                "internal_asgi_raw_path_hex": internal_scope["raw_path"].hex(),
                "internal_framework_root_path": internal_scope["root_path"],
                "internal_request_hash": ref.request_hash("POST", internal_external, b"", BODY),
                "public_get": list_trace,
                "public_post": receipt_trace,
            }
        ),
    )
