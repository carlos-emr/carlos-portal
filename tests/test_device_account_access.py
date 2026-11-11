# SPDX-License-Identifier: AGPL-3.0-or-later
"""Gateway-local account access using signed requests and retained synthetic records."""

from contextlib import ExitStack
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.auth import set_patient_account_access
from carlos_patient_portal.device_identity import (
    LINK_RECOVERY_AUDIENCE,
    lock_active_device_account,
)
from carlos_patient_portal.mailbox import TERMINAL_RESERVATION, mailbox_lock
from carlos_patient_portal.mailbox_models import MailboxBase, MailboxBlob, MailboxCopy
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosWaitingKey,
)
from carlos_patient_portal.mycarlos_devices import remove_device
from carlos_patient_portal.routes import mycarlos, mycarlos_availability, mycarlos_mailbox
from tests import delivery_contract_reference as ref
from tests.test_internal_api import internal_app
from tests.test_mycarlos_availability_routes import Device, enrollment, seed, signed
from tests.test_mycarlos_waiting_routes import NOW, WaitingKey, add_copy, ask, register

SUBSCRIPTIONS = "/api/mycarlos/availability/subscriptions"
WAITING_KEYS = "/api/mycarlos/availability/waiting-keys"


@pytest.fixture
def gateways(monkeypatch):
    monkeypatch.setattr(mycarlos, "mycarlos_clock", lambda: NOW)
    monkeypatch.setattr(mycarlos_mailbox, "time", lambda: NOW)
    monkeypatch.setattr(mycarlos_availability, "time", lambda: NOW)
    with ExitStack() as stack:
        result = []
        for label in ("a", "b"):
            host = f"https://gateway-{label}.example.test"
            app = internal_app(
                mycarlos_delivery_enabled=True,
                mycarlos_mailbox_enabled=True,
                mycarlos_availability_enabled=True,
                public_base_url=host,
            )
            MailboxBase.metadata.create_all(app.state.database_engine)
            device = Device(f"account-access-{label}")
            seed(app, device, 7201)
            add_copy(app, device, expires_at=NOW + 600)
            with app.state.session_factory() as session, session.begin():
                copy = session.scalars(select(MailboxCopy)).one()
                session.add(MailboxBlob(copy_id=copy.id, sealed=b"x" * copy.size))
                m = mailbox_lock(
                    session, account_id=copy.account_id, device_key_id=device.keys.device_key_id
                )
                m.device_quota.delivery_sequence = copy.sequence
                for quota in (m.clinic, m.account_quota, m.device_quota):
                    quota.waiting_count = 1
                    quota.waiting_bytes = copy.size
                m.clinic.reserved_terminal_bytes = TERMINAL_RESERVATION
                delivery_id = copy.delivery_id
            # Match the existing mailbox HTTP fixtures: do not start maintenance workers
            # against the in-memory database used to exercise request transactions.
            client = TestClient(app, base_url=host)
            stack.callback(client.close)
            stack.callback(app.state.database_engine.dispose)
            key = WaitingKey(f"account-access-{label}")
            assert register(client, device, key).status_code == 201
            body = enrollment()
            response = client.post(
                SUBSCRIPTIONS, content=body, headers=signed(device, "POST", SUBSCRIPTIONS, body)
            )
            assert response.status_code == 201
            result.append((app, client, device, key, delivery_id, response.json()))
        yield result


def access(gateway, enabled):
    app, _client, device, *_ = gateway
    with app.state.session_factory() as session, session.begin():
        account = session.scalars(select(PatientPortalAccount)).one()
        set_patient_account_access(
            session, account.id, "FAKE staff", enabled=enabled, clinic_id="clinic-a"
        )


def request(gateway, method, path, body=b""):
    _app, client, device, *_ = gateway
    headers = signed(device, method, path, body)
    if path == "/api/mycarlos/link":
        claims = {
            "aud": LINK_RECOVERY_AUDIENCE,
            "iss": "mycarlos",
            "kid": device.keys.device_key_id,
            "jti": str(uuid4()),
            "iat": NOW,
            "exp": NOW + 60,
            "request_hash": ref.request_hash(method, path.encode(), b"", body),
        }
        headers = {"X-MyCarlos-Device-Assertion": ref.compact_ed25519(device.keys.ed25519, claims)}
    return client.request(method, path, content=body, headers=headers)


def retained(gateway):
    app, *_ = gateway
    with app.state.session_factory() as session:
        device = session.scalars(select(PatientPortalMyCarlosDevice)).one()
        key = session.scalars(select(PatientPortalMyCarlosWaitingKey)).one()
        subscription = session.scalars(select(PatientPortalMyCarlosAvailabilitySubscription)).one()
        copy = session.scalars(select(MailboxCopy)).one()
        return (
            device.status,
            key.key_id,
            key.revoked_at,
            key.last_answered_at,
            subscription.subscription_id,
            subscription.revoked_at,
            copy.delivery_id,
            copy.status,
            session.get(MailboxBlob, copy.id).sealed,
        )


@pytest.mark.parametrize(
    "method,path,body,active_status",
    [
        ("GET", "/api/mycarlos/deliveries", b"", 200),
        ("GET", "/api/mycarlos/deliveries/{copy}", b"", 200),
        ("POST", "/api/mycarlos/deliveries/{copy}/receipt", b"{}", 400),
        ("GET", "/api/mycarlos/anchors", b"", 200),
        ("GET", "/api/mycarlos/link", b"", 409),
        ("GET", "/api/mycarlos/clinic-keys", b"", 409),
        ("GET", SUBSCRIPTIONS, b"", 200),
        ("POST", SUBSCRIPTIONS, b"{}", 400),
        ("DELETE", SUBSCRIPTIONS + "/{subscription}", b"", 200),
        ("POST", WAITING_KEYS, b"{}", 400),
        ("DELETE", WAITING_KEYS + "/{key}", b"", 200),
    ],
)
def test_disabled_gateway_does_not_disable_another_gateway(
    gateways,
    method,
    path,
    body,
    active_status,
):
    a, b = gateways

    def target(gateway):
        return path.format(
            copy=gateway[4], key=gateway[3].key_id, subscription=gateway[5]["subscription_id"]
        )

    access(a, False)
    before = retained(a)
    response = request(a, method, target(a), body)
    assert response.status_code == 404
    assert response.json() == {"detail": "not found"}
    assert retained(a) == before
    assert request(b, "GET", "/api/mycarlos/deliveries").status_code == 200
    access(a, True)
    assert request(a, method, target(a), body).status_code == active_status


def test_waiting_access_resumes_only_for_its_own_gateway(gateways):
    a, b = gateways
    access(a, False)
    before = retained(a)
    assert ask(a[1], a[3]).status_code == 404
    assert ask(a[1], a[3], method="DELETE").status_code == 404
    assert retained(a) == before
    assert ask(b[1], b[3]).json() == {"waiting": True}
    access(a, True)
    assert ask(a[1], a[3]).json() == {"waiting": True}
    # Explicit removal while disabled still cleans up; re-enable never resurrects it.
    access(a, False)
    with a[0].state.session_factory() as session, session.begin():
        account = session.scalars(select(PatientPortalAccount)).one()
        remove_device(
            session,
            account_id=account.id,
            device_key_id=a[2].keys.device_key_id,
            removed_by="staff",
            now=datetime.fromtimestamp(NOW, tz=UTC),
            mailbox_enabled=True,
        )
    access(a, True)
    assert ask(a[1], a[3]).status_code == 404
    assert request(a, "GET", "/api/mycarlos/deliveries").status_code == 403
    # B remains linked and can fetch its sealed copy, independently of A's removal.
    assert request(b, "GET", f"/api/mycarlos/deliveries/{b[4]}").content == b"x" * 49


def test_account_guard_refreshes_a_cached_account_without_touching_another(gateways):
    a, b = gateways
    with a[0].state.session_factory() as stale:
        account = stale.scalars(select(PatientPortalAccount)).one()
        stale.commit()
        assert account.status == "active"
        account_id = account.id
        access(a, False)
        assert account.status == "active"
        assert not lock_active_device_account(stale, account.id)
        assert account.status == "disabled"
        stale.rollback()
    assert request(b, "GET", "/api/mycarlos/deliveries").status_code == 200
    access(a, True)
    with a[0].state.session_factory() as session:
        assert lock_active_device_account(session, account_id)
