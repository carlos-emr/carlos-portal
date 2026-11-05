# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The device's availability enrollment routes (P1): enroll, list, revoke.

Each request is signed by a FAKE linked device as myCarlos signs it (tests/
delivery_contract_reference.py), and checked by the same device-assertion code the mailbox
routes use. Nothing is sent: these routes only store what the device reports.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
)
from carlos_patient_portal.routes import mycarlos_availability
from tests import delivery_contract_reference as ref
from tests.test_internal_api import internal_app

NOW = 1_793_800_000
PATH = "/api/mycarlos/availability/subscriptions"
RECORD_KEYS = {
    "subscription_id",
    "epoch",
    "destination_id",
    "platform",
    "remote_enabled",
    "remote_consent_version",
    "permission_observed",
    "enrolled_at",
    "revoked",
}


class Device:
    def __init__(self, label: str) -> None:
        self.keys = ref.DeviceKeys(f"FAKE availability {label}")
        self.recipient_id = f"FAKE-recipient-{label}"
        self.username = f"fake.availability.{label}"


A = Device("a")
B = Device("b")


def enabled_app(**overrides: object):  # noqa: ANN201
    return internal_app(
        mycarlos_delivery_enabled=True,
        mycarlos_availability_enabled=True,
        public_base_url="https://portal.example.test",
        **overrides,
    )


def seed(app, device: Device, demographic_no: int, *, status: str = "active") -> None:  # noqa: ANN001
    with app.state.session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id="clinic-a",
            demographic_no=demographic_no,
            username=device.username,
            email=f"{device.username}@example.test",
            password_hash="FAKE-unused",
            status="active",
        )
        session.add(account)
        session.flush()
        session.add(
            PatientPortalMyCarlosRecipient(account_id=account.id, recipient_id=device.recipient_id)
        )
        session.add(
            PatientPortalMyCarlosDevice(
                account_id=account.id,
                device_key_id=device.keys.device_key_id,
                ed25519_public_key=device.keys.ed25519_public,
                x25519_public_key=device.keys.x25519_public,
                device_name="FAKE availability device",
                status=status,
                linked_at=datetime.fromtimestamp(NOW, tz=UTC),
                removed_at=datetime.fromtimestamp(NOW, tz=UTC) if status != "active" else None,
                removed_by="patient" if status != "active" else None,
            )
        )


@pytest.fixture
def portal(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[object, TestClient]]:
    monkeypatch.setattr(mycarlos_availability, "time", lambda: NOW)
    app = enabled_app()
    seed(app, A, 7001)
    seed(app, B, 7002)
    with TestClient(app, base_url="https://portal.example.test") as client:
        yield app, client


def signed(device: Device, method: str, path: str, body: bytes = b"") -> dict[str, str]:
    raw, _, query = path.partition("?")
    claims = {
        "aud": ref.DEVICE_AUDIENCE,
        "iss": "mycarlos",
        "kid": device.keys.device_key_id,
        "recipient_id": device.recipient_id,
        "jti": str(uuid4()),
        "iat": NOW,
        "exp": NOW + 60,
        "request_hash": ref.request_hash(method, raw.encode(), query.encode(), body),
    }
    return {"X-MyCarlos-Device-Assertion": ref.compact_ed25519(device.keys.ed25519, claims)}


def enrollment(**changes: object) -> bytes:
    return json.dumps(
        {
            "platform": "android_fcm",
            "destination_id": str(uuid4()),
            "remote_enabled": True,
            "remote_consent_version": 1,
            "permission_observed": True,
            **changes,
        }
    ).encode()


def post(client: TestClient, device: Device, body: bytes):  # noqa: ANN201
    return client.post(
        PATH,
        content=body,
        headers=signed(device, "POST", PATH, body) | {"Content-Type": "application/json"},
    )


def get(client: TestClient, device: Device):  # noqa: ANN201
    return client.get(PATH, headers=signed(device, "GET", PATH))


def delete(client: TestClient, device: Device, subscription_id: str):  # noqa: ANN201
    path = f"{PATH}/{subscription_id}"
    return client.delete(path, headers=signed(device, "DELETE", path))


@pytest.mark.parametrize(
    "switches",
    [
        {},
        {"mycarlos_delivery_enabled": True},
        {"mycarlos_availability_enabled": True},
    ],
)
def test_the_routes_exist_only_with_both_switches_on(switches: dict[str, object]) -> None:
    app = internal_app(**switches)
    paths = {getattr(route, "path", "") for route in app.routes}
    assert PATH not in paths
    assert f"{PATH}/{{subscription_id}}" not in paths
    assert PATH in {getattr(route, "path", "") for route in enabled_app().routes}


def test_a_device_enrolls_lists_and_revokes_its_destination(portal) -> None:
    _app, client = portal
    destination = str(uuid4())
    created = post(client, A, enrollment(destination_id=destination))
    assert created.status_code == 201
    assert created.headers["cache-control"] == "no-store"
    record = created.json()
    assert set(record) == RECORD_KEYS
    assert record["destination_id"] == destination
    assert (record["platform"], record["remote_enabled"], record["revoked"]) == (
        "android_fcm",
        True,
        False,
    )
    # Enrolling the same destination again returns the same subscription.
    again = post(client, A, enrollment(destination_id=destination, remote_enabled=False))
    assert again.status_code == 200
    assert again.json()["subscription_id"] == record["subscription_id"]
    assert again.json()["remote_enabled"] is False

    listed = get(client, A)
    assert listed.status_code == 200
    assert [s["subscription_id"] for s in listed.json()["subscriptions"]] == [
        record["subscription_id"]
    ]

    revoked = delete(client, A, record["subscription_id"])
    assert revoked.status_code == 200
    assert (revoked.json()["revoked"], revoked.json()["remote_enabled"]) == (True, False)
    # The tombstone is still listed, and the destination cannot come back.
    assert get(client, A).json()["subscriptions"][0]["revoked"] is True
    refused = post(client, A, enrollment(destination_id=destination))
    assert (refused.status_code, refused.json()) == (409, {"code": "destination_revoked"})


@pytest.mark.parametrize(
    ("changes", "status", "code"),
    [
        ({"remote_consent_version": 0}, 422, "consent_required"),
        ({"permission_observed": False}, 422, "consent_required"),
        ({"platform": "FAKE_push"}, 400, "invalid_platform"),
        ({"destination_id": "FAKE"}, 400, "invalid_destination"),
        ({"remote_enabled": "yes"}, 400, "invalid_enrollment"),
        ({"remote_consent_version": True}, 400, "invalid_enrollment"),
        ({"note": "FAKE extra field"}, 400, "invalid_enrollment"),
    ],
)
def test_an_enrollment_without_consent_or_with_a_wrong_field_is_refused(
    portal, changes: dict[str, object], status: int, code: str
) -> None:
    app, client = portal
    refused = post(client, A, enrollment(**changes))
    assert (refused.status_code, refused.json()) == (status, {"code": code})
    with app.state.session_factory() as session:
        assert session.scalars(select(PatientPortalMyCarlosAvailabilitySubscription)).all() == []


def test_a_body_that_is_not_the_five_fields_or_too_large_is_refused(portal) -> None:
    _app, client = portal
    assert post(client, A, b"[]").json() == {"code": "invalid_enrollment"}
    assert post(client, A, b"\xff").json() == {"code": "invalid_enrollment"}
    too_large = post(client, A, b" " * 2000)
    assert too_large.status_code == 413


def test_another_device_cannot_see_take_or_revoke_a_destination(portal) -> None:
    _app, client = portal
    destination = str(uuid4())
    record = post(client, A, enrollment(destination_id=destination)).json()
    assert get(client, B).json() == {"subscriptions": []}
    taken = post(client, B, enrollment(destination_id=destination))
    assert (taken.status_code, taken.json()) == (409, {"code": "destination_taken"})
    foreign = delete(client, B, record["subscription_id"])
    assert (foreign.status_code, foreign.json()) == (404, {"detail": "not found"})
    assert get(client, A).json()["subscriptions"][0]["revoked"] is False


def test_unsigned_replayed_or_mis_signed_requests_are_not_found(portal) -> None:
    _app, client = portal
    assert client.get(PATH).status_code == 404
    headers = signed(A, "GET", PATH)
    assert client.get(PATH, headers=headers).status_code == 200
    # The assertion's nonce is used once.
    assert client.get(PATH, headers=headers).status_code == 404
    # Signed for another request (a different body).
    body = enrollment()
    wrong = client.post(PATH, content=body, headers=signed(A, "POST", PATH, b"{}"))
    assert wrong.status_code == 404
    # A query string is not part of these routes.
    query = PATH + "?all=1"
    assert client.get(query, headers=signed(A, "GET", query)).status_code == 404


def test_a_removed_device_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mycarlos_availability, "time", lambda: NOW)
    app = enabled_app()
    seed(app, A, 7001, status="removed")
    with TestClient(app, base_url="https://portal.example.test") as client:
        refused = post(client, A, enrollment())
    assert (refused.status_code, refused.json()) == (403, {"code": "device_removed"})


def test_a_device_reaches_sixteen_destinations_and_no_more(portal) -> None:
    _app, client = portal
    for _ in range(16):
        assert post(client, A, enrollment()).status_code == 201
    full = post(client, A, enrollment())
    assert (full.status_code, full.json()) == (409, {"code": "destination_capacity"})


def test_responses_say_nothing_about_the_patient(portal) -> None:
    app, client = portal
    created = post(client, A, enrollment())
    listed = get(client, A)
    with app.state.session_factory() as session:
        account = session.scalars(
            select(PatientPortalAccount).where(PatientPortalAccount.username == A.username)
        ).one()
        demographic_no = account.demographic_no
    for response in (created, listed):
        text = response.text
        for secret in (
            A.username,
            f"{A.username}@example.test",
            A.recipient_id,
            A.keys.device_key_id,
            "clinic-a",
            "FAKE availability device",
        ):
            assert secret not in text
        # No owner key at all: the record names the device's own subscription only.
        for key in ("account_id", "device_id", "demographic_no", "recipient_id", "username"):
            assert f'"{key}"' not in text
        assert str(demographic_no) not in text
    assert set(created.json()) == RECORD_KEYS
    assert all(set(record) == RECORD_KEYS for record in listed.json()["subscriptions"])
