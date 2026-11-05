# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The device's revocation acknowledgement (P4): the portal commits a tombstone, then answers.

myCarlos queues a revocation when the patient opts out, a link or owner goes, or a vault is
reset (`pending_revocations`), and drops it only once the portal has answered this route. Each
request is signed by a FAKE linked device as myCarlos signs it, checked and used once by the
same device-assertion code as the other availability routes. Every id and value is FAKE.
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.models import (
    PatientPortalMyCarlosAvailabilityOutbox,
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosDevice,
)
from carlos_patient_portal.mycarlos_availability import (
    AvailabilityError,
    MailboxReady,
    Owner,
    PushPlatform,
    queue_new_copy,
)
from carlos_patient_portal.mycarlos_availability_store import (
    RevocationRequest,
    SqlAvailabilityTransaction,
    acknowledge_revocation,
)
from carlos_patient_portal.routes import mycarlos_availability
from tests import delivery_contract_reference as ref
from tests.test_internal_api import internal_app
from tests.test_mycarlos_availability_dispatch import (
    Clock,
    db,  # noqa: F401
    enrolled,
    fcm,
    new_copy,
    outbox,
    worker,
)
from tests.test_mycarlos_availability_routes import (
    NOW,
    A,
    B,
    Device,
    enabled_app,
    enrollment,
    get,
    portal,  # noqa: F401
    post,
    seed,
    signed,
)
from tests.test_mycarlos_availability_store import migrated  # noqa: F401

PATH = "/api/mycarlos/availability/revocations"
Subscriptions = PatientPortalMyCarlosAvailabilitySubscription
Outbox = PatientPortalMyCarlosAvailabilityOutbox


def revocation(destination_id: str, platform: str = "android_fcm", **extra: object) -> bytes:
    return json.dumps({"platform": platform, "destination_id": destination_id, **extra}).encode()


def revoke_by_id(client: TestClient, device: Device, body: bytes, path: str = PATH):  # noqa: ANN201
    return client.post(
        path,
        content=body,
        headers=signed(device, "POST", path, body) | {"Content-Type": "application/json"},
    )


def signed_at(device: Device, body: bytes, *, iat: int, exp: int) -> dict[str, str]:
    claims = {
        "aud": ref.DEVICE_AUDIENCE,
        "iss": "mycarlos",
        "kid": device.keys.device_key_id,
        "recipient_id": device.recipient_id,
        "jti": str(uuid4()),
        "iat": iat,
        "exp": exp,
        "request_hash": ref.request_hash("POST", PATH.encode(), b"", body),
    }
    return {
        "X-MyCarlos-Device-Assertion": ref.compact_ed25519(device.keys.ed25519, claims),
        "Content-Type": "application/json",
    }


def rows(app) -> list[Subscriptions]:  # noqa: ANN001
    with app.state.session_factory() as session:
        return list(session.scalars(select(Subscriptions).order_by(Subscriptions.id)))


def owner_of(app, device: Device) -> Owner:  # noqa: ANN001
    with app.state.session_factory() as session:
        row = session.scalars(
            select(PatientPortalMyCarlosDevice).where(
                PatientPortalMyCarlosDevice.device_key_id == device.keys.device_key_id
            )
        ).one()
        return Owner(row.account_id, row.id)


def queue_intent(app, device: Device, sequence: int) -> None:  # noqa: ANN001
    owner = owner_of(app, device)
    with app.state.session_factory() as session, session.begin():
        queue_new_copy(
            SqlAvailabilityTransaction(session, clock=lambda: NOW),
            MailboxReady(owner, sequence, NOW + 3600, True),
            now=NOW,
            server_enabled=True,
        )


def pending(app) -> list[Outbox]:  # noqa: ANN001
    with app.state.session_factory() as session:
        return list(session.scalars(select(Outbox).where(Outbox.status == "pending")))


@pytest.mark.parametrize(
    "switches",
    [{}, {"mycarlos_delivery_enabled": True}, {"mycarlos_availability_enabled": True}],
)
def test_the_route_exists_only_with_both_switches_on(switches: dict[str, object]) -> None:
    assert PATH not in {getattr(route, "path", "") for route in internal_app(**switches).routes}
    assert PATH in {getattr(route, "path", "") for route in enabled_app().routes}


def test_an_enrolled_destination_is_revoked_then_acknowledged(portal) -> None:  # noqa: F811
    app, client = portal
    destination = str(uuid4())
    assert post(client, A, enrollment(destination_id=destination)).status_code == 201
    queue_intent(app, A, 1)
    assert len(pending(app)) == 1

    answer = revoke_by_id(client, A, revocation(destination))
    assert answer.status_code == 200
    assert answer.headers["cache-control"] == "no-store"
    # Only the destination the device sent: no subscription id, epoch or anything else.
    assert answer.json() == {"destination_id": destination, "revoked": True}
    [row] = rows(app)
    assert (row.revoked_by, row.remote_enabled) == ("device", False)
    assert row.revoked_at is not None
    assert pending(app) == []
    # The tombstone is listed, and the destination cannot come back.
    assert get(client, A).json()["subscriptions"][0]["revoked"] is True
    refused = post(client, A, enrollment(destination_id=destination))
    assert (refused.status_code, refused.json()) == (409, {"code": "destination_revoked"})


def test_an_id_the_portal_never_saw_gets_a_tombstone_a_late_enrollment_cannot_pass(
    portal,  # noqa: F811
) -> None:
    app, client = portal
    destination = str(uuid4())
    # The device opted out while its enrollment was still on the way.
    answer = revoke_by_id(client, A, revocation(destination, "windows_wns"))
    assert (answer.status_code, answer.json()) == (
        200,
        {"destination_id": destination, "revoked": True},
    )
    [row] = rows(app)
    owner = owner_of(app, A)
    assert (row.account_id, row.device_id) == (owner.account_id, owner.device_id)
    assert (row.destination_id, row.platform, row.revoked_by) == (
        destination,
        "windows_wns",
        "device",
    )
    # Never enrolled: nothing says it was switched on or permitted.
    assert (row.remote_enabled, row.permission_observed) == (False, False)
    for device in (A, B):
        late = post(client, device, enrollment(destination_id=destination, platform="windows_wns"))
        assert (late.status_code, late.json()) == (409, {"code": "destination_revoked"})
    assert len(rows(app)) == 1


def test_a_repeated_revocation_is_answered_again_and_changes_nothing(portal) -> None:  # noqa: F811
    app, client = portal
    destination = str(uuid4())
    for _ in range(3):
        # A lost answer: the device sends it again, with a fresh assertion each time.
        answer = revoke_by_id(client, A, revocation(destination))
        assert (answer.status_code, answer.json()["revoked"]) == (200, True)
    [row] = rows(app)
    first = row.revoked_at
    assert revoke_by_id(client, A, revocation(destination)).status_code == 200
    assert rows(app)[0].revoked_at == first


def test_a_destination_the_provider_revoked_is_acknowledged_and_keeps_its_cause(
    portal,  # noqa: F811
) -> None:
    app, client = portal
    destination = str(uuid4())
    post(client, A, enrollment(destination_id=destination))
    with app.state.session_factory() as session, session.begin():
        row = session.scalars(select(Subscriptions)).one()
        row.revoked_at = datetime.fromtimestamp(NOW, tz=UTC)
        row.revoked_by = "provider"
        row.remote_enabled = False
    assert revoke_by_id(client, A, revocation(destination)).status_code == 200
    assert rows(app)[0].revoked_by == "provider"


def test_the_platform_is_not_compared_for_the_devices_own_destination(portal) -> None:  # noqa: F811
    app, client = portal
    destination = str(uuid4())
    post(client, A, enrollment(destination_id=destination, platform="ios_apns"))
    assert revoke_by_id(client, A, revocation(destination, "android_fcm")).status_code == 200
    assert (rows(app)[0].platform, rows(app)[0].revoked_by) == ("ios_apns", "device")


def test_another_devices_destination_is_not_revoked(portal) -> None:  # noqa: F811
    app, client = portal
    destination = str(uuid4())
    post(client, A, enrollment(destination_id=destination))
    foreign = revoke_by_id(client, B, revocation(destination))
    # The same answer B's enrollment of it gets.
    assert (foreign.status_code, foreign.json()) == (409, {"code": "destination_taken"})
    assert rows(app)[0].revoked_at is None


def test_a_replayed_revocation_is_not_found(portal) -> None:  # noqa: F811
    app, client = portal
    body = revocation(str(uuid4()))
    headers = signed(A, "POST", PATH, body) | {"Content-Type": "application/json"}
    assert client.post(PATH, content=body, headers=headers).status_code == 200
    # The assertion's nonce is used once.
    replay = client.post(PATH, content=body, headers=headers)
    assert (replay.status_code, replay.json()) == (404, {"detail": "not found"})
    assert len(rows(app)) == 1


@pytest.mark.parametrize(
    ("iat", "exp", "server_now"),
    [
        pytest.param(NOW, NOW + 60, NOW + 60 + 31, id="expired-past-the-skew"),
        pytest.param(NOW + 31, NOW + 90, NOW, id="issued-past-the-skew"),
        pytest.param(NOW, NOW + 121, NOW, id="lifetime-over-120-s"),
    ],
)
def test_an_expired_or_out_of_window_assertion_tombstones_nothing(
    monkeypatch: pytest.MonkeyPatch, iat: int, exp: int, server_now: int
) -> None:
    monkeypatch.setattr(mycarlos_availability, "time", lambda: server_now)
    app = enabled_app()
    seed(app, A, 7101)
    body = revocation(str(uuid4()))
    with TestClient(app, base_url="https://portal.example.test") as client:
        answer = client.post(PATH, content=body, headers=signed_at(A, body, iat=iat, exp=exp))
        assert (answer.status_code, answer.json()) == (404, {"detail": "not found"})
        assert rows(app) == []


def test_a_revocation_signed_for_another_request_is_not_found(portal) -> None:  # noqa: F811
    app, client = portal
    body = revocation(str(uuid4()))
    other = revocation(str(uuid4()))
    unsigned = client.post(PATH, content=body)
    wrong_body = client.post(PATH, content=body, headers=signed(A, "POST", PATH, other))
    wrong_route = client.post(
        PATH, content=body, headers=signed(A, "POST", PATH.replace("revocations", "x"), body)
    )
    query = PATH + "?again=1"
    with_query = client.post(query, content=body, headers=signed(A, "POST", query, body))
    for answer in (unsigned, wrong_body, wrong_route, with_query):
        assert (answer.status_code, answer.json()) == (404, {"detail": "not found"})
    assert rows(app) == []


def test_a_removed_device_is_refused_and_tombstones_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(mycarlos_availability, "time", lambda: NOW)
    app = enabled_app()
    seed(app, A, 7102, status="removed")
    with TestClient(app, base_url="https://portal.example.test") as client:
        answer = revoke_by_id(client, A, revocation(str(uuid4())))
        assert (answer.status_code, answer.json()) == (403, {"code": "device_removed"})
        assert rows(app) == []


@pytest.mark.parametrize(
    ("body", "status", "code"),
    [
        (b"[]", 400, "invalid_enrollment"),
        (b"\xff", 400, "invalid_enrollment"),
        (
            json.dumps({"destination_id": "00000000-0000-4000-8000-000000000001"}).encode(),
            400,
            "invalid_enrollment",
        ),
        (
            revocation("00000000-0000-4000-8000-000000000001", note="FAKE extra"),
            400,
            "invalid_enrollment",
        ),
        (
            json.dumps({"platform": "android_fcm", "destination_id": 7}).encode(),
            400,
            "invalid_enrollment",
        ),
        (revocation("FAKE-not-a-uuid"), 400, "invalid_destination"),
        (revocation("00000000-0000-4000-8000-000000000001", "FAKE_push"), 400, "invalid_platform"),
    ],
)
def test_a_body_that_is_not_the_two_fields_is_refused(
    portal,  # noqa: F811
    body: bytes,
    status: int,
    code: str,
) -> None:
    app, client = portal
    answer = revoke_by_id(client, A, body)
    assert (answer.status_code, answer.json()) == (status, {"code": code})
    assert rows(app) == []


def test_a_body_over_one_kib_is_refused(portal) -> None:  # noqa: F811
    app, client = portal
    assert revoke_by_id(client, A, b" " * 2000).status_code == 413
    assert rows(app) == []


def test_the_store_needs_an_open_transaction(db) -> None:  # noqa: F811
    owner, _sid, dest = enrolled(db, "no-transaction")
    with db() as session, pytest.raises(AvailabilityError, match="transaction_required"):
        acknowledge_revocation(session, owner, RevocationRequest("android_fcm", str(dest)))


def test_a_leased_intent_is_not_recalled_but_its_send_is_suppressed(db) -> None:  # noqa: F811
    owner, _sid, dest = enrolled(db, "leased")
    new_copy(db, owner, 1)
    transport = fcm(dest, 200)
    run = worker(db, Clock(), {PushPlatform.ANDROID_FCM: transport})
    claim = run.claim()
    with db() as session, session.begin():
        acknowledge_revocation(session, owner, RevocationRequest("android_fcm", str(dest)))
    # Already handed to the worker: still there, and the fresh read stops it.
    assert [row.status for row in outbox(db)] == ["leased"]
    assert run.complete(claim) == "suppressed"
    assert transport.requests == []
