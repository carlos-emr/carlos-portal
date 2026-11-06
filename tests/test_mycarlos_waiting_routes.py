"""The waiting key (carlos-portal#87): registered with the device key, then "anything waiting?".

A FAKE linked device registers a second Ed25519 key, then asks with it whether a mailbox copy
waits for the device. The answer is 17 bytes either way, at most once every 120 seconds, and
every refusal is the same 404. No other myCarlos route accepts a waiting assertion.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.mailbox_models import MailboxCopy
from carlos_patient_portal.models import (
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosWaitingKey,
)
from carlos_patient_portal.mycarlos_availability import Owner
from carlos_patient_portal.mycarlos_devices import remove_device
from carlos_patient_portal.mycarlos_waiting import (
    ANSWER_NOTHING,
    ANSWER_WAITING,
    WAITING_AUDIENCE,
    waiting_key_id,
)
from carlos_patient_portal.mycarlos_waiting import register as store_register
from carlos_patient_portal.routes import mycarlos_availability
from tests import delivery_contract_reference as ref
from tests.test_internal_api import internal_app
from tests.test_mycarlos_availability_routes import (
    NOW,
    Device,
    enabled_app,
    seed,
    signed,
)

KEYS_PATH = "/api/mycarlos/availability/waiting-keys"
WAITING_PATH = "/api/mycarlos/availability/waiting"
A = Device("waiting-a")
B = Device("waiting-b")


class WaitingKey:
    """A FAKE waiting key, derived from its label at test time."""

    def __init__(self, label: str) -> None:
        self.private = Ed25519PrivateKey.from_private_bytes(
            ref.DeviceKeys(f"FAKE waiting key {label}").ed25519_seed
        )
        self.public = ref._raw(self.private.public_key())
        self.key_id = waiting_key_id(self.public)

    def registration(self, **changes: object) -> bytes:
        return json.dumps(
            {"key_id": self.key_id, "public_key": ref.b64url(self.public), "alg": "ed25519"}
            | changes
        ).encode()


class Clock:
    def __init__(self) -> None:
        self.now = NOW

    def __call__(self) -> int:
        return self.now


@pytest.fixture
def portal(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[object, TestClient, Clock]]:
    clock = Clock()
    monkeypatch.setattr(mycarlos_availability, "time", clock)
    app = enabled_app()
    seed(app, A, 7101)
    seed(app, B, 7102)
    with TestClient(app, base_url="https://portal.example.test") as client:
        yield app, client, clock


def register(client: TestClient, device: Device, key: WaitingKey, body: bytes | None = None):  # noqa: ANN201
    body = key.registration() if body is None else body
    return client.post(
        KEYS_PATH,
        content=body,
        headers=signed(device, "POST", KEYS_PATH, body) | {"Content-Type": "application/json"},
    )


def waiting_claims(key: WaitingKey, method: str, body: bytes, **changes: object) -> dict:
    return {
        "aud": WAITING_AUDIENCE,
        "iss": "mycarlos",
        "kid": key.key_id,
        "jti": str(uuid4()),
        "iat": NOW,
        "exp": NOW + 60,
        "request_hash": ref.request_hash(method, WAITING_PATH.encode(), b"", body),
    } | changes


def ask(  # noqa: ANN201
    client: TestClient,
    key: WaitingKey,
    *,
    method: str = "POST",
    body: bytes | None = None,
    assertion: str | None = None,
    **claims: object,
):
    body = json.dumps({"key_id": key.key_id}).encode() if body is None else body
    assertion = assertion or ref.compact_ed25519(
        key.private, waiting_claims(key, method, body, **claims)
    )
    return client.request(
        method,
        WAITING_PATH,
        content=body,
        headers={"X-MyCarlos-Waiting-Assertion": assertion, "Content-Type": "application/json"},
    )


def device_id(app, device: Device) -> int:  # noqa: ANN001
    with app.state.session_factory() as session:
        return session.scalar(
            select(PatientPortalMyCarlosDevice.id).where(
                PatientPortalMyCarlosDevice.device_key_id == device.keys.device_key_id
            )
        )


def keys(app, device: Device) -> list[PatientPortalMyCarlosWaitingKey]:  # noqa: ANN001
    with app.state.session_factory() as session:
        return list(
            session.scalars(
                select(PatientPortalMyCarlosWaitingKey)
                .where(PatientPortalMyCarlosWaitingKey.device_id == device_id(app, device))
                .order_by(PatientPortalMyCarlosWaitingKey.id)
            )
        )


def add_copy(app, device: Device, *, expires_at: int, status: str = "waiting") -> None:  # noqa: ANN001
    with app.state.session_factory() as session, session.begin():
        row = session.scalars(
            select(PatientPortalMyCarlosDevice).where(
                PatientPortalMyCarlosDevice.device_key_id == device.keys.device_key_id
            )
        ).one()
        sequence = 1 + len(list(session.scalars(select(MailboxCopy.id))))
        session.add(
            MailboxCopy(
                account_id=row.account_id,
                device_id=row.id,
                clinic_id="clinic-a",
                recipient_id=device.recipient_id,
                device_key_id=row.device_key_id,
                delivery_id=f"00000000-0000-4000-8000-{sequence:012d}",
                sequence=sequence,
                size=49,
                ciphertext_sha256="c" * 64,
                body_sha256="b" * 64,
                created_at=NOW - 60,
                expires_at=expires_at,
                status=status,
                terminal_at=None if status == "waiting" else NOW - 30,
                receipt_sha256="d" * 64 if status == "picked_up" else None,
            )
        )


# --- Registration, with the device key ------------------------------------------------------


def test_a_device_registers_its_key_once_and_again_is_the_same(portal) -> None:
    app, client, _ = portal
    key = WaitingKey("register")
    first = register(client, A, key)
    assert first.status_code == 201
    assert first.json() == {"key_id": key.key_id, "registered": True}
    again = register(client, A, key)
    assert again.status_code == 200
    assert again.json() == first.json()
    (row,) = keys(app, A)
    assert (row.key_id, row.public_key, row.revoked_at) == (key.key_id, key.public, None)


def test_a_new_key_replaces_the_live_one_which_stays_as_a_tombstone(portal) -> None:
    app, client, _ = portal
    old, new = WaitingKey("old"), WaitingKey("new")
    assert register(client, A, old).status_code == 201
    assert register(client, A, new).status_code == 201
    first, second = keys(app, A)
    assert (first.key_id, first.revoked_by) == (old.key_id, "device")
    assert (second.key_id, second.revoked_at) == (new.key_id, None)
    # A revoked key never comes back, on this device or another.
    assert register(client, A, old).json() == {"code": "waiting_key_taken"}
    assert register(client, B, old).status_code == 409


def test_a_key_in_use_by_another_device_is_refused(portal) -> None:
    _, client, _ = portal
    key = WaitingKey("shared")
    assert register(client, A, key).status_code == 201
    taken = register(client, B, key)
    assert (taken.status_code, taken.json()) == (409, {"code": "waiting_key_taken"})


@pytest.mark.parametrize(
    "changes",
    [
        {"alg": "rsa"},
        {"key_id": "A" * 43},
        {"public_key": "not-base64!"},
        {"public_key": ref.b64url(b"\x01" * 31)},
        {"extra": True},
        {"key_id": 7},
    ],
)
def test_a_malformed_registration_is_refused(portal, changes: dict) -> None:
    _, client, _ = portal
    refused = register(
        client, A, WaitingKey("malformed"), WaitingKey("malformed").registration(**changes)
    )
    assert (refused.status_code, refused.json()) == (400, {"code": "invalid_waiting_key"})


def test_the_device_key_itself_cannot_be_the_waiting_key(portal) -> None:
    _, client, _ = portal
    own = A.keys.ed25519_public
    body = json.dumps(
        {"key_id": waiting_key_id(own), "public_key": ref.b64url(own), "alg": "ed25519"}
    ).encode()
    assert register(client, A, WaitingKey("unused"), body).status_code == 400


def test_a_device_gives_its_key_up_and_again_is_harmless(portal) -> None:
    app, client, _ = portal
    key = WaitingKey("give-up")
    register(client, A, key)
    path = f"{KEYS_PATH}/{key.key_id}"
    for _ in range(2):
        response = client.delete(path, headers=signed(A, "DELETE", path))
        assert response.status_code == 200
        assert response.json() == {"key_id": key.key_id, "revoked": True}
    assert keys(app, A)[0].revoked_by == "device"
    # Another device's key is not this device's to give up.
    other = WaitingKey("other")
    register(client, B, other)
    path = f"{KEYS_PATH}/{other.key_id}"
    assert client.delete(path, headers=signed(A, "DELETE", path)).status_code == 404


def test_registration_needs_the_device_assertion(portal) -> None:
    _, client, _ = portal
    key = WaitingKey("unsigned")
    body = key.registration()
    assert client.post(KEYS_PATH, content=body).status_code == 404


# --- The check, with the waiting key ---------------------------------------------------------


def test_the_answer_is_17_bytes_either_way_and_says_only_whether_a_copy_waits(portal) -> None:
    app, client, clock = portal
    key, other = WaitingKey("answer"), WaitingKey("answer-b")
    register(client, A, key)
    # (Device assertions here are signed at NOW: register before the clock moves.)
    register(client, B, other)
    nothing = ask(client, key)
    assert (nothing.status_code, nothing.content) == (200, ANSWER_NOTHING)
    assert nothing.headers["cache-control"] == "no-store"
    # Expired or picked-up copies are not waiting; a not-expired waiting one is.
    add_copy(app, A, expires_at=NOW - 1)
    add_copy(app, A, expires_at=NOW + 3600, status="picked_up")
    clock.now += 120
    assert ask(client, key, iat=clock.now, exp=clock.now + 60).content == ANSWER_NOTHING
    add_copy(app, A, expires_at=clock.now + 3600)
    clock.now += 120
    waiting = ask(client, key, iat=clock.now, exp=clock.now + 60)
    assert (waiting.status_code, waiting.content) == (200, ANSWER_WAITING)
    assert len(ANSWER_WAITING) == len(ANSWER_NOTHING) == 17
    # Another device's copy is not this device's.
    assert ask(client, other, iat=clock.now, exp=clock.now + 60).content == ANSWER_NOTHING


def test_one_answer_per_key_per_120_seconds(portal) -> None:
    _, client, clock = portal
    key = WaitingKey("spacing")
    register(client, A, key)
    assert ask(client, key).status_code == 200
    clock.now += 30
    soon = ask(client, key, iat=clock.now, exp=clock.now + 60)
    assert soon.status_code == 429
    assert soon.headers["retry-after"] == "90"
    assert soon.json() == {"detail": "too soon"}
    clock.now += 90
    assert ask(client, key, iat=clock.now, exp=clock.now + 60).status_code == 200


def test_an_assertion_is_used_once_even_when_it_was_too_soon(portal) -> None:
    _, client, clock = portal
    key = WaitingKey("replay")
    register(client, A, key)
    body = json.dumps({"key_id": key.key_id}).encode()
    assertion = ref.compact_ed25519(key.private, waiting_claims(key, "POST", body))
    assert ask(client, key, body=body, assertion=assertion).status_code == 200
    assert ask(client, key, body=body, assertion=assertion).status_code == 404
    clock.now += 10
    too_soon = ref.compact_ed25519(
        key.private, waiting_claims(key, "POST", body, iat=clock.now, exp=clock.now + 60)
    )
    assert ask(client, key, body=body, assertion=too_soon).status_code == 429
    assert ask(client, key, body=body, assertion=too_soon).status_code == 404


@pytest.mark.parametrize(
    "claims",
    [
        {"exp": NOW + 61},
        {"aud": ref.DEVICE_AUDIENCE},
        {"iss": "someone"},
        {"request_hash": "0" * 64},
        {"recipient_id": "FAKE-recipient-waiting-a"},
        {"iat": NOW - 200, "exp": NOW - 150},
    ],
)
def test_every_refused_assertion_is_the_same_404(portal, claims: dict) -> None:
    _, client, _ = portal
    key = WaitingKey("refused")
    register(client, A, key)
    refused = ask(client, key, **claims)
    assert (refused.status_code, refused.json()) == (404, {"detail": "not found"})


def test_the_body_must_name_the_signing_key(portal) -> None:
    _, client, _ = portal
    key, other = WaitingKey("named"), WaitingKey("other-named")
    register(client, A, key)
    register(client, B, other)
    body = json.dumps({"key_id": other.key_id}).encode()
    assert ask(client, key, body=body).status_code == 404
    assert ask(client, key, body=b'{"key_id": 1}').status_code == 404
    assert ask(client, key, body=b"{}").status_code == 404


def test_a_query_string_or_a_large_body_is_refused(portal) -> None:
    _, client, _ = portal
    key = WaitingKey("shape")
    register(client, A, key)
    assert client.post(WAITING_PATH + "?x=1", content=b"{}").status_code == 404
    assert client.post(WAITING_PATH, content=b"x" * 300).status_code == 413


def test_a_device_assertion_never_passes_the_waiting_check(portal) -> None:
    _, client, _ = portal
    key = WaitingKey("device-signed")
    register(client, A, key)
    body = json.dumps({"key_id": key.key_id}).encode()
    device_assertion = signed(A, "POST", WAITING_PATH, body)["X-MyCarlos-Device-Assertion"]
    for header in ("X-MyCarlos-Waiting-Assertion", "X-MyCarlos-Device-Assertion"):
        response = client.post(WAITING_PATH, content=body, headers={header: device_assertion})
        assert response.status_code == 404


def test_the_key_gives_itself_up_and_then_only_gets_404(portal) -> None:
    app, client, clock = portal
    key = WaitingKey("self")
    register(client, A, key)
    gone = ask(client, key, method="DELETE")
    assert (gone.status_code, gone.json()) == (200, {"revoked": True})
    assert keys(app, A)[0].revoked_by == "waiting_key"
    clock.now += 200
    assert ask(client, key, iat=clock.now, exp=clock.now + 60).status_code == 404
    assert ask(client, key, method="DELETE", iat=clock.now, exp=clock.now + 60).status_code == 404


@pytest.mark.parametrize(
    ("removed_by", "revoked_by"), [("patient", "device_removed"), ("staff", "staff")]
)
def test_removing_the_device_kills_its_keys(portal, removed_by: str, revoked_by: str) -> None:
    app, client, _ = portal
    key = WaitingKey(f"removed-{removed_by}")
    register(client, A, key)
    with app.state.session_factory() as session, session.begin():
        account_id = session.scalar(
            select(PatientPortalMyCarlosDevice.account_id).where(
                PatientPortalMyCarlosDevice.device_key_id == A.keys.device_key_id
            )
        )
        remove_device(
            session,
            account_id=account_id,
            device_key_id=A.keys.device_key_id,
            removed_by=removed_by,
            now=datetime.fromtimestamp(NOW, tz=UTC),
        )
    assert keys(app, A)[0].revoked_by == revoked_by
    assert ask(client, key).status_code == 404


def test_no_waiting_routes_while_availability_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(mycarlos_availability, "time", lambda: NOW)
    app = internal_app(
        mycarlos_delivery_enabled=True,
        mycarlos_availability_enabled=False,
        public_base_url="https://portal.example.test",
    )
    seed(app, A, 7103)
    key = WaitingKey("off")
    with TestClient(app, base_url="https://portal.example.test") as client:
        assert register(client, A, key).status_code == 404
        assert ask(client, key).status_code == 404


# --- No other route takes a waiting assertion ------------------------------------------------


def _mycarlos_routes(app) -> list[tuple[str, str]]:  # noqa: ANN001
    found = []
    for route in app.routes:
        path = getattr(route, "path", "")
        if not path.startswith("/api/mycarlos") or path == WAITING_PATH:
            continue
        for method in sorted(getattr(route, "methods", None) or ()):
            if method in {"HEAD", "OPTIONS"}:
                continue
            found.append((method, path))
    return found


@pytest.fixture
def every_route(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[tuple[object, TestClient, WaitingKey]]:
    monkeypatch.setattr(mycarlos_availability, "time", lambda: NOW)
    app = enabled_app(mycarlos_mailbox_enabled=True, mycarlos_approval_enabled=True)
    seed(app, A, 7104)
    key = WaitingKey("everywhere")
    # Registered through the store before the client starts the app: with the mailbox on, its
    # worker shares the in-memory test database, and this test is about the other routes.
    with app.state.session_factory() as session, session.begin():
        row = session.scalars(
            select(PatientPortalMyCarlosDevice).where(
                PatientPortalMyCarlosDevice.device_key_id == A.keys.device_key_id
            )
        ).one()
        store_register(session, Owner(row.account_id, row.id), key.key_id, key.public)
    with TestClient(app, base_url="https://portal.example.test") as client:
        yield app, client, key


def test_every_other_mycarlos_route_refuses_a_waiting_assertion(every_route) -> None:
    app, client, key = every_route
    routes = _mycarlos_routes(app)
    # The device API: link, clinic keys, mailbox, approvals, availability and the key routes.
    assert len(routes) >= 18, routes
    for method, template in routes:
        path = template
        for name in ("{delivery_id}", "{challenge_id}", "{request_id}", "{subscription_id}"):
            path = path.replace(name, str(uuid4()))
        path = path.replace("{key_id}", key.key_id)
        body = b"" if method in {"GET", "DELETE"} else json.dumps({"key_id": key.key_id}).encode()
        claims = waiting_claims(key, method, body) | {
            "request_hash": ref.request_hash(method, path.encode(), b"", body)
        }
        assertion = ref.compact_ed25519(key.private, claims)
        for header in ("X-MyCarlos-Device-Assertion", "X-MyCarlos-Waiting-Assertion"):
            response = client.request(method, path, content=body, headers={header: assertion})
            assert response.status_code >= 400, (method, path, header, response.status_code)
    (row,) = keys(app, A)
    assert (row.revoked_at, row.last_answered_at) == (None, None)
