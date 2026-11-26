# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The push handle (iPhone push, piece 6): a linked device binds its Apple token to a destination.

Every request is signed by a FAKE linked device, as in the other availability route tests. The
tokens here are FAKE hex strings. What is pinned: the route's contract (201 and 200 with `{}`,
404 for an unknown, other, revoked or other-platform destination, strict fields, the token never
in an answer), the encryption at rest (nothing readable in the table, bound to its destination and
environment, readable across a keyring rotation), and that a token goes with its destination.
"""

import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from alembic import command
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import func, inspect, select
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.models import (
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosPushHandle,
)
from carlos_patient_portal.mycarlos_availability import AvailabilityError, Owner, PushPlatform
from carlos_patient_portal.mycarlos_availability_store import (
    enroll,
    forget_push_handles,
    revoke_for_removed_device,
)
from carlos_patient_portal.mycarlos_push_handles import (
    HandleKeys,
    HandleRequest,
    SqlDestinationHandles,
    _decrypt,
    bind,
    parse_handle,
)
from carlos_patient_portal.notification_transports import ApnsConfig, ApnsTokenTransport
from tests.notification_transports_support import FixedToken, RecordingHttpClient
from tests.support import alembic_config_for_tests
from tests.test_mycarlos_availability_dispatch import (
    Clock,
    db,  # noqa: F401
    enrolled,
    new_copy,
    outbox,
    subscription,
    worker,
)
from tests.test_mycarlos_availability_routes import (
    NOW,
    A,
    B,
    delete,
    enabled_app,
    enrollment,
    post,
    seed,
)
from tests.test_mycarlos_availability_routes import signed as route_signed
from tests.test_mycarlos_availability_store import add_owner, consent, migrated  # noqa: F401

PATH = "/api/mycarlos/availability/handles"
SECRET = "FAKE push handle test secret, not used anywhere else, 40+ chars"
TOKEN_A = "ab" * 32
TOKEN_B = "cd" * 40
KEYS = HandleKeys({"primary": SECRET}, "primary")


def handle_body(destination: str, **changes: object) -> bytes:
    return json.dumps(
        {
            "destination_id": destination,
            "platform": "ios_apns",
            "environment": "sandbox",
            "token": TOKEN_A,
            **changes,
        }
    ).encode()


@pytest.fixture
def portal(monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[object, TestClient]]:
    from carlos_patient_portal.routes import mycarlos_availability

    monkeypatch.setattr(mycarlos_availability, "time", lambda: NOW)
    app = enabled_app(outbox_encryption_secret=SECRET)
    seed(app, A, 8001)
    seed(app, B, 8002)
    with TestClient(app, base_url="https://portal.example.test") as client:
        yield app, client


def post_handle(client: TestClient, device, body: bytes):  # noqa: ANN001, ANN201
    return client.post(
        PATH,
        content=body,
        headers=route_signed(device, "POST", PATH, body) | {"Content-Type": "application/json"},
    )


def enroll_ios(client: TestClient, device) -> str:  # noqa: ANN001
    destination = str(uuid4())
    created = post(client, device, enrollment(platform="ios_apns", destination_id=destination))
    assert created.status_code == 201, created.text
    return destination


def rows(app) -> list[PatientPortalMyCarlosPushHandle]:  # noqa: ANN001
    with app.state.session_factory() as session:
        return list(session.scalars(select(PatientPortalMyCarlosPushHandle)))


# --- the route ---------------------------------------------------------------------------------


def test_the_route_exists_only_with_both_switches_on() -> None:
    from tests.test_internal_api import internal_app

    for switches in (
        {},
        {"mycarlos_delivery_enabled": True},
        {"mycarlos_availability_enabled": True},
    ):
        paths = {getattr(r, "path", "") for r in internal_app(**switches).routes}
        assert PATH not in paths
    assert PATH in {getattr(r, "path", "") for r in enabled_app().routes}


def test_a_token_is_bound_replaced_and_never_returned(portal) -> None:
    app, client = portal
    destination = enroll_ios(client, A)
    created = post_handle(client, A, handle_body(destination))
    assert (created.status_code, created.json()) == (201, {})
    assert created.headers["cache-control"] == "no-store"
    assert TOKEN_A not in created.text
    replaced = post_handle(
        client, A, handle_body(destination, token=TOKEN_B, environment="production")
    )
    assert (replaced.status_code, replaced.json()) == (200, {})
    (row,) = rows(app)
    assert (row.destination_id, row.platform, row.environment) == (
        destination,
        "ios_apns",
        "production",
    )
    handles = SqlDestinationHandles(app.state.session_factory, KEYS)
    assert handles.handle_for(UUID(destination)) == TOKEN_B
    assert handles.environment_for(UUID(destination)) == "production"
    # The same token again changes only the row's ciphertext (a fresh nonce), not the answer.
    again = post_handle(
        client, A, handle_body(destination, token=TOKEN_B, environment="production")
    )
    assert (again.status_code, again.json()) == (200, {})
    assert rows(app)[0].ciphertext != row.ciphertext


def test_a_token_is_lower_cased_and_held_nowhere_in_the_clear(portal) -> None:
    app, client = portal
    destination = enroll_ios(client, A)
    upper = TOKEN_A.upper()
    assert post_handle(client, A, handle_body(destination, token=upper)).status_code == 201
    (row,) = rows(app)
    stored = bytes(row.ciphertext) + bytes(row.nonce)
    for form in (TOKEN_A, upper, bytes.fromhex(TOKEN_A).hex()):
        assert form.encode() not in stored
    assert bytes.fromhex(TOKEN_A) not in stored
    assert (
        SqlDestinationHandles(app.state.session_factory, KEYS).handle_for(UUID(destination))
        == TOKEN_A
    )


@pytest.mark.parametrize("length", [64, 100, 200])
def test_tokens_of_64_to_200_hex_characters_are_accepted(portal, length: int) -> None:
    _app, client = portal
    destination = enroll_ios(client, A)
    token = ("0123456789abcdef" * 13)[:length]
    assert post_handle(client, A, handle_body(destination, token=token)).status_code == 201


@pytest.mark.parametrize(
    ("changes", "status", "code"),
    [
        ({"token": "ab" * 31 + "a"}, 400, "invalid_handle"),  # 63 characters
        ({"token": "a" * 201}, 400, "invalid_handle"),
        ({"token": "g" * 64}, 400, "invalid_handle"),
        ({"token": ""}, 400, "invalid_handle"),
        ({"token": 12345}, 400, "invalid_handle"),
        ({"token": "ab" * 32 + "\n"}, 400, "invalid_handle"),
        ({"environment": "staging"}, 400, "invalid_environment"),
        ({"environment": "Sandbox"}, 400, "invalid_environment"),
        ({"environment": None}, 400, "invalid_handle"),
        ({"platform": "android_fcm"}, 400, "invalid_platform"),
        ({"platform": "macos_apns"}, 400, "invalid_platform"),
        ({"platform": "no_such"}, 400, "invalid_platform"),
        ({"destination_id": "not-a-uuid"}, 400, "invalid_handle"),
        ({"destination_id": str(UUID(int=0))}, 400, "invalid_handle"),
    ],
)
def test_a_malformed_handle_is_refused_without_echoing_the_token(
    portal, changes: dict[str, object], status: int, code: str
) -> None:
    _app, client = portal
    destination = enroll_ios(client, A)
    body = handle_body(changes.pop("destination_id", destination), **changes)  # type: ignore[arg-type]
    answer = post_handle(client, A, body)
    assert (answer.status_code, answer.json()) == (status, {"code": code})
    assert TOKEN_A not in answer.text


def test_the_exact_four_fields_are_required(portal) -> None:
    _app, client = portal
    destination = enroll_ios(client, A)
    good = json.loads(handle_body(destination))
    for body in (
        json.dumps({k: v for k, v in good.items() if k != "token"}).encode(),
        json.dumps({**good, "extra": "x"}).encode(),
        json.dumps([good]).encode(),
        b"not json",
        b"\xff\xfe",
        b"{}",
        b"null",
    ):
        answer = post_handle(client, A, body)
        assert (answer.status_code, answer.json()) == (400, {"code": "invalid_handle"})


def test_a_destination_the_device_does_not_hold_is_not_found_whatever_the_reason(portal) -> None:
    app, client = portal
    mine = enroll_ios(client, A)
    theirs = enroll_ios(client, B)
    android = str(uuid4())
    assert (
        post(client, A, enrollment(platform="android_fcm", destination_id=android)).status_code
        == 201
    )
    revoked = enroll_ios(client, A)
    with app.state.session_factory() as session, session.begin():
        row = session.scalars(
            select(PatientPortalMyCarlosAvailabilitySubscription).where(
                PatientPortalMyCarlosAvailabilitySubscription.destination_id == revoked
            )
        ).one()
        row.revoked_at, row.revoked_by, row.remote_enabled = datetime.now(UTC), "device", False
    for destination in (str(uuid4()), theirs, android, revoked):
        answer = post_handle(client, A, handle_body(destination))
        assert (answer.status_code, answer.json()) == (404, {"detail": "not found"}), destination
    # The device that holds it can bind, and the other cannot take it over afterwards.
    assert post_handle(client, A, handle_body(mine)).status_code == 201
    assert post_handle(client, B, handle_body(mine, token=TOKEN_B)).status_code == 404
    handles = SqlDestinationHandles(app.state.session_factory, KEYS)
    assert handles.handle_for(UUID(mine)) == TOKEN_A


def test_a_destination_that_is_not_opted_in_gets_no_token_stored(portal) -> None:
    app, client = portal
    destination = str(uuid4())
    created = post(
        client,
        A,
        enrollment(platform="ios_apns", destination_id=destination, remote_enabled=False),
    )
    assert created.status_code == 201, created.text
    answer = post_handle(client, A, handle_body(destination))
    assert (answer.status_code, answer.json()) == (404, {"detail": "not found"})
    assert rows(app) == []


def test_the_request_is_signed_bounded_and_has_no_query(portal) -> None:
    _app, client = portal
    destination = enroll_ios(client, A)
    body = handle_body(destination)
    assert client.post(PATH, content=body).status_code == 404  # no assertion
    other = route_signed(A, "POST", PATH, handle_body(destination, token=TOKEN_B))
    assert (
        client.post(PATH, content=body, headers=other).status_code == 404
    )  # signed for another body
    big = handle_body(destination, token="a" * 2000)
    assert post_handle(client, A, big).status_code == 413
    path = PATH + "?x=1"
    answer = client.post(
        path,
        content=body,
        headers=route_signed(A, "POST", path, body) | {"Content-Type": "application/json"},
    )
    assert answer.status_code == 404
    assert client.get(PATH).status_code == 405


def test_without_an_encryption_keyring_the_route_says_so_and_stores_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from carlos_patient_portal.routes import mycarlos_availability

    monkeypatch.setattr(mycarlos_availability, "time", lambda: NOW)
    app = enabled_app()
    seed(app, A, 8003)
    with TestClient(app, base_url="https://portal.example.test") as client:
        destination = enroll_ios(client, A)
        answer = post_handle(client, A, handle_body(destination))
        assert (answer.status_code, answer.json()) == (503, {"code": "handles_unavailable"})
        assert rows(app) == []


# --- encryption at rest ------------------------------------------------------------------------


def test_a_token_is_bound_to_its_destination_platform_and_environment(portal) -> None:
    app, client = portal
    first = enroll_ios(client, A)
    second = enroll_ios(client, A)
    assert post_handle(client, A, handle_body(first)).status_code == 201
    (row,) = rows(app)
    assert _decrypt(KEYS, row) == TOKEN_A
    # A row copied under another destination, or with another environment or platform, is not
    # readable: the lookup answers None, which the transport turns into "gone".
    for change in (
        {"destination_id": second},
        {"environment": "production"},
        {"platform": "macos_apns"},
    ):
        clone = PatientPortalMyCarlosPushHandle(
            **{
                "destination_id": row.destination_id,
                "account_id": row.account_id,
                "device_id": row.device_id,
                "platform": row.platform,
                "environment": row.environment,
                "key_id": row.key_id,
                "nonce": row.nonce,
                "ciphertext": row.ciphertext,
                "created_at": row.created_at,
                "updated_at": row.updated_at,
                **change,
            }
        )
        assert _decrypt(KEYS, clone) is None, change
    flipped = bytearray(row.ciphertext)
    flipped[0] ^= 1
    row.ciphertext = bytes(flipped)
    assert _decrypt(KEYS, row) is None


def test_a_rotated_keyring_still_reads_old_tokens_and_a_missing_key_reads_none(portal) -> None:
    app, client = portal
    destination = enroll_ios(client, A)
    assert post_handle(client, A, handle_body(destination)).status_code == 201
    (row,) = rows(app)
    assert row.key_id == "primary"
    rotated = HandleKeys(
        {"primary": SECRET, "next": "FAKE a second secret for rotation, also 40+ chars"}, "next"
    )
    assert _decrypt(rotated, row) == TOKEN_A
    without = HandleKeys({"next": "FAKE a second secret for rotation, also 40+ chars"}, "next")
    assert _decrypt(without, row) is None
    # A new token is written under the active key.
    with app.state.session_factory() as session, session.begin():
        owner = session.scalars(select(PatientPortalMyCarlosPushHandle)).one()
        assert (
            bind(
                session,
                Owner(owner.account_id, owner.device_id),
                HandleRequest(destination, "ios_apns", "sandbox", TOKEN_B),
                rotated,
            )
            is False
        )
    assert rows(app)[0].key_id == "next"


def test_keys_must_name_an_active_entry() -> None:
    for keyring, active in (({}, "primary"), ({"a": "x" * 40}, "b")):
        with pytest.raises(AvailabilityError):
            HandleKeys(keyring, active)
    assert repr(KEYS) == "HandleKeys[REDACTED]"
    assert repr(HandleRequest("d", "p", "e", TOKEN_A)) == "HandleRequest[REDACTED]"


def test_parse_handle_checks_every_field() -> None:
    destination = str(uuid4())
    assert parse_handle(HandleRequest(destination, "ios_apns", "production", TOKEN_A.upper())) == (
        destination,
        "ios_apns",
        "production",
        TOKEN_A,
    )


# --- a token goes with its destination ---------------------------------------------------------


def test_a_device_revocation_deletes_the_token(portal) -> None:
    app, client = portal
    destination = enroll_ios(client, A)
    assert post_handle(client, A, handle_body(destination)).status_code == 201
    assert len(rows(app)) == 1
    with app.state.session_factory() as session:
        sid = session.scalars(
            select(PatientPortalMyCarlosAvailabilitySubscription.subscription_id)
        ).first()
    assert delete(client, A, sid).status_code == 200
    assert rows(app) == []
    # And a revoked destination can no longer be bound.
    assert post_handle(client, A, handle_body(destination)).status_code == 404


def test_the_devices_own_revocation_message_deletes_the_token(portal) -> None:
    app, client = portal
    destination = enroll_ios(client, A)
    assert post_handle(client, A, handle_body(destination)).status_code == 201
    path = "/api/mycarlos/availability/revocations"
    body = json.dumps({"platform": "ios_apns", "destination_id": destination}).encode()
    answer = client.post(
        path,
        content=body,
        headers=route_signed(A, "POST", path, body) | {"Content-Type": "application/json"},
    )
    assert answer.status_code == 200
    assert rows(app) == []


def test_removing_a_device_deletes_its_tokens_and_only_its_own(db) -> None:  # noqa: F811
    first, _sid, one = enrolled(db, "handle-one", platform="ios_apns")
    second, _sid2, two = enrolled(db, "handle-two", platform="ios_apns")
    with db() as session, session.begin():
        bind(session, first, HandleRequest(str(one), "ios_apns", "sandbox", TOKEN_A), KEYS)
        bind(session, second, HandleRequest(str(two), "ios_apns", "production", TOKEN_B), KEYS)
    with db() as session, session.begin():
        assert revoke_for_removed_device(session, first.device_id, by="device_removed") == 1
    handles = SqlDestinationHandles(db, KEYS)
    assert handles.handle_for(one) is None
    assert handles.handle_for(two) == TOKEN_B


def test_forgetting_nothing_or_an_unknown_destination_is_harmless(db) -> None:  # noqa: F811
    with db() as session, session.begin():
        assert forget_push_handles(session, []) == 0
        assert forget_push_handles(session, [str(uuid4())]) == 0


def test_apns_saying_410_revokes_the_destination_and_deletes_the_token(db) -> None:  # noqa: F811
    owner, sid, destination = enrolled(db, "apns-gone", platform="ios_apns")
    with db() as session, session.begin():
        bind(session, owner, HandleRequest(str(destination), "ios_apns", "sandbox", TOKEN_A), KEYS)
    http = RecordingHttpClient(410)
    transport = ApnsTokenTransport(
        ApnsConfig("FAKETEAM01", "FAKEKEYID1", Path("/nonexistent/fake.p8"), "ca.example.fake"),
        http,
        SqlDestinationHandles(db, KEYS),
        FixedToken(),
        lambda: NOW,
    )
    new_copy(db, owner, 1)
    run = worker(db, Clock(), {PushPlatform.IOS_APNS: transport})
    assert run.process_one() == "invalid_destination"
    assert len(http.requests) == 1
    assert subscription(db, sid).revoked_by == "provider"
    assert SqlDestinationHandles(db, KEYS).handle_for(destination) is None
    with db() as session:
        assert (
            session.scalar(select(func.count()).select_from(PatientPortalMyCarlosPushHandle)) == 0
        )
    assert [r.status for r in outbox(db)] == ["done"]


# --- the migration -----------------------------------------------------------------------------


def test_the_revision_follows_the_signup_claim_and_the_line_has_one_head() -> None:
    script = ScriptDirectory.from_config(alembic_config_for_tests())
    heads = script.get_heads()
    assert len(heads) == 1
    revision = script.get_revision("0026_mycarlos_push_handles")
    assert revision.down_revision == "0025_signup_claim"
    # It is on the line to the head (later revisions build on it).
    assert "0026_mycarlos_push_handles" in {r.revision for r in script.walk_revisions()}
    # alembic_version.version_num is VARCHAR(32) on PostgreSQL.
    assert all(len(r.revision) <= 32 for r in script.walk_revisions())


def test_the_downgrade_is_refused_while_a_token_exists(migrated) -> None:  # noqa: F811
    engine, config = migrated
    session_factory = sessionmaker(engine, expire_on_commit=False)
    with session_factory() as session, session.begin():
        owner = add_owner(session, "push-migration")
        row, _ = enroll(
            session, owner, consent(platform="ios_apns"), now=datetime.fromtimestamp(NOW, tz=UTC)
        )
        bind(
            session, owner, HandleRequest(row.destination_id, "ios_apns", "sandbox", TOKEN_A), KEYS
        )
    assert "patient_portal_mycarlos_push_handles" in set(inspect(engine).get_table_names())
    with pytest.raises(RuntimeError, match="push handles exist"):
        command.downgrade(config, "0025_signup_claim")
    with Session(engine) as session, session.begin():
        session.query(PatientPortalMyCarlosPushHandle).delete()
    command.downgrade(config, "0025_signup_claim")
    assert "patient_portal_mycarlos_push_handles" not in set(inspect(engine).get_table_names())
    command.upgrade(config, "head")
    assert "patient_portal_mycarlos_push_handles" in set(inspect(engine).get_table_names())
