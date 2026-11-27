# ruff: noqa: F811  (the portal fixture is imported from test_mycarlos_waiting_routes)
"""The waiting-key route's refusals that the route tests do not reach: a key nobody registered,
an assertion that has ended, a body that is not exactly the question, a key giving itself up twice,
and the transaction guards. Every refused ask is the same 404. FAKE keys and devices only.
"""

import json
from datetime import UTC, datetime

import pytest
from sqlalchemy import select

from carlos_patient_portal.models import PatientPortalMyCarlosDevice
from carlos_patient_portal.mycarlos_availability import AvailabilityError, Owner
from carlos_patient_portal.mycarlos_devices import remove_device
from carlos_patient_portal.mycarlos_waiting import (
    WaitingPrincipal,
    WaitingRefusal,
    answer,
    revoke_for_device,
    revoke_self,
)
from carlos_patient_portal.mycarlos_waiting import register as store_register
from tests.test_mycarlos_availability_routes import NOW, signed
from tests.test_mycarlos_waiting_routes import (  # noqa: F401  (portal is a fixture)
    KEYS_PATH,
    WAITING_PATH,
    A,
    B,
    WaitingKey,
    ask,
    device_id,
    keys,
    portal,
    register,
)

NOT_FOUND = {"detail": "not found"}


def test_a_key_nobody_registered_gets_the_same_404_as_any_other_refusal(portal) -> None:
    _, client, _ = portal
    stranger = WaitingKey("never-registered")
    refused = ask(client, stranger)
    assert (refused.status_code, refused.json()) == (404, NOT_FOUND)
    assert refused.headers["cache-control"] == "no-store"


def test_an_assertion_that_has_ended_gets_the_same_404(portal) -> None:
    _, client, _ = portal
    key = WaitingKey("expired")
    register(client, A, key)
    refused = ask(client, key, iat=NOW - 120, exp=NOW - 60)
    assert (refused.status_code, refused.json()) == (404, NOT_FOUND)
    # The key itself is fine: a fresh assertion still gets its answer.
    assert ask(client, key).status_code == 200


@pytest.mark.parametrize(
    "body",
    [
        b"not json at all",
        b"\xff\xfe",
        b"[]",
        b'"a string"',
        b'{"key_id": 7}',
        b'{"key_id": "x", "more": 1}',
        b"{}",
    ],
)
def test_a_body_that_is_not_exactly_the_question_is_the_same_404(portal, body) -> None:
    _, client, _ = portal
    key = WaitingKey("body")
    register(client, A, key)
    refused = ask(client, key, body=body)
    assert (refused.status_code, refused.json()) == (404, NOT_FOUND), body
    # Nothing was answered, so the spacing clock did not start: the next real ask is answered.
    assert ask(client, key).status_code == 200


def test_giving_the_key_up_twice_is_a_404_the_second_time(portal) -> None:
    app, client, _ = portal
    key = WaitingKey("twice")
    register(client, A, key)
    assert ask(client, key, method="DELETE").status_code == 200
    again = ask(client, key, method="DELETE")
    assert (again.status_code, again.json()) == (404, NOT_FOUND)
    assert keys(app, A)[0].revoked_at is not None


def test_a_key_of_a_removed_device_cannot_give_itself_up_or_ask(portal) -> None:
    app, client, _ = portal
    key = WaitingKey("removed-first")
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
            removed_by="staff",
            now=datetime.fromtimestamp(NOW, tz=UTC),
        )
    for method in ("POST", "DELETE"):
        refused = ask(client, key, method=method)
        assert (refused.status_code, refused.json()) == (404, NOT_FOUND), method


@pytest.mark.parametrize(
    "method,path",
    [
        ("DELETE", KEYS_PATH + "/{key_id}"),
        ("DELETE", "/api/mycarlos/availability/subscriptions/{id}"),
    ],
)
def test_a_delete_that_carries_a_body_is_refused_as_too_large(portal, method, path) -> None:
    _, client, _ = portal
    key = WaitingKey("delete-body")
    register(client, A, key)
    path = path.format(key_id=key.key_id, id="00000000-0000-4000-8000-000000000001")
    body = b'{"unexpected": true}'
    refused = client.request(
        method,
        path,
        content=body,
        headers=signed(A, method, path, body) | {"Content-Type": "application/json"},
    )
    # These routes take no body at all, so any byte is "too large", refused before the handler.
    assert (refused.status_code, refused.json()) == (413, {"detail": "request too large"}), path


def test_listing_subscriptions_with_a_body_is_refused_as_too_large(portal) -> None:
    _, client, _ = portal
    path = "/api/mycarlos/availability/subscriptions"
    body = b'{"unexpected": true}'
    refused = client.request(
        "GET",
        path,
        content=body,
        headers=signed(A, "GET", path, body) | {"Content-Type": "application/json"},
    )
    assert (refused.status_code, refused.json()) == (413, {"detail": "request too large"})


def owner_of(app) -> Owner:
    with app.state.session_factory() as session:
        row = session.scalars(
            select(PatientPortalMyCarlosDevice).where(
                PatientPortalMyCarlosDevice.device_key_id == A.keys.device_key_id
            )
        ).one()
        return Owner(row.account_id, row.id)


def test_the_store_calls_refuse_to_run_outside_a_transaction(portal) -> None:
    app, client, _ = portal
    key = WaitingKey("no-transaction")
    register(client, A, key)
    owner = owner_of(app)
    principal = WaitingPrincipal(
        key_row_id=keys(app, A)[0].id,
        device_id=device_id(app, A),
        key_id=key.key_id,
        assertion_id="00000000-0000-4000-8000-000000000001",
        assertion_expires_at=NOW + 60,
    )
    now = datetime.fromtimestamp(NOW, tz=UTC)
    with app.state.session_factory() as session:
        assert not session.in_transaction()
        for call in (
            lambda: store_register(
                session, owner, key_id=key.key_id, public_key=key.public, now=now
            ),
            lambda: revoke_for_device(session, owner, key.key_id, now=now),
            lambda: answer(session, principal, now=now),
            lambda: revoke_self(session, principal, now=now),
        ):
            with pytest.raises(AvailabilityError, match="transaction_required"):
                call()


def test_a_device_that_is_not_active_cannot_register_a_key(portal) -> None:
    app, _client, _ = portal
    owner = owner_of(app)
    stranger = WaitingKey("inactive-device")
    with app.state.session_factory() as session, session.begin():
        row = session.get(PatientPortalMyCarlosDevice, owner.device_id)
        row.status = "removed"
        row.removed_by, row.removed_at = "staff", datetime.fromtimestamp(NOW, tz=UTC)
    with app.state.session_factory() as session, session.begin():
        with pytest.raises(WaitingRefusal) as refused:
            store_register(
                session,
                owner,
                key_id=stranger.key_id,
                public_key=stranger.public,
                now=datetime.fromtimestamp(NOW, tz=UTC),
            )
        assert refused.value.code == "device_inactive"


@pytest.mark.parametrize("names", ["another-device", "nobody"])
def test_a_body_naming_another_key_is_refused_before_anything_is_answered(portal, names) -> None:
    app, client, clock = portal
    key = WaitingKey(f"signer-{names}")
    register(client, A, key)
    if names == "another-device":
        other = WaitingKey("other-device-key")
        register(client, B, other)
    else:
        other = WaitingKey("never-registered-key")
    body = json.dumps({"key_id": other.key_id}).encode()
    refused = ask(client, key, body=body)
    assert (refused.status_code, refused.json()) == (404, NOT_FOUND)
    # The refusal comes before the answer: no answer was recorded, so the spacing clock never began.
    assert keys(app, A)[0].last_answered_at is None
    if names == "another-device":
        assert keys(app, B)[0].last_answered_at is None
    # A normal ask by the same key, right after, is answered and not told to wait.
    assert ask(client, key).status_code == 200
    # And the key it named, if it exists, is untouched by the other's ask.
    if names == "another-device":
        assert ask(client, other).status_code == 200
