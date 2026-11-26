# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The waiting key's own refusals, called directly (coverage round 3).

The route tests (`test_mycarlos_waiting_routes.py`) show every refusal as the same 404 and cannot
tell which check refused. These call `mycarlos_waiting` itself, with FAKE keys derived from labels
and a FAKE linked device, so that each check is pinned by its own code: a body that is not exactly
the agreed JSON, a device that is removed or does not exist, a call outside a transaction, a key
that is the device's own, already used, or revoked, an assertion with each claim wrong, a nonce
used twice or too late, and a key that is gone when the answer is asked.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from carlos_patient_portal.device_identity import (
    DEVICE_CLOCK_SKEW_SECONDS,
    REFUSAL_DEVICE_REMOVED,
    REFUSAL_EXPIRED,
    REFUSAL_INVALID_ASSERTION,
    REFUSAL_UNKNOWN_DEVICE,
    DeviceRefusal,
)
from carlos_patient_portal.mailbox_models import MailboxCopy
from carlos_patient_portal.models import (
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosWaitingKey,
)
from carlos_patient_portal.mycarlos_availability import AvailabilityError, Owner
from carlos_patient_portal.mycarlos_waiting import (
    ANSWER_NOTHING,
    ANSWER_SPACING_SECONDS,
    ANSWER_WAITING,
    MAX_WAITING_ASSERTION_LIFETIME_SECONDS,
    TooSoon,
    WaitingKeyRecord,
    WaitingPrincipal,
    WaitingRefusal,
    answer,
    consume_waiting_assertion,
    find_waiting_key,
    parse_check,
    parse_registration,
    register,
    revoke_for_device,
    revoke_self,
    tombstone_device_keys,
    verify_waiting_assertion,
    waiting_key_id,
)
from tests import delivery_contract_reference as ref
from tests.test_mycarlos_availability_store import NOW, add_owner, migrated  # noqa: F401
from tests.test_mycarlos_waiting_routes import WAITING_PATH, WaitingKey, waiting_claims

MOMENT = datetime.fromtimestamp(NOW, tz=UTC)


@pytest.fixture
def factory(migrated) -> sessionmaker:  # noqa: F811
    engine, _config = migrated
    return sessionmaker(engine, expire_on_commit=False)


def refused(call, code: str = "invalid_waiting_key") -> None:  # noqa: ANN001
    with pytest.raises(WaitingRefusal) as raised:
        call()
    assert str(raised.value) == code


# --- the bodies ---------------------------------------------------------------------------------


def test_a_registration_is_exactly_the_three_fields_and_a_key_that_names_itself() -> None:
    key = WaitingKey("exact")
    assert parse_registration(key.registration()) == (key.key_id, key.public)
    other = WaitingKey("other")
    registration = json.loads(key.registration())
    bad: list[bytes] = [
        b"\xff\xfe",  # not UTF-8
        b"{",
        b"not json",
        b"[]",
        b'"text"',
        b"null",
        b"[" * 100_000,  # deeper than the JSON reader goes
        b"{}",
        json.dumps({k: v for k, v in registration.items() if k != "alg"}).encode(),
        json.dumps(registration | {"extra": 1}).encode(),
        key.registration(key_id=7),
        key.registration(public_key=7),
        key.registration(alg="rsa"),
        key.registration(alg="ED25519"),
        key.registration(public_key="!!not-base64!!"),
        key.registration(public_key=ref.b64url(key.public[:31])),
        key.registration(public_key=ref.b64url(key.public + b"\x00")),
        # The key id is the hash of another key: not this key's name.
        key.registration(key_id=other.key_id),
        key.registration(key_id=key.key_id[:-1] + ("A" if key.key_id[-1] != "A" else "B")),
    ]
    for body in bad:
        refused(lambda body=body: parse_registration(body))


def test_a_check_is_exactly_one_string_key_id() -> None:
    assert parse_check(b'{"key_id":"abc"}') == "abc"
    for body in (
        b"\xff",
        b"{",
        b"[]",
        b"{}",
        b'{"key_id":5}',
        b'{"key_id":null}',
        b'{"key_id":"a","other":1}',
        b'{"other":"a"}',
    ):
        refused(lambda body=body: parse_check(body))


# --- the device ---------------------------------------------------------------------------------


def test_only_an_active_device_that_exists_can_register_or_give_up_a_key(factory) -> None:  # noqa: ANN001
    key = WaitingKey("device")
    with factory() as session, session.begin():
        removed = add_owner(session, "removed", status="removed")
        active = add_owner(session, "active")
        absent = Owner(active.account_id, 987_654)
        other_account = Owner(active.account_id + 1_000, active.device_id)
    for owner in (removed, absent, other_account):
        with factory() as session, session.begin():
            refused(
                lambda owner=owner, session=session: register(
                    session, owner, key.key_id, key.public, now=MOMENT
                ),
                "device_inactive",
            )
        with factory() as session, session.begin():
            refused(
                lambda owner=owner, session=session: revoke_for_device(
                    session, owner, key.key_id, now=MOMENT
                ),
                "device_inactive",
            )
    with factory() as session, session.begin():
        row, created = register(session, active, key.key_id, key.public, now=MOMENT)
    assert created and row.revoked_at is None


def test_a_call_outside_a_transaction_is_refused_before_anything_is_read(factory) -> None:  # noqa: ANN001
    key = WaitingKey("no-transaction")
    with factory() as session, session.begin():
        owner = add_owner(session, "notrans")
    principal = WaitingPrincipal(1, owner.device_id, key.key_id, "assertion", NOW + 60)
    calls = [
        lambda s: register(s, owner, key.key_id, key.public, now=MOMENT),
        lambda s: revoke_for_device(s, owner, key.key_id, now=MOMENT),
        lambda s: answer(s, principal, now=MOMENT),
        lambda s: revoke_self(s, principal, now=MOMENT),
    ]
    for call in calls:
        with factory() as session:
            assert not session.in_transaction()
            with pytest.raises(AvailabilityError) as raised:
                call(session)
            assert str(raised.value) == "transaction_required"
            assert not session.in_transaction()


# --- registering --------------------------------------------------------------------------------


def test_the_devices_own_key_a_used_key_and_a_revoked_key_are_never_a_waiting_key(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        first = add_owner(session, "first")
        second = add_owner(session, "second")
    key, other, third = WaitingKey("a"), WaitingKey("b"), WaitingKey("c")
    # The key the device signs with (the helper makes its device key all zeros).
    own = bytes(32)
    with factory() as session, session.begin():
        refused(lambda: register(session, first, waiting_key_id(own), own, now=MOMENT))
    with factory() as session, session.begin():
        row, created = register(session, first, key.key_id, key.public, now=MOMENT)
        assert created
    # The same live key again is returned unchanged.
    with factory() as session, session.begin():
        again, created = register(session, first, key.key_id, key.public, now=MOMENT)
        assert not created and again.id == row.id
    # Another device cannot take that key id.
    with factory() as session, session.begin():
        refused(
            lambda: register(session, second, key.key_id, key.public, now=MOMENT),
            "waiting_key_taken",
        )
    # A different key replaces the live one, which stays as a tombstone, and its id never returns.
    with factory() as session, session.begin():
        replaced, created = register(session, first, other.key_id, other.public, now=MOMENT)
        assert created
    with factory() as session, session.begin():
        old = session.get(PatientPortalMyCarlosWaitingKey, row.id)
        assert old.revoked_at is not None and old.revoked_by == "device"
        refused(
            lambda: register(session, first, key.key_id, key.public, now=MOMENT),
            "waiting_key_taken",
        )
        assert replaced.revoked_at is None
    # A third key id nobody used is fine.
    with factory() as session, session.begin():
        assert register(session, second, third.key_id, third.public, now=MOMENT)[1]


def test_two_devices_registering_one_key_at_once_lose_to_the_unique_index(  # noqa: ANN001
    factory, monkeypatch: pytest.MonkeyPatch
) -> None:
    with factory() as session, session.begin():
        owner = add_owner(session, "race")
    key = WaitingKey("race")
    with factory() as session, session.begin():
        real_flush = session.flush

        def lost_the_race(*args, **kwargs) -> None:  # noqa: ANN002, ANN003
            # Only the flush that writes the new key loses; the queries' own autoflushes do not.
            if any(isinstance(row, PatientPortalMyCarlosWaitingKey) for row in session.new):
                raise IntegrityError("INSERT", {}, Exception("FAKE unique constraint"))
            return real_flush(*args, **kwargs)

        monkeypatch.setattr(session, "flush", lost_the_race)
        refused(
            lambda: register(session, owner, key.key_id, key.public, now=MOMENT),
            "waiting_key_taken",
        )
    with factory() as session:
        assert session.scalars(select(PatientPortalMyCarlosWaitingKey)).all() == []


# --- giving a key up ------------------------------------------------------------------------------


def test_a_device_gives_up_only_its_own_keys_and_again_is_harmless(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        first = add_owner(session, "giver")
        second = add_owner(session, "keeper")
    mine, theirs = WaitingKey("mine"), WaitingKey("theirs")
    with factory() as session, session.begin():
        register(session, first, mine.key_id, mine.public, now=MOMENT)
        register(session, second, theirs.key_id, theirs.public, now=MOMENT)
    with factory() as session, session.begin():
        refused(
            lambda: revoke_for_device(session, first, "never-registered", now=MOMENT), "not_found"
        )
        # Another device's key is not found for this one, and stays live.
        refused(lambda: revoke_for_device(session, first, theirs.key_id, now=MOMENT), "not_found")
    with factory() as session, session.begin():
        row = revoke_for_device(session, first, mine.key_id, now=MOMENT)
        assert row.revoked_at is not None and row.revoked_by == "device"
        stamped = row.revoked_at
    later = MOMENT + timedelta(hours=1)
    with factory() as session, session.begin():
        again = revoke_for_device(session, first, mine.key_id, now=later)
        assert again.revoked_at.replace(tzinfo=None) == stamped.replace(tzinfo=None)
    with factory() as session:
        live = session.scalars(
            select(PatientPortalMyCarlosWaitingKey).where(
                PatientPortalMyCarlosWaitingKey.key_id == theirs.key_id
            )
        ).one()
        assert live.revoked_at is None


def test_removing_a_device_tombstones_each_live_key_once(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        owner = add_owner(session, "tomb")
    key = WaitingKey("tomb")
    with factory() as session, session.begin():
        register(session, owner, key.key_id, key.public, now=MOMENT)
    with factory() as session, session.begin():
        assert tombstone_device_keys(session, owner.device_id, by="staff", now=MOMENT) == 1
    with factory() as session, session.begin():
        assert tombstone_device_keys(session, owner.device_id, by="staff", now=MOMENT) == 0
        assert tombstone_device_keys(session, 987_654, by="staff", now=MOMENT) == 0
        row = session.scalars(select(PatientPortalMyCarlosWaitingKey)).one()
        assert row.revoked_by == "staff"


# --- finding a key and checking an assertion ----------------------------------------------------


def record(key: WaitingKey, **changes: object) -> WaitingKeyRecord:
    fields: dict[str, object] = {
        "row_id": 1,
        "device_id": 1,
        "public_key": key.public,
        "revoked": False,
        "device_status": "active",
    }
    return WaitingKeyRecord(**{**fields, **changes})  # type: ignore[arg-type]


def test_an_unknown_key_finds_nothing_and_a_known_one_says_what_it_needs(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        owner = add_owner(session, "finder")
    key = WaitingKey("finder")
    with factory() as session, session.begin():
        register(session, owner, key.key_id, key.public, now=MOMENT)
    with factory() as session:
        assert find_waiting_key(session, "no-such-key") is None
        found = find_waiting_key(session, key.key_id)
    assert found.public_key == key.public and found.device_id == owner.device_id
    assert (found.revoked, found.device_status) == (False, "active")
    with factory() as session, session.begin():
        revoke_for_device(session, owner, key.key_id, now=MOMENT)
    with factory() as session:
        assert find_waiting_key(session, key.key_id).revoked is True


BODY = json.dumps({"key_id": "x"}).encode()
REQUEST_HASH = ref.request_hash("POST", WAITING_PATH.encode(), b"", BODY)


def verify(key: WaitingKey, found, *, now: int = NOW, **claims: object):  # noqa: ANN001, ANN201
    assertion = ref.compact_ed25519(key.private, waiting_claims(key, "POST", BODY, **claims))
    return verify_waiting_assertion(
        assertion, find_key=lambda _kid: found, expected_request_hash=REQUEST_HASH, now=now
    )


def code_of(call) -> str:  # noqa: ANN001
    with pytest.raises(DeviceRefusal) as raised:
        call()
    return raised.value.code


def test_each_wrong_claim_or_key_state_of_an_assertion_has_its_own_refusal() -> None:
    key = WaitingKey("verify")
    good = record(key)
    assert verify(key, good).key_id == key.key_id
    # An unknown key, a revoked key and a key whose device is removed.
    assert code_of(lambda: verify(key, None)) == REFUSAL_UNKNOWN_DEVICE
    assert code_of(lambda: verify(key, record(key, revoked=True))) == REFUSAL_DEVICE_REMOVED
    assert (
        code_of(lambda: verify(key, record(key, device_status="removed"))) == REFUSAL_DEVICE_REMOVED
    )
    # Signed by another key than the one on record.
    other = WaitingKey("another")
    assert code_of(lambda: verify(key, record(other))) == REFUSAL_INVALID_ASSERTION
    # The lifetime: one second over the most, none at all, going backwards, issued in the future.
    longest = MAX_WAITING_ASSERTION_LIFETIME_SECONDS
    assert verify(key, good, exp=NOW + longest).key_id == key.key_id
    for claims in (
        {"exp": NOW + longest + 1},
        {"exp": NOW},
        {"exp": NOW - 1},
        {"iat": NOW + DEVICE_CLOCK_SKEW_SECONDS + 1, "exp": NOW + DEVICE_CLOCK_SKEW_SECONDS + 30},
    ):
        assert code_of(lambda claims=claims: verify(key, good, **claims)) == (
            REFUSAL_INVALID_ASSERTION
        ), claims
    # Expired: at exp plus the clock allowance, and not a second before.
    assert verify(key, good, now=NOW + 60 + DEVICE_CLOCK_SKEW_SECONDS - 1).key_id == key.key_id
    assert (
        code_of(lambda: verify(key, good, now=NOW + 60 + DEVICE_CLOCK_SKEW_SECONDS))
        == REFUSAL_EXPIRED
    )
    # A request other than the one the assertion names.
    assert code_of(
        lambda: verify(key, good, request_hash=ref.request_hash("POST", b"/other", b"", BODY))
    ) in {REFUSAL_INVALID_ASSERTION, "request_mismatch"}


def test_a_nonce_is_used_once_and_never_after_it_has_expired(factory) -> None:  # noqa: ANN001
    principal = WaitingPrincipal(1, 1, "kid", str(UUID(int=1)), NOW + 60)
    consume_waiting_assertion(factory, principal, now=NOW)
    assert code_of(lambda: consume_waiting_assertion(factory, principal, now=NOW)) == "replay"
    # An assertion whose time (plus the allowance) has passed cannot be recorded at all.
    old = WaitingPrincipal(1, 1, "kid", str(UUID(int=2)), NOW - 3600)
    assert code_of(lambda: consume_waiting_assertion(factory, old, now=NOW)) == REFUSAL_EXPIRED


# --- the answer ---------------------------------------------------------------------------------


def principal_for(factory, owner: Owner, key: WaitingKey) -> WaitingPrincipal:  # noqa: ANN001
    with factory() as session:
        row = session.scalars(
            select(PatientPortalMyCarlosWaitingKey).where(
                PatientPortalMyCarlosWaitingKey.key_id == key.key_id
            )
        ).one()
        return WaitingPrincipal(row.id, owner.device_id, key.key_id, "FAKE-assertion", NOW + 60)


def test_a_key_that_is_gone_unknown_or_revoked_gets_no_answer_and_cannot_revoke(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        owner = add_owner(session, "answerer")
        other = add_owner(session, "stranger")
    key = WaitingKey("answerer")
    with factory() as session, session.begin():
        register(session, owner, key.key_id, key.public, now=MOMENT)
    principal = principal_for(factory, owner, key)
    # The principal's row does not exist, belongs to another device, names another key id.
    for bad in (
        WaitingPrincipal(987_654, owner.device_id, key.key_id, "a", NOW + 60),
        WaitingPrincipal(principal.key_row_id, other.device_id, key.key_id, "a", NOW + 60),
        WaitingPrincipal(principal.key_row_id, owner.device_id, "another-key-id", "a", NOW + 60),
    ):
        with factory() as session, session.begin():
            refused(lambda bad=bad, session=session: answer(session, bad, now=MOMENT), "not_found")
        with factory() as session, session.begin():
            refused(
                lambda bad=bad, session=session: revoke_self(session, bad, now=MOMENT), "not_found"
            )
    # The first answer is "nothing", a second within the spacing is too soon with the wait left,
    # and one after the spacing is answered again.
    with factory() as session, session.begin():
        assert answer(session, principal, now=MOMENT) == ANSWER_NOTHING
    soon = MOMENT + timedelta(seconds=ANSWER_SPACING_SECONDS - 30)
    with factory() as session, session.begin():
        with pytest.raises(TooSoon) as raised:
            answer(session, principal, now=soon)
        assert raised.value.retry_after == 30
    with factory() as session, session.begin():
        assert answer(
            session, principal, now=MOMENT + timedelta(seconds=ANSWER_SPACING_SECONDS)
        ) == (ANSWER_NOTHING)
    # The key gives itself up; after that it is not found, for the answer or for giving up again.
    with factory() as session, session.begin():
        revoke_self(session, principal, now=MOMENT)
    with factory() as session, session.begin():
        row = session.get(PatientPortalMyCarlosWaitingKey, principal.key_row_id)
        assert row.revoked_by == "waiting_key"
        refused(lambda: answer(session, principal, now=MOMENT), "not_found")
        refused(lambda: revoke_self(session, principal, now=MOMENT), "not_found")


def test_a_key_of_a_removed_device_gets_no_answer(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        owner = add_owner(session, "leaver")
    key = WaitingKey("leaver")
    with factory() as session, session.begin():
        register(session, owner, key.key_id, key.public, now=MOMENT)
    principal = principal_for(factory, owner, key)
    from carlos_patient_portal.models import PatientPortalMyCarlosDevice

    with factory() as session, session.begin():
        device = session.get(PatientPortalMyCarlosDevice, owner.device_id)
        device.status = "removed"
        device.removed_at = MOMENT
        device.removed_by = "patient"
    with factory() as session, session.begin():
        refused(lambda: answer(session, principal, now=MOMENT), "device_inactive")


def test_a_nonce_stays_recorded_through_the_whole_grace_after_exp(factory) -> None:  # noqa: ANN001
    # An assertion still verifies from exp until exp + the allowance, so that is exactly the time a
    # forgotten nonce would let it be replayed: it must be remembered through all of it.
    exp = NOW + 60
    principal = WaitingPrincipal(1, 1, "kid", str(UUID(int=7)), exp)
    consume_waiting_assertion(factory, principal, now=exp - 10)
    for later in (exp - 1, exp, exp + 1, exp + DEVICE_CLOCK_SKEW_SECONDS - 1):

        def again(later: int = later) -> None:
            consume_waiting_assertion(factory, principal, now=later)

        assert code_of(again) == "replay", later
    # At the end of the allowance the assertion itself no longer verifies: expired, not replay.
    end = exp + DEVICE_CLOCK_SKEW_SECONDS
    assert (
        code_of(lambda: consume_waiting_assertion(factory, principal, now=end)) == REFUSAL_EXPIRED
    )


def add_waiting_copy(session, owner: Owner, *, expires_at: int, status: str = "waiting") -> None:  # noqa: ANN001
    sequence = 1 + len(list(session.scalars(select(MailboxCopy.id))))
    recipient = session.scalars(
        select(PatientPortalMyCarlosDevice).where(PatientPortalMyCarlosDevice.id == owner.device_id)
    ).one()
    session.add(
        MailboxCopy(
            account_id=owner.account_id,
            device_id=owner.device_id,
            clinic_id="clinic-a",
            recipient_id=f"FAKE-{sequence}",
            device_key_id=recipient.device_key_id,
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


def test_only_a_waiting_copy_that_has_not_expired_makes_the_answer_waiting(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        owner = add_owner(session, "mailbox")
    key = WaitingKey("mailbox")
    with factory() as session, session.begin():
        register(session, owner, key.key_id, key.public, now=MOMENT)
    principal = principal_for(factory, owner, key)
    step = timedelta(seconds=ANSWER_SPACING_SECONDS)
    moment = MOMENT
    now_epoch = int(moment.timestamp())

    def answered(at: datetime) -> bytes:
        with factory() as session, session.begin():
            return answer(session, principal, now=at)

    # A waiting copy whose time has passed does not count; a copy that is not waiting never does.
    with factory() as session, session.begin():
        add_waiting_copy(session, owner, expires_at=now_epoch - 1)
        add_waiting_copy(session, owner, expires_at=now_epoch + 3600, status="picked_up")
    assert answered(moment) == ANSWER_NOTHING
    # One that expires exactly now has expired (the copy lives until, not through, its time).
    with factory() as session, session.begin():
        add_waiting_copy(session, owner, expires_at=int((moment + step).timestamp()))
    assert answered(moment + step) == ANSWER_NOTHING
    # One second more life and it still waits.
    with factory() as session, session.begin():
        add_waiting_copy(session, owner, expires_at=int((moment + 2 * step).timestamp()) + 1)
    assert answered(moment + 2 * step) == ANSWER_WAITING
