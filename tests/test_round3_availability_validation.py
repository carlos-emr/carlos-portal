# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The policy core refuses a malformed value of every kind it is handed (coverage round 3).

The notice policy takes plain values from the persistence adapter, and each of its types checks
its own fields when it is built, so a corrupt row or a wiring slip stops there with a fixed code
and never reaches a provider. FAKE ids and keys only. What is pinned: a value of the wrong type,
the number one past either end of a range, a nil UUID and a bool where an integer is wanted are
each refused with the type's own code; a time that is not an integer is refused by the three
functions that read it; an adapter that answers a non-bool from `put` is refused; and the
decision's status is a non-empty string of bounded length.
"""

from __future__ import annotations

from uuid import UUID

import pytest

from carlos_patient_portal.mycarlos_availability import (
    MAX_SEQUENCE,
    MAX_STATUS_LENGTH,
    AvailabilityError,
    CurrentAvailability,
    DispatchDecision,
    DispatchLease,
    MailboxReady,
    NoticeKeys,
    OutboxIntent,
    Owner,
    PushPlatform,
    ReadyHint,
    Subscription,
    coalesce_pending,
    dispatch,
    notice_token,
    queue_new_copy,
)

NOW = 1_800_000_000
OWNER = Owner(7, 11)
HINT = ReadyHint(UUID(int=1), UUID(int=2), 5)
INTENT = OutboxIntent(OWNER, UUID(int=3), PushPlatform.IOS_APNS, HINT, NOW + 600)


def refuses(code: str, build, **changes: object) -> None:  # noqa: ANN001
    with pytest.raises(AvailabilityError) as raised:
        build(**changes)
    assert str(raised.value) == code


def subscription(**changes: object) -> Subscription:
    fields: dict[str, object] = {
        "owner": OWNER,
        "subscription_id": UUID(int=1),
        "epoch": UUID(int=2),
        "destination_id": UUID(int=3),
        "platform": PushPlatform.IOS_APNS,
        "remote_enabled": True,
        "remote_consent_version": 1,
        "permission_observed_for_enrollment": True,
    }
    return Subscription(**{**fields, **changes})  # type: ignore[arg-type]


def test_the_builders_accept_the_values_the_refusals_below_change() -> None:
    subscription()
    MailboxReady(OWNER, 1, 0, inserted=True)
    DispatchLease(INTENT, UUID(int=9), NOW + 30, 1)
    CurrentAvailability(subscription(), True, True, 0)
    DispatchDecision("x" * MAX_STATUS_LENGTH)


@pytest.mark.parametrize(
    ("account_id", "device_id"),
    [(0, 1), (1, 0), (-1, 1), (1, -1), ("7", 11), (7, "11"), (True, 1), (1, True), (None, None)],
)
def test_an_owner_is_two_positive_integer_ids(account_id: object, device_id: object) -> None:
    with pytest.raises(AvailabilityError) as raised:
        Owner(account_id, device_id)  # type: ignore[arg-type]
    assert str(raised.value) == "invalid_owner"
    assert Owner(1, 1) == Owner(1, 1)


@pytest.mark.parametrize(
    "changes",
    [
        {"owner": (7, 11)},
        {"platform": "ios_apns"},  # the name, not the enum
        {"subscription_id": UUID(int=0)},
        {"epoch": str(UUID(int=2))},
        {"destination_id": None},
        {"remote_enabled": 1},
        {"permission_observed_for_enrollment": "yes"},
        {"revoked": 0},
        {"remote_consent_version": -1},
        {"remote_consent_version": True},
        {"remote_consent_version": "1"},
        {"remote_consent_version": MAX_SEQUENCE + 1},
    ],
)
def test_a_stored_subscription_with_a_field_of_the_wrong_kind_is_refused(changes: dict) -> None:
    refuses("invalid_subscription", subscription, **changes)


@pytest.mark.parametrize(
    "changes",
    [
        {"owner": None},
        {"sequence": 0},  # sequences start at 1
        {"sequence": True},
        {"sequence": MAX_SEQUENCE + 1},
        {"expires_at": -1},
        {"expires_at": 1.5},
        {"inserted": 1},
        {"inserted": None},
    ],
)
def test_a_new_copy_event_with_a_bad_field_is_refused(changes: dict) -> None:
    fields: dict[str, object] = {"owner": OWNER, "sequence": 1, "expires_at": 1, "inserted": True}
    refuses("invalid_ready_event", MailboxReady, **{**fields, **changes})


@pytest.mark.parametrize(
    "changes",
    [
        {"owner": None},
        {"destination_id": str(UUID(int=3))},
        {"destination_id": UUID(int=0)},
        {"platform": "ios_apns"},
        {"platform": None},
        {"hint": (UUID(int=1), UUID(int=2), 5)},
        {"expires_at": -1},
        {"expires_at": "soon"},
    ],
)
def test_an_outbox_intent_with_a_bad_field_is_refused(changes: dict) -> None:
    fields: dict[str, object] = {
        "owner": OWNER,
        "destination_id": UUID(int=3),
        "platform": PushPlatform.IOS_APNS,
        "hint": HINT,
        "expires_at": NOW,
    }
    refuses("invalid_intent", OutboxIntent, **{**fields, **changes})


@pytest.mark.parametrize(
    "changes",
    [
        {"intent": None},
        {"lease_token": "not-a-uuid"},
        {"lease_token": UUID(int=0)},
        {"lease_until": -1},
        {"lease_until": None},
        {"attempt": 0},  # the first attempt is 1
        {"attempt": False},
    ],
)
def test_a_lease_with_a_bad_field_is_refused(changes: dict) -> None:
    fields: dict[str, object] = {
        "intent": INTENT,
        "lease_token": UUID(int=9),
        "lease_until": NOW + 30,
        "attempt": 1,
    }
    refuses("invalid_lease", DispatchLease, **{**fields, **changes})


@pytest.mark.parametrize(
    "changes",
    [
        {"subscription": "a subscription"},
        {"account_active": 1},
        {"device_active": None},
        {"latest_waiting_sequence": -1},
        {"latest_waiting_sequence": 2.0},
    ],
)
def test_a_dispatch_time_snapshot_with_a_bad_field_is_refused(changes: dict) -> None:
    fields: dict[str, object] = {
        "subscription": None,
        "account_active": True,
        "device_active": True,
        "latest_waiting_sequence": 0,
    }
    refuses("invalid_dispatch_snapshot", CurrentAvailability, **{**fields, **changes})


@pytest.mark.parametrize("status", ["", "x" * (MAX_STATUS_LENGTH + 1), None, b"accepted", 7])
def test_a_decision_needs_a_status_of_bounded_length(status: object) -> None:
    refuses("invalid_decision", DispatchDecision, status=status)


def test_a_notice_token_is_made_only_from_real_keys_and_a_real_hint() -> None:
    keys = NoticeKeys(b"k" * 32)
    assert len(notice_token(keys, HINT)) == 22
    for bad_keys, bad_hint in (
        (b"k" * 32, HINT),
        (keys, (UUID(int=1), UUID(int=2), 5)),
        (None, None),
    ):
        with pytest.raises(AvailabilityError) as raised:
            notice_token(bad_keys, bad_hint)  # type: ignore[arg-type]
        assert str(raised.value) == "invalid_notice"


@pytest.mark.parametrize("now", [None, "1", 1.5, -1, True, MAX_SEQUENCE + 1])
def test_a_time_that_is_not_an_integer_in_range_is_refused_by_every_function_that_reads_it(
    now: object,
) -> None:
    class Never:
        def in_transaction(self) -> bool:
            raise AssertionError("nothing is read before the time is checked")

    event = MailboxReady(OWNER, 1, NOW + 600, inserted=True)
    for call in (
        lambda: coalesce_pending(INTENT, INTENT, now=now),  # type: ignore[arg-type]
        lambda: queue_new_copy(Never(), event, now=now, server_enabled=True),  # type: ignore[arg-type]
        lambda: dispatch(
            DispatchLease(INTENT, UUID(int=9), NOW + 30, 1),
            CurrentAvailability(None, True, True, 0),
            None,  # type: ignore[arg-type]
            now=now,  # type: ignore[arg-type]
            server_enabled=True,
        ),
    ):
        with pytest.raises(AvailabilityError) as raised:
            call()
        assert str(raised.value) == "invalid_time"


def test_an_adapter_that_does_not_answer_true_or_false_from_put_is_refused() -> None:
    class Adapter:
        def __init__(self, answer: object) -> None:
            self.answer = answer

        def in_transaction(self) -> bool:
            return True

        def subscriptions(self, owner: Owner) -> list[Subscription]:
            return [subscription()]

        def put(self, intent: OutboxIntent) -> object:
            return self.answer

    event = MailboxReady(OWNER, 3, NOW + 600, inserted=True)
    assert queue_new_copy(Adapter(True), event, now=NOW, server_enabled=True) == 1  # type: ignore[arg-type]
    assert queue_new_copy(Adapter(False), event, now=NOW, server_enabled=True) == 0  # type: ignore[arg-type]
    for answer in (1, 0, None, "stored"):
        with pytest.raises(AvailabilityError) as raised:
            queue_new_copy(Adapter(answer), event, now=NOW, server_enabled=True)  # type: ignore[arg-type]
        assert str(raised.value) == "invalid_outbox_result"
