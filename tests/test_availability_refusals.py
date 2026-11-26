"""What the availability policy refuses when it is handed something it should never be given.

These are programming-fault guards (a content-free `AvailabilityError` code each), not patient
paths: a bad owner, a malformed enrollment snapshot, a lease with no token, a non-integer clock.
Synthetic values only.
"""

from dataclasses import replace
from uuid import UUID

import pytest

from carlos_patient_portal import mycarlos_availability as av

A, B, C = UUID(int=1), UUID(int=2), UUID(int=3)
OWNER = av.Owner(1, 1)
HINT = av.ReadyHint(A, B, 1)


def intent(**changes):
    values = {
        "owner": OWNER,
        "destination_id": C,
        "platform": av.PushPlatform.ANDROID_FCM,
        "hint": HINT,
        "expires_at": 1_000,
    }
    return av.OutboxIntent(**{**values, **changes})


def code(call, *args, **kwargs):
    with pytest.raises(av.AvailabilityError) as refused:
        call(*args, **kwargs)
    return str(refused.value)


@pytest.mark.parametrize("bad", [0, -1, True, "1", 1.0, None, av.MAX_SEQUENCE + 1])
def test_an_owner_needs_two_positive_integer_ids(bad):
    assert code(av.Owner, bad, 1) == "invalid_owner"
    assert code(av.Owner, 1, bad) == "invalid_owner"


def test_a_subscription_snapshot_refuses_every_malformed_field():
    good = dict(
        owner=OWNER,
        subscription_id=A,
        epoch=B,
        destination_id=C,
        platform=av.PushPlatform.IOS_APNS,
    )
    assert av.Subscription(**good).permits_remote() is False
    for field, bad in (
        ("owner", (1, 1)),
        ("platform", "ios_apns"),
        ("subscription_id", UUID(int=0)),
        ("epoch", "not-a-uuid"),
        ("destination_id", None),
        ("remote_enabled", 1),
        ("permission_observed_for_enrollment", "yes"),
        ("revoked", None),
        ("remote_consent_version", True),
        ("remote_consent_version", -1),
    ):
        assert code(av.Subscription, **{**good, field: bad}) == "invalid_subscription", field


def test_remote_is_permitted_only_with_every_condition_at_once():
    base = av.Subscription(
        OWNER,
        A,
        B,
        C,
        av.PushPlatform.IOS_APNS,
        remote_enabled=True,
        remote_consent_version=av.REMOTE_CONSENT_VERSION,
        permission_observed_for_enrollment=True,
    )
    assert base.permits_remote() is True
    for change in (
        {"remote_enabled": False},
        {"remote_consent_version": av.REMOTE_CONSENT_VERSION + 1},
        {"remote_consent_version": 0},
        {"permission_observed_for_enrollment": False},
        {"revoked": True},
    ):
        assert replace(base, **change).permits_remote() is False, change


def test_a_mailbox_event_and_an_intent_refuse_what_is_not_theirs():
    for bad in (
        dict(owner=(1, 1)),
        dict(sequence=0),
        dict(expires_at=-1),
        dict(inserted=1),
    ):
        good = dict(owner=OWNER, sequence=1, expires_at=5, inserted=True)
        assert code(av.MailboxReady, **{**good, **bad}) == "invalid_ready_event", bad
    for bad in (
        dict(owner="owner"),
        dict(destination_id=UUID(int=0)),
        dict(platform="android_fcm"),
        dict(hint=(A, B, 1)),
        dict(expires_at=1.5),
    ):
        assert code(intent, **bad) == "invalid_intent", bad


def test_a_lease_and_a_dispatch_snapshot_refuse_what_is_malformed():
    good = dict(intent=intent(), lease_token=A, lease_until=10, attempt=1)
    assert av.DispatchLease(**good).attempt == 1
    for bad in (
        dict(intent="intent"),
        dict(lease_token=UUID(int=0)),
        dict(lease_until=-1),
        dict(attempt=0),
        dict(attempt=True),
    ):
        assert code(av.DispatchLease, **{**good, **bad}) == "invalid_lease", bad
    snapshot = dict(
        subscription=None, account_active=True, device_active=True, latest_waiting_sequence=0
    )
    assert av.CurrentAvailability(**snapshot).subscription is None
    for bad in (
        dict(subscription="subscription"),
        dict(account_active=1),
        dict(device_active=None),
        dict(latest_waiting_sequence=-1),
    ):
        assert code(av.CurrentAvailability, **{**snapshot, **bad}) == "invalid_dispatch_snapshot", (
            bad
        )


def test_a_decision_status_is_a_short_string():
    assert av.DispatchDecision("sent").status == "sent"
    for bad in ("", "x" * (av.MAX_STATUS_LENGTH + 1), None, 1):
        assert code(av.DispatchDecision, bad) == "invalid_decision", bad


@pytest.mark.parametrize("now", [True, -1, "1", 1.0, None])
def test_a_clock_that_is_not_a_non_negative_integer_is_refused(now):
    assert code(av.coalesce_pending, intent(), intent(), now=now) == "invalid_time"
    event = av.MailboxReady(OWNER, 1, 10, True)
    assert code(av.queue_new_copy, object(), event, now=now) == "invalid_time"
    lease = av.DispatchLease(intent(), A, 10, 1)
    current = av.CurrentAvailability(None, True, True, 0)
    assert code(av.dispatch, lease, current, object(), now=now) == "invalid_time"


def test_a_notice_token_needs_real_keys_and_a_real_hint():
    keys = av.NoticeKeys(b"k" * 32)
    assert isinstance(av.notice_token(keys, HINT), str)
    assert code(av.notice_token, b"k" * 32, HINT) == "invalid_notice"
    assert code(av.notice_token, keys, (A, B, 1)) == "invalid_notice"


class Stub:
    """A transaction whose outbox answers whatever it is told."""

    def __init__(self, stored, subscriptions):
        self.stored, self._subscriptions = stored, subscriptions

    def in_transaction(self):
        return True

    def subscriptions(self, owner):
        return self._subscriptions

    def put(self, intent):
        return self.stored


def test_an_outbox_that_does_not_say_stored_or_not_is_a_fault():
    subscription = av.Subscription(
        OWNER,
        A,
        B,
        C,
        av.PushPlatform.ANDROID_FCM,
        remote_enabled=True,
        remote_consent_version=av.REMOTE_CONSENT_VERSION,
        permission_observed_for_enrollment=True,
    )
    event = av.MailboxReady(OWNER, 1, 10_000, True)
    for answer in (None, 1, "yes"):
        stub = Stub(answer, [subscription])
        assert (
            code(av.queue_new_copy, stub, event, now=1, server_enabled=True)
            == "invalid_outbox_result"
        ), answer
    assert av.queue_new_copy(Stub(True, [subscription]), event, now=1, server_enabled=True) == 1
    assert av.queue_new_copy(Stub(False, [subscription]), event, now=1, server_enabled=True) == 0
