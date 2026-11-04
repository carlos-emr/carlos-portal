# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The availability switch is a settings key that defaults off; unset, nothing queues or sends."""

from uuid import UUID

import pytest

from carlos_patient_portal.config import Settings
from carlos_patient_portal.mycarlos_availability import (
    CurrentAvailability,
    DispatchLease,
    MailboxReady,
    OutboxIntent,
    Owner,
    ProviderResult,
    PushPlatform,
    ReadyHint,
    Subscription,
    dispatch,
    queue_new_copy,
)

NOW = 1_800_000_000
OWNER = Owner(7, 11)
SUBSCRIPTION = Subscription(
    OWNER, UUID(int=1), UUID(int=2), UUID(int=3), PushPlatform.ANDROID_FCM,
    remote_enabled=True, remote_consent_version=1, permission_observed_for_enrollment=True,
)


class _Transaction:
    def __init__(self) -> None:
        self.reads = 0
        self.puts = 0

    def in_transaction(self) -> bool:
        return True

    def subscriptions(self, owner: Owner) -> tuple[Subscription, ...]:
        self.reads += 1
        return (SUBSCRIPTION,)

    def put(self, intent: OutboxIntent) -> bool:
        self.puts += 1
        return True


class _Transport:
    def __init__(self) -> None:
        self.calls = 0

    def send(self, **kwargs: object) -> ProviderResult:
        self.calls += 1
        return ProviderResult.ACCEPTED


def _settings(monkeypatch: pytest.MonkeyPatch) -> Settings:
    monkeypatch.delenv("PATIENT_PORTAL_MYCARLOS_AVAILABILITY_ENABLED", raising=False)
    return Settings(
        _env_file=None,
        environment="development",
        clinic_id="clinic-a",
        clinic_name="Clinic A",
    )


def test_the_availability_switch_defaults_off(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = _settings(monkeypatch)

    assert settings.mycarlos_availability_enabled is False
    assert Settings.model_fields["mycarlos_availability_enabled"].default is False


def test_an_unset_switch_queues_nothing_and_sends_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(monkeypatch)
    transaction = _Transaction()
    event = MailboxReady(OWNER, 17, NOW + 3600, inserted=True)

    assert queue_new_copy(
        transaction, event, now=NOW, server_enabled=settings.mycarlos_availability_enabled
    ) == 0
    assert (transaction.reads, transaction.puts) == (0, 0)

    intent = OutboxIntent(
        OWNER, SUBSCRIPTION.destination_id, SUBSCRIPTION.platform,
        ReadyHint(SUBSCRIPTION.subscription_id, SUBSCRIPTION.epoch, 17), NOW + 900,
    )
    lease = DispatchLease(intent, UUID(int=99), NOW + 120, 1)
    current = CurrentAvailability(SUBSCRIPTION, True, True, 17)
    transport = _Transport()

    decision = dispatch(
        lease, current, transport, now=NOW, server_enabled=settings.mycarlos_availability_enabled
    )

    assert decision.status == "suppressed"
    assert transport.calls == 0
