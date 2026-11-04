# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Opaque availability contract and transactional-outbox policy, with no database/provider IO.

Not registered by a route, lifespan or worker. A durable adapter requires separately reviewed
schema/enrollment changes. Queueing belongs to the NEW mailbox-copy transaction; dispatch belongs
after commit. The adapter must persist revocations, serialize enrollment/removal and fence job
updates with the claim's lease token. An already provider-accepted alert cannot be recalled here.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from hashlib import sha256
from typing import Protocol
from uuid import UUID

MAX_HINT_BYTES = 256
MAX_SEQUENCE = (1 << 63) - 1
MAX_DESTINATIONS = 16
MAX_ATTEMPTS = 5
HINT_TTL_SECONDS = 900
MAX_LEASE_SECONDS = 120
MAX_STATUS_LENGTH = 96
REMOTE_CONSENT_VERSION = 1


class AvailabilityError(ValueError):
    """Fixed, content-free refusal; never include payload, tokens or provider exception text."""


class TransportFailure(Exception):
    """The one exception a transport may raise for a provider-side failure worth retrying.

    Anything else a transport raises is a wiring or programming fault, not a provider outage,
    and dispatch() reports it as a content-free transport_error decision instead of retrying.
    """


def _integer(value: object, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= MAX_SEQUENCE


def _uuid(value: object) -> bool:
    return isinstance(value, UUID) and value.int != 0


@dataclass(frozen=True, repr=False)
class ReadyHint:
    subscription_id: UUID
    epoch: UUID
    sequence: int

    def __post_init__(self) -> None:
        if (
            not _uuid(self.subscription_id) or not _uuid(self.epoch)
            or not _integer(self.sequence, 1)
        ):
            raise AvailabilityError("invalid_hint")

    def encode(self) -> bytes:
        # Same five-field v1 wire contract as native document_notifications::ReadyHint.
        return json.dumps(
            {
                "version": 1,
                "kind": "documents_ready",
                "subscription_id": str(self.subscription_id),
                "epoch": str(self.epoch),
                "sequence": self.sequence,
            },
            separators=(",", ":"),
        ).encode("ascii")

    @classmethod
    def decode(cls, raw: bytes) -> ReadyHint:
        def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in items:
                if key in result:
                    raise AvailabilityError("invalid_hint")
                result[key] = value
            return result

        if type(raw) is not bytes or len(raw) > MAX_HINT_BYTES:
            raise AvailabilityError("invalid_hint")
        try:
            value = json.loads(raw, object_pairs_hook=pairs)
            if not isinstance(value, dict) or set(value) != {
                "version", "kind", "subscription_id", "epoch", "sequence"
            }:
                raise AvailabilityError("invalid_hint")
            if type(value["version"]) is not int or value["version"] != 1:
                raise AvailabilityError("invalid_hint")
            if value["kind"] != "documents_ready":
                raise AvailabilityError("invalid_hint")
            if not all(type(value[key]) is str for key in ("subscription_id", "epoch")):
                raise AvailabilityError("invalid_hint")
            return cls(UUID(value["subscription_id"]), UUID(value["epoch"]), value["sequence"])
        except (ValueError, TypeError, AttributeError, UnicodeError, RecursionError):
            raise AvailabilityError("invalid_hint") from None


class PushPlatform(StrEnum):
    ANDROID_FCM = "android_fcm"
    IOS_APNS = "ios_apns"
    MACOS_APNS = "macos_apns"
    WINDOWS_WNS = "windows_wns"


@dataclass(frozen=True, repr=False)
class Owner:
    """Internal active-account/device binding, never part of the provider payload."""

    account_id: int
    device_id: int

    def __post_init__(self) -> None:
        if not _integer(self.account_id, 1) or not _integer(self.device_id, 1):
            raise AvailabilityError("invalid_owner")


@dataclass(frozen=True, repr=False)
class Subscription:
    """Current durable enrollment snapshot; existing local-notice consent does not populate it.

    The authenticated enrollment adapter must observe OS permission afresh and obtain explicit
    remote-consent v1. Saved local enabled/granted state is insufficient. While the app sleeps,
    the OS enforces its current permission; this snapshot is not a per-alert OS permission probe.
    Provider tokens live in separately scoped destination storage, never in this policy object.
    """

    owner: Owner
    subscription_id: UUID
    epoch: UUID
    destination_id: UUID
    platform: PushPlatform
    remote_enabled: bool = False
    remote_consent_version: int = 0
    permission_observed_for_enrollment: bool = False
    revoked: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.owner, Owner) or not isinstance(self.platform, PushPlatform):
            raise AvailabilityError("invalid_subscription")
        if not all(_uuid(v) for v in (self.subscription_id, self.epoch, self.destination_id)):
            raise AvailabilityError("invalid_subscription")
        if any(type(v) is not bool for v in (
            self.remote_enabled, self.permission_observed_for_enrollment, self.revoked
        )) or not _integer(self.remote_consent_version):
            raise AvailabilityError("invalid_subscription")

    def permits_remote(self) -> bool:
        return (
            self.remote_enabled
            and self.remote_consent_version == REMOTE_CONSENT_VERSION
            and self.permission_observed_for_enrollment
            and not self.revoked
        )


@dataclass(frozen=True, repr=False)
class MailboxReady:
    owner: Owner
    sequence: int
    expires_at: int
    inserted: bool

    def __post_init__(self) -> None:
        if not isinstance(self.owner, Owner) or not _integer(self.sequence, 1):
            raise AvailabilityError("invalid_ready_event")
        if not _integer(self.expires_at) or type(self.inserted) is not bool:
            raise AvailabilityError("invalid_ready_event")


@dataclass(frozen=True, repr=False)
class OutboxIntent:
    owner: Owner
    destination_id: UUID
    platform: PushPlatform
    hint: ReadyHint
    expires_at: int

    def __post_init__(self) -> None:
        if not isinstance(self.owner, Owner) or not _uuid(self.destination_id):
            raise AvailabilityError("invalid_intent")
        if not isinstance(self.platform, PushPlatform) or not isinstance(self.hint, ReadyHint):
            raise AvailabilityError("invalid_intent")
        if not _integer(self.expires_at):
            raise AvailabilityError("invalid_intent")

    @property
    def idempotency_key(self) -> tuple[UUID, UUID, int]:
        return self.hint.subscription_id, self.hint.epoch, self.hint.sequence

    @property
    def collapse_key(self) -> str:
        # Exactly64 ASCII bytes; separate epochs do not share a provider collapse identity.
        return sha256(self.hint.subscription_id.bytes + self.hint.epoch.bytes).hexdigest()


class AvailabilityTransaction(Protocol):
    """Adapter uses the SAME transaction as MailboxCopy/Blob/device-sequence insertion.

    put() must atomically suppress same/older sequence and coalesce an unleased pending slot by
    subscription/epoch using coalesce_pending(). Preserve its existing retry budget; do not edit
    an in-flight lease. Never commit, send or schedule an in-memory after-commit callback here.
    A durable row is required, so rollback discards mailbox AND intent; a worker recovers a crash.
    """

    def in_transaction(self) -> bool: ...
    def subscriptions(self, owner: Owner) -> Sequence[Subscription]: ...
    def put(self, intent: OutboxIntent) -> bool: ...


def coalesce_pending(existing: OutboxIntent, incoming: OutboxIntent, *, now: int) -> OutboxIntent:
    """Merge only an unleased pending slot, without extending its original retry/TTL window.

    Adapter must serialize the slot and retain attempts/next_attempt_at. Different destination,
    owner or epoch needs separate revocation/enrollment, not silent retargeting of old work.
    """
    if not _integer(now):
        raise AvailabilityError("invalid_time")
    if (
        existing.owner != incoming.owner or existing.destination_id != incoming.destination_id
        or existing.platform != incoming.platform
        or existing.hint.subscription_id != incoming.hint.subscription_id
        or existing.hint.epoch != incoming.hint.epoch
    ):
        raise AvailabilityError("coalescing_binding_mismatch")
    if incoming.hint.sequence <= existing.hint.sequence:
        return existing
    if incoming.expires_at <= now:
        # An already-expired newer intent never replaces or shortens a live slot.
        return existing
    if existing.expires_at <= now:
        return incoming
    return replace(incoming, expires_at=min(existing.expires_at, incoming.expires_at))


def queue_new_copy(
    transaction: AvailabilityTransaction,
    event: MailboxReady,
    *,
    now: int,
    server_enabled: bool = False,
) -> int:
    if not _integer(now):
        raise AvailabilityError("invalid_time")
    if server_enabled is not True or not event.inserted or event.expires_at <= now:
        return 0
    if transaction.in_transaction() is not True:
        raise AvailabilityError("transaction_required")
    subscriptions = transaction.subscriptions(event.owner)
    if len(subscriptions) > MAX_DESTINATIONS:
        raise AvailabilityError("destination_capacity")
    queued = 0
    seen: set[UUID] = set()
    for subscription in subscriptions:
        if subscription.owner != event.owner or subscription.subscription_id in seen:
            raise AvailabilityError("invalid_subscription_set")
        seen.add(subscription.subscription_id)
        if not subscription.permits_remote():
            continue
        intent = OutboxIntent(
            event.owner, subscription.destination_id, subscription.platform,
            ReadyHint(subscription.subscription_id, subscription.epoch, event.sequence),
            min(event.expires_at, now + HINT_TTL_SECONDS),
        )
        stored = transaction.put(intent)
        if type(stored) is not bool:
            raise AvailabilityError("invalid_outbox_result")
        if stored:
            queued += 1
    return queued


@dataclass(frozen=True, repr=False)
class DispatchLease:
    intent: OutboxIntent
    lease_token: UUID
    lease_until: int
    attempt: int

    def __post_init__(self) -> None:
        if not isinstance(self.intent, OutboxIntent) or not _uuid(self.lease_token):
            raise AvailabilityError("invalid_lease")
        if not _integer(self.lease_until) or not _integer(self.attempt, 1):
            raise AvailabilityError("invalid_lease")


@dataclass(frozen=True, repr=False)
class CurrentAvailability:
    """Fresh dispatch-time read under existing active account/device/assertion boundaries."""

    subscription: Subscription | None
    account_active: bool
    device_active: bool
    latest_waiting_sequence: int

    def __post_init__(self) -> None:
        if self.subscription is not None and not isinstance(self.subscription, Subscription):
            raise AvailabilityError("invalid_dispatch_snapshot")
        if type(self.account_active) is not bool or type(self.device_active) is not bool:
            raise AvailabilityError("invalid_dispatch_snapshot")
        if not _integer(self.latest_waiting_sequence):
            raise AvailabilityError("invalid_dispatch_snapshot")


class ProviderResult(StrEnum):
    ACCEPTED = "accepted"
    TRANSIENT_FAILURE = "transient_failure"
    INVALID_DESTINATION = "invalid_destination"
    PERMANENT_FAILURE = "permanent_failure"


@dataclass(frozen=True, repr=False)
class GenericNotice:
    hint: ReadyHint

    @property
    def title(self) -> str:
        return "myCarlos"

    @property
    def body(self) -> str:
        return "A new document is available in myCarlos."


class AvailabilityTransport(Protocol):
    """send() reports provider outcomes as ProviderResult and raises TransportFailure for a
    provider-side failure (timeout, connection loss) that dispatch() may retry."""

    def send(
        self, *, destination_id: UUID, platform: PushPlatform, notice: GenericNotice,
        ttl_seconds: int, collapse_key: str,
    ) -> ProviderResult: ...


@dataclass(frozen=True)
class DispatchDecision:
    """Persist only with matching unexpired lease token; never treat ACCEPTED as user-seen.

    Invalid-destination revocation must additionally match the current subscription epoch and
    destination. It must not revoke a concurrently rotated/reinstalled destination.
    """

    status: str
    retry_at: int | None = None
    revoke_destination: bool = False

    def __post_init__(self) -> None:
        if type(self.status) is not str or not 0 < len(self.status) <= MAX_STATUS_LENGTH:
            raise AvailabilityError("invalid_decision")


def dispatch(
    lease: DispatchLease,
    current: CurrentAvailability,
    transport: AvailabilityTransport,
    *,
    now: int,
    server_enabled: bool = False,
) -> DispatchDecision:
    """Called outside the enqueue/claim transaction, after fresh ownership/consent read.

    The persistence adapter owns bounded claim/lease heartbeat/CAS. Sending may race opt-out or
    lease expiry: duplicate provider acceptance is possible; stable collapse identity helps, but
    does not promise exactly-once OS display. No token, owner or document data enters the notice.
    A TransportFailure from the transport is retried; any other exception ends the attempt with
    a "transport_error:<ExceptionClass>" decision for the adapter to persist as a fault.
    """
    if not _integer(now):
        raise AvailabilityError("invalid_time")
    intent = lease.intent
    if lease.lease_until <= now:
        return DispatchDecision("lease_lost")
    if lease.lease_until - now > MAX_LEASE_SECONDS:
        return DispatchDecision("invalid_lease_window")
    if intent.expires_at <= now:
        return DispatchDecision("expired")
    if intent.expires_at - now > HINT_TTL_SECONDS:
        return DispatchDecision("invalid_ttl")
    if lease.attempt > MAX_ATTEMPTS:
        return DispatchDecision("attempts_exhausted")
    subscription = current.subscription
    if (
        server_enabled is not True or subscription is None or not current.account_active
        or not current.device_active or not subscription.permits_remote()
        or subscription.owner != intent.owner
        or subscription.subscription_id != intent.hint.subscription_id
        or subscription.epoch != intent.hint.epoch
        or subscription.destination_id != intent.destination_id
        or subscription.platform != intent.platform
        or current.latest_waiting_sequence < intent.hint.sequence
    ):
        return DispatchDecision("suppressed")
    try:
        result = transport.send(
            destination_id=intent.destination_id, platform=intent.platform,
            notice=GenericNotice(intent.hint), ttl_seconds=intent.expires_at - now,
            collapse_key=intent.collapse_key,
        )
    except TransportFailure:
        # A timeout may follow provider acceptance. Retry same replacement identity, boundedly;
        # neither exception text nor provider response bodies enter a decision/log here.
        result = ProviderResult.TRANSIENT_FAILURE
    except Exception as failure:
        # A mis-wired adapter (TypeError, AttributeError, a provider SDK's own exception) is a
        # fault to fix, not an outage to retry. Only the exception class name is reported, never
        # its text, so the decision stays content-free and an operator can tell bug from outage.
        return DispatchDecision(f"transport_error:{type(failure).__name__[:64]}")
    if result is ProviderResult.ACCEPTED:
        return DispatchDecision("provider_accepted")
    if result is ProviderResult.INVALID_DESTINATION:
        return DispatchDecision("invalid_destination", revoke_destination=True)
    if result is ProviderResult.PERMANENT_FAILURE:
        return DispatchDecision("permanent_failure")
    if result is not ProviderResult.TRANSIENT_FAILURE:
        raise AvailabilityError("invalid_provider_result")
    retry_at = now + min(30 * 2 ** (lease.attempt - 1), 300)
    if lease.attempt == MAX_ATTEMPTS:
        return DispatchDecision("attempts_exhausted")
    if retry_at >= intent.expires_at:
        return DispatchDecision("expired")
    return DispatchDecision("retry", retry_at=retry_at)
