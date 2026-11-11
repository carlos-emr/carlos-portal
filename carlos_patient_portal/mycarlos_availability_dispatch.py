# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Queueing hook and outbox worker for myCarlos "documents ready" notices (P2).

`queue_documents_ready` runs inside the transaction that inserts a new mailbox copy, so a
rollback drops the copy and its intents together. `AvailabilityDispatcher` drains the outbox:
it claims one row with a lease and a fresh fencing token, commits the claim, reads the owner's
current state, calls the policy core's `dispatch()` outside any transaction, and writes the
decision back only while its token still holds the lease.

Off unless PATIENT_PORTAL_MYCARLOS_DELIVERY_ENABLED, _MAILBOX_ENABLED and _AVAILABILITY_ENABLED
are all on AND the runtime carries an `AvailabilityDispatch` (transports with credentials plus
notice keys). Nothing builds one from settings yet, so nothing sends. No audit events, no log
line with an id, token, handle or provider text; a fault is reported by exception class only.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from time import time
from typing import TYPE_CHECKING
from uuid import UUID, uuid4

import anyio
from sqlalchemy import delete, func, or_, select
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.mailbox_models import MailboxCopy
from carlos_patient_portal.models import (
    ACCOUNT_STATUS_ACTIVE,
    MYCARLOS_DEVICE_STATUS_ACTIVE,
    PatientPortalAccount,
    PatientPortalMyCarlosAvailabilityOutbox,
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosDevice,
)
from carlos_patient_portal.mycarlos_availability import (
    MAX_LEASE_SECONDS,
    AvailabilityError,
    AvailabilityTransport,
    CurrentAvailability,
    DispatchDecision,
    DispatchLease,
    GenericNotice,
    MailboxReady,
    NoticeKeys,
    OutboxIntent,
    Owner,
    ProviderResult,
    PushPlatform,
    ReadyHint,
    dispatch,
    queue_new_copy,
)
from carlos_patient_portal.mycarlos_availability_store import (
    STATUS_LEASED,
    STATUS_PENDING,
    SqlAvailabilityTransaction,
    as_subscription,
)
from carlos_patient_portal.mycarlos_devices import recipient_id_for_account

if TYPE_CHECKING:
    from carlos_patient_portal.runtime import PortalRuntime

logger = logging.getLogger(__name__)

STATUS_DONE = "done"
DECISION_RETRY = "retry"
DECISION_LEASE_LOST = "lease_lost"
# A retry that found a newer pending intent for the same subscription and epoch hands it its
# attempts and backoff, then closes: the newer one carries the newest sequence.
DECISION_RETRY_SUPERSEDED = "retry_superseded"
DECISION_SUPPRESSED = "suppressed"
# A row the worker cannot turn into an intent is closed rather than left to block the queue.
DECISION_INVALID_ROW = "invalid_row"
DEFAULT_LEASE_SECONDS = 60
# Closed rows stay this long after their notice would have expired, then go.
DONE_RETENTION_SECONDS = 24 * 60 * 60
PRUNE_BATCH = 100
DRAIN_BATCH = 20
IDLE_SECONDS = 5.0


def queue_documents_ready(
    session: Session, copy: MailboxCopy, *, now: int, server_enabled: bool = False
) -> int:
    """Queues one intent per permitted subscription of the copy's device; the number queued.

    Call it in the transaction that inserted `copy`, after the mailbox and device rows are
    locked (as `mailbox_lock` does), so enrollment and revocation cannot interleave. Off, or
    for an already-expired copy, it reads and writes nothing.
    """
    if server_enabled is not True:
        return 0
    return queue_new_copy(
        SqlAvailabilityTransaction(session, clock=lambda: now),
        MailboxReady(Owner(copy.account_id, copy.device_id), copy.sequence, copy.expires_at, True),
        now=now,
        server_enabled=server_enabled,
    )


class PlatformNotConfigured(Exception):  # noqa: N818 - its class name is the stored decision
    """No transport holds credentials for this platform. Not retried: a fault, not an outage."""


class PlatformTransports:
    """One `AvailabilityTransport` that sends through the transport configured per platform."""

    def __init__(self, transports: Mapping[PushPlatform, AvailabilityTransport]) -> None:
        if not transports or not all(isinstance(p, PushPlatform) for p in transports):
            raise AvailabilityError("invalid_transports")
        self._transports = dict(transports)

    def send(
        self,
        *,
        destination_id: UUID,
        platform: PushPlatform,
        notice: GenericNotice,
        ttl_seconds: int,
        collapse_key: str,
    ) -> ProviderResult:
        transport = self._transports.get(platform)
        if transport is None:
            raise PlatformNotConfigured
        return transport.send(
            destination_id=destination_id,
            platform=platform,
            notice=notice,
            ttl_seconds=ttl_seconds,
            collapse_key=collapse_key,
        )


@dataclass(frozen=True, repr=False)
class AvailabilityDispatch:
    """What the worker needs that settings do not hold yet: credentialled transports and keys."""

    transports: Mapping[PushPlatform, AvailabilityTransport]
    notice_keys: NoticeKeys
    lease_seconds: int = DEFAULT_LEASE_SECONDS

    def __post_init__(self) -> None:
        if not isinstance(self.notice_keys, NoticeKeys):
            raise AvailabilityError("invalid_notice_key")
        if type(self.lease_seconds) is not int or not 1 <= self.lease_seconds <= MAX_LEASE_SECONDS:
            raise AvailabilityError("invalid_lease")
        PlatformTransports(self.transports)

    def __repr__(self) -> str:
        return "AvailabilityDispatch[REDACTED]"


@dataclass(frozen=True)
class Claim:
    """A committed lease on one outbox row: its id and what the policy core dispatches."""

    row_id: int
    lease: DispatchLease


@dataclass
class AvailabilityDispatcher:
    """Claims, sends and settles outbox rows; one row per `process_one` call."""

    session_factory: sessionmaker[Session]
    config: AvailabilityDispatch
    server_enabled: bool = False
    clock: Callable[[], int] = field(default=lambda: int(time()))

    def __post_init__(self) -> None:
        self._transport = PlatformTransports(self.config.transports)

    def process_one(self) -> str | None:
        """Handles the next due row; its decision, or None when nothing is due."""
        claim = self.claim()
        if claim is None or isinstance(claim, str):
            return claim
        return self.complete(claim)

    def complete(self, claim: Claim) -> str:
        """Sends a claimed row after a fresh read and settles it; the decision written."""
        intent = claim.lease.intent
        with self.session_factory() as session, session.begin():
            try:
                current = current_availability(session, intent, now=self.clock())
            except AvailabilityError:
                # A stored subscription the policy core refuses permits nothing.
                current = CurrentAvailability(None, False, False, 0)
        decision = dispatch(
            claim.lease,
            current,
            self._transport,
            now=self.clock(),
            server_enabled=self.server_enabled,
            notice_keys=self.config.notice_keys,
        )
        if decision.status == DECISION_LEASE_LOST:
            # The lease ran out before the send; the row is reclaimed with a fresh token.
            return decision.status
        with self.session_factory() as session, session.begin():
            return settle(session, claim.row_id, claim.lease, decision, now=self.clock())

    def prune(self) -> int:
        """Deletes up to PRUNE_BATCH closed rows past their retention; how many went."""
        cutoff = self.clock() - DONE_RETENTION_SECONDS
        with self.session_factory() as session, session.begin():
            ids = list(
                session.scalars(
                    select(PatientPortalMyCarlosAvailabilityOutbox.id)
                    .where(
                        PatientPortalMyCarlosAvailabilityOutbox.status == STATUS_DONE,
                        PatientPortalMyCarlosAvailabilityOutbox.expires_at <= cutoff,
                    )
                    .order_by(PatientPortalMyCarlosAvailabilityOutbox.id)
                    .limit(PRUNE_BATCH)
                )
            )
            if ids:
                session.execute(
                    delete(PatientPortalMyCarlosAvailabilityOutbox).where(
                        PatientPortalMyCarlosAvailabilityOutbox.id.in_(ids)
                    )
                )
        return len(ids)

    def claim(self) -> Claim | str | None:
        """Leases the next due row with a fresh token and commits; None when nothing is due.

        Due: pending and past its backoff, or leased with an expired lease (a worker that
        stopped mid-send). Each claim counts an attempt. A row that cannot form an intent is
        closed and its decision returned instead.
        """
        now = self.clock()
        outbox = PatientPortalMyCarlosAvailabilityOutbox
        with self.session_factory() as session, session.begin():
            row = session.scalars(
                select(outbox)
                .where(
                    or_(
                        (outbox.status == STATUS_PENDING)
                        & (outbox.next_attempt_at.is_(None) | (outbox.next_attempt_at <= now)),
                        (outbox.status == STATUS_LEASED) & (outbox.lease_until <= now),
                    )
                )
                .order_by(outbox.id)
                .limit(1)
                .with_for_update(skip_locked=True)
            ).first()
            if row is None:
                return None
            subscription = session.scalars(
                select(PatientPortalMyCarlosAvailabilitySubscription).where(
                    PatientPortalMyCarlosAvailabilitySubscription.subscription_id
                    == row.subscription_id
                )
            ).first()
            try:
                if subscription is None:
                    raise AvailabilityError("invalid_subscription")
                intent = OutboxIntent(
                    Owner(subscription.account_id, subscription.device_id),
                    UUID(subscription.destination_id),
                    PushPlatform(subscription.platform),
                    ReadyHint(UUID(row.subscription_id), UUID(row.epoch), row.sequence),
                    row.expires_at,
                )
            except ValueError:
                # AvailabilityError is a ValueError, as are a malformed UUID and platform.
                return _release(row, STATUS_DONE, DECISION_INVALID_ROW)
            token = uuid4()
            row.status = STATUS_LEASED
            row.lease_token = str(token)
            row.lease_until = now + self.config.lease_seconds
            row.attempts += 1
            return Claim(row.id, DispatchLease(intent, token, row.lease_until, row.attempts))


def current_availability(
    session: Session, intent: OutboxIntent, *, now: int
) -> CurrentAvailability:
    """The dispatch-time read: subscription, account and device state, newest waiting copy."""
    owner = intent.owner
    row = session.scalars(
        select(PatientPortalMyCarlosAvailabilitySubscription).where(
            PatientPortalMyCarlosAvailabilitySubscription.subscription_id
            == str(intent.hint.subscription_id)
        )
    ).first()
    account_status = session.scalar(
        select(PatientPortalAccount.status).where(PatientPortalAccount.id == owner.account_id)
    )
    device_status = session.scalar(
        select(PatientPortalMyCarlosDevice.status).where(
            PatientPortalMyCarlosDevice.id == owner.device_id,
            PatientPortalMyCarlosDevice.account_id == owner.account_id,
        )
    )
    latest = session.scalar(
        select(func.max(MailboxCopy.sequence)).where(
            MailboxCopy.account_id == owner.account_id,
            MailboxCopy.device_id == owner.device_id,
            MailboxCopy.status == "waiting",
            MailboxCopy.expires_at > now,
        )
    )
    return CurrentAvailability(
        subscription=None if row is None else as_subscription(row),
        account_active=(
            account_status == ACCOUNT_STATUS_ACTIVE
            and recipient_id_for_account(session, owner.account_id) is not None
        ),
        device_active=device_status == MYCARLOS_DEVICE_STATUS_ACTIVE,
        latest_waiting_sequence=latest or 0,
    )


def _release(
    row: PatientPortalMyCarlosAvailabilityOutbox,
    status: str,
    decision: str,
    *,
    next_attempt_at: int | None = None,
) -> str:
    """Ends the lease and sets the outcome in one step. No query may run between these writes:
    autoflush would send a leased row without its token, which the table's checks refuse."""
    row.status = status
    row.lease_token = None
    row.lease_until = None
    row.last_decision = decision
    if next_attempt_at is not None:
        row.next_attempt_at = next_attempt_at
    return decision


def settle(
    session: Session, row_id: int, lease: DispatchLease, decision: DispatchDecision, *, now: int
) -> str:
    """Writes `decision` only while `lease` still holds the row, unexpired; what was written.

    A retry goes back to pending with its backoff (or hands both to a newer pending intent);
    every other decision closes the row. An invalid destination also revokes its subscription,
    but only if the subscription still has the lease's epoch and destination.
    """
    outbox = PatientPortalMyCarlosAvailabilityOutbox
    row = session.scalars(select(outbox).where(outbox.id == row_id).with_for_update()).first()
    if (
        row is None
        or row.status != STATUS_LEASED
        or row.lease_token != str(lease.lease_token)
        or row.lease_until is None
        or row.lease_until <= now
    ):
        return DECISION_LEASE_LOST
    if decision.status == DECISION_RETRY and decision.retry_at is not None:
        # Lock the subscription as queueing does before it looks for the pending slot, so a
        # concurrent new copy and this retry cannot both make a pending row.
        subscription = session.scalars(
            select(PatientPortalMyCarlosAvailabilitySubscription)
            .where(
                PatientPortalMyCarlosAvailabilitySubscription.subscription_id == row.subscription_id
            )
            .with_for_update()
        ).first()
        if subscription is None or subscription.revoked_at is not None:
            # Revocation dropped the pending intents; a retry must not bring one back.
            result = _release(row, STATUS_DONE, DECISION_SUPPRESSED)
        else:
            newer = session.scalars(
                select(outbox)
                .where(
                    outbox.subscription_id == row.subscription_id,
                    outbox.epoch == row.epoch,
                    outbox.status == STATUS_PENDING,
                )
                .with_for_update()
            ).first()
            if newer is None:
                result = _release(
                    row, STATUS_PENDING, decision.status, next_attempt_at=decision.retry_at
                )
            else:
                newer.attempts = max(newer.attempts, row.attempts)
                newer.next_attempt_at = max(newer.next_attempt_at or 0, decision.retry_at)
                result = _release(row, STATUS_DONE, DECISION_RETRY_SUPERSEDED)
        session.flush()
        return result
    result = _release(row, STATUS_DONE, decision.status)
    session.flush()
    if decision.revoke_destination:
        revoke_invalid_destination(session, lease.intent, now=now)
    return result


def revoke_invalid_destination(session: Session, intent: OutboxIntent, *, now: int) -> bool:
    """Revokes the subscription the provider refused, fenced on its epoch and destination.

    Locks the device row first, as enrollment, revocation and queueing do. A subscription that
    was revoked meanwhile, or no longer has this epoch and destination, is left alone.
    """
    session.scalars(
        select(PatientPortalMyCarlosDevice.id)
        .where(PatientPortalMyCarlosDevice.id == intent.owner.device_id)
        .with_for_update()
    ).first()
    row = session.scalars(
        select(PatientPortalMyCarlosAvailabilitySubscription)
        .where(
            PatientPortalMyCarlosAvailabilitySubscription.subscription_id
            == str(intent.hint.subscription_id)
        )
        .with_for_update()
    ).first()
    if (
        row is None
        or row.revoked_at is not None
        or row.epoch != str(intent.hint.epoch)
        or row.destination_id != str(intent.destination_id)
        or (row.account_id, row.device_id) != (intent.owner.account_id, intent.owner.device_id)
    ):
        return False
    row.revoked_at = datetime.fromtimestamp(now, tz=UTC)
    row.revoked_by = "provider"
    row.remote_enabled = False
    session.execute(
        delete(PatientPortalMyCarlosAvailabilityOutbox).where(
            PatientPortalMyCarlosAvailabilityOutbox.subscription_id == row.subscription_id,
            PatientPortalMyCarlosAvailabilityOutbox.status == STATUS_PENDING,
        )
    )
    session.flush()
    return True


def dispatcher_for(runtime: PortalRuntime) -> AvailabilityDispatcher | None:
    """The worker this runtime may run, or None: every switch on and credentials present."""
    settings = runtime.settings
    config = runtime.availability_dispatch
    if not (
        settings.mycarlos_delivery_enabled
        and settings.mycarlos_mailbox_enabled
        and settings.mycarlos_availability_enabled
        and isinstance(config, AvailabilityDispatch)
    ):
        return None
    return AvailabilityDispatcher(runtime.session_factory, config, server_enabled=True)


async def run_dispatch_worker(
    dispatcher: AvailabilityDispatcher, runtime: PortalRuntime | None = None
) -> None:
    """Drains due rows, one thread call per row so cancellation never waits on a whole batch."""
    while True:
        handled = 0
        try:
            await anyio.to_thread.run_sync(dispatcher.prune)
            while handled < DRAIN_BATCH:
                # Default abandon_on_cancel=False: an owned transaction or send finishes before
                # the lifespan disposes the engine.
                if await anyio.to_thread.run_sync(dispatcher.process_one) is None:
                    break
                handled += 1
        except Exception as exc:
            # No SQL, bindings, ids, handles or provider text in application logs.
            logger.error("myCarlos availability dispatch failed (%s)", type(exc).__name__)
            if runtime is not None:
                runtime.operational_metrics.record_failure("mycarlos_availability_dispatch")
        await anyio.sleep(0 if handled >= DRAIN_BATCH else IDLE_SECONDS)
