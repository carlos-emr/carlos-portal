# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Durable storage for myCarlos availability notices: enrollment and the outbox (P1).

`SqlAvailabilityTransaction` is the adapter the policy core's `queue_new_copy` takes: it reads
an owner's live subscriptions and puts intents into the outbox, inside the caller's transaction
(the one that makes the new mailbox copy durable), never committing itself. `enroll`, `revoke`
and `subscriptions_for_owner` serve the device's enrollment routes.

What is stored is ids, the platform, the consent the device reported and counters: no document
id, no text, no provider token (those live in separately scoped storage when P3 adds providers),
and nothing that names the patient. Nothing here sends; no worker reads the outbox yet (P2).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from time import time
from uuid import UUID, uuid4

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.models import (
    MYCARLOS_DEVICE_STATUS_ACTIVE,
    PatientPortalMyCarlosAvailabilityOutbox,
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosDevice,
)
from carlos_patient_portal.mycarlos_availability import (
    MAX_DESTINATIONS,
    REMOTE_CONSENT_VERSION,
    AvailabilityError,
    OutboxIntent,
    Owner,
    PushPlatform,
    ReadyHint,
    Subscription,
    coalesce_pending,
)

STATUS_PENDING = "pending"
STATUS_LEASED = "leased"


class EnrollmentRefusal(AvailabilityError):
    """A content-free reason an enrollment or revocation was refused; `code` is all it says."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def _uuid_text(value: object, code: str) -> str:
    """A canonical, non-nil UUID string, or the refusal `code`."""
    try:
        parsed = value if isinstance(value, UUID) else UUID(str(value))
    except (ValueError, TypeError, AttributeError):
        raise EnrollmentRefusal(code) from None
    if parsed.int == 0 or (isinstance(value, str) and value != str(parsed)):
        raise EnrollmentRefusal(code)
    return str(parsed)


def as_subscription(row: PatientPortalMyCarlosAvailabilitySubscription) -> Subscription:
    """The policy core's snapshot of a stored row."""
    return Subscription(
        owner=Owner(row.account_id, row.device_id),
        subscription_id=UUID(row.subscription_id),
        epoch=UUID(row.epoch),
        destination_id=UUID(row.destination_id),
        platform=PushPlatform(row.platform),
        remote_enabled=bool(row.remote_enabled),
        remote_consent_version=row.remote_consent_version,
        permission_observed_for_enrollment=bool(row.permission_observed),
        revoked=row.revoked_at is not None,
    )


def _lock_active_device(session: Session, owner: Owner) -> None:
    """Serializes enrollment and revocation per device, and refuses a removed device."""
    device = session.scalars(
        select(PatientPortalMyCarlosDevice)
        .where(
            PatientPortalMyCarlosDevice.id == owner.device_id,
            PatientPortalMyCarlosDevice.account_id == owner.account_id,
        )
        .with_for_update()
    ).first()
    if device is None or device.status != MYCARLOS_DEVICE_STATUS_ACTIVE:
        raise EnrollmentRefusal("device_inactive")


def subscriptions_for_owner(
    session: Session, owner: Owner, *, include_revoked: bool = False
) -> list[PatientPortalMyCarlosAvailabilitySubscription]:
    statement = select(PatientPortalMyCarlosAvailabilitySubscription).where(
        PatientPortalMyCarlosAvailabilitySubscription.account_id == owner.account_id,
        PatientPortalMyCarlosAvailabilitySubscription.device_id == owner.device_id,
    )
    if not include_revoked:
        statement = statement.where(
            PatientPortalMyCarlosAvailabilitySubscription.revoked_at.is_(None)
        )
    return list(
        session.scalars(statement.order_by(PatientPortalMyCarlosAvailabilitySubscription.id))
    )


@dataclass(frozen=True)
class EnrollmentRequest:
    """What the device sends, after the patient's remote consent and an observed OS permission."""

    platform: str
    destination_id: str
    remote_enabled: bool
    remote_consent_version: int
    permission_observed: bool


def enroll(
    session: Session,
    owner: Owner,
    request: EnrollmentRequest,
    *,
    now: datetime | None = None,
) -> tuple[PatientPortalMyCarlosAvailabilitySubscription, bool]:
    """Enrolls a destination for this device; the row and whether it is new.

    Remote consent v1 and an observed OS permission are required: the local-notice setting is
    not consent. A destination already enrolled by this device is returned again, with the
    remote switch updated; one enrolled elsewhere, or ever revoked, is refused, so a revoked
    destination never comes back. At most `MAX_DESTINATIONS` live enrollments per device.
    """
    if not session.in_transaction():
        raise AvailabilityError("transaction_required")
    try:
        platform = PushPlatform(request.platform)
    except ValueError:
        raise EnrollmentRefusal("invalid_platform") from None
    destination_id = _uuid_text(request.destination_id, "invalid_destination")
    if (
        type(request.remote_consent_version) is not int
        or request.remote_consent_version != REMOTE_CONSENT_VERSION
        or request.permission_observed is not True
    ):
        raise EnrollmentRefusal("consent_required")
    if type(request.remote_enabled) is not bool:
        raise EnrollmentRefusal("invalid_enrollment")
    _lock_active_device(session, owner)
    existing = _destination_row(session, destination_id)
    if existing is not None:
        if existing.revoked_at is not None:
            raise EnrollmentRefusal("destination_revoked")
        if (existing.account_id, existing.device_id) != (owner.account_id, owner.device_id):
            raise EnrollmentRefusal("destination_taken")
        if existing.platform != platform.value:
            raise EnrollmentRefusal("destination_taken")
        existing.remote_enabled = request.remote_enabled
        existing.remote_consent_version = request.remote_consent_version
        existing.permission_observed = True
        return existing, False
    live = session.scalar(
        select(func.count())
        .select_from(PatientPortalMyCarlosAvailabilitySubscription)
        .where(
            PatientPortalMyCarlosAvailabilitySubscription.account_id == owner.account_id,
            PatientPortalMyCarlosAvailabilitySubscription.device_id == owner.device_id,
            PatientPortalMyCarlosAvailabilitySubscription.revoked_at.is_(None),
        )
    )
    if live >= MAX_DESTINATIONS:
        raise EnrollmentRefusal("destination_capacity")
    row = PatientPortalMyCarlosAvailabilitySubscription(
        subscription_id=str(uuid4()),
        account_id=owner.account_id,
        device_id=owner.device_id,
        epoch=str(uuid4()),
        destination_id=destination_id,
        platform=platform.value,
        remote_enabled=request.remote_enabled,
        remote_consent_version=request.remote_consent_version,
        permission_observed=True,
        created_at=now or datetime.now(UTC),
    )
    # Two devices enrolling one destination at the same moment both pass the lookup
    # above (each holds only its own device row): the unique index decides, and the
    # loser is told the destination is taken, inside a savepoint so its transaction
    # stays usable.
    try:
        with session.begin_nested():
            session.add(row)
            session.flush()
    except IntegrityError:
        if _destination_row(session, destination_id) is None:
            raise
        raise EnrollmentRefusal("destination_taken") from None
    return row, True


def _destination_row(
    session: Session, destination_id: str
) -> PatientPortalMyCarlosAvailabilitySubscription | None:
    return session.scalars(
        select(PatientPortalMyCarlosAvailabilitySubscription).where(
            PatientPortalMyCarlosAvailabilitySubscription.destination_id == destination_id
        )
    ).first()


def revoke(
    session: Session,
    owner: Owner,
    subscription_id: object,
    *,
    by: str = "device",
    now: datetime | None = None,
) -> PatientPortalMyCarlosAvailabilitySubscription:
    """Revokes this device's subscription, keeping it as a tombstone; again is harmless.

    Its pending intents go with it. A leased one is already being sent and cannot be recalled:
    the dispatch-time check suppresses only what has not reached the provider.
    """
    if not session.in_transaction():
        raise AvailabilityError("transaction_required")
    wanted = _uuid_text(subscription_id, "not_found")
    _lock_active_device(session, owner)
    row = session.scalars(
        select(PatientPortalMyCarlosAvailabilitySubscription)
        .where(
            PatientPortalMyCarlosAvailabilitySubscription.subscription_id == wanted,
            PatientPortalMyCarlosAvailabilitySubscription.account_id == owner.account_id,
            PatientPortalMyCarlosAvailabilitySubscription.device_id == owner.device_id,
        )
        .with_for_update()
    ).first()
    if row is None:
        raise EnrollmentRefusal("not_found")
    if row.revoked_at is None:
        row.revoked_at = now or datetime.now(UTC)
        row.revoked_by = by
        row.remote_enabled = False
        for pending in session.scalars(
            select(PatientPortalMyCarlosAvailabilityOutbox).where(
                PatientPortalMyCarlosAvailabilityOutbox.subscription_id == row.subscription_id,
                PatientPortalMyCarlosAvailabilityOutbox.status == STATUS_PENDING,
            )
        ):
            session.delete(pending)
        session.flush()
    return row


class SqlAvailabilityTransaction:
    """The policy core's `AvailabilityTransaction`, over the caller's open session.

    Use it inside the transaction that inserts the mailbox copy, so a rollback discards the
    copy and its intent together. It never commits, sends, or schedules anything.
    """

    def __init__(self, session: Session, *, clock: Callable[[], int] | None = None) -> None:
        self._session = session
        self._clock = clock or (lambda: int(time()))

    def in_transaction(self) -> bool:
        return self._session.in_transaction()

    def subscriptions(self, owner: Owner) -> Sequence[Subscription]:
        return [as_subscription(row) for row in subscriptions_for_owner(self._session, owner)]

    def put(self, intent: OutboxIntent) -> bool:
        """Stores the intent: coalesced into the unleased pending slot of its subscription and
        epoch, or a new pending row; False when a same or newer sequence is already there."""
        if not self._session.in_transaction():
            raise AvailabilityError("transaction_required")
        now = self._clock()
        subscription_id = str(intent.hint.subscription_id)
        epoch = str(intent.hint.epoch)
        row = self._session.scalars(
            select(PatientPortalMyCarlosAvailabilitySubscription)
            .where(PatientPortalMyCarlosAvailabilitySubscription.subscription_id == subscription_id)
            .with_for_update()
        ).first()
        if (
            row is None
            or row.revoked_at is not None
            or row.epoch != epoch
            or row.destination_id != str(intent.destination_id)
            or row.platform != intent.platform.value
            or (row.account_id, row.device_id) != (intent.owner.account_id, intent.owner.device_id)
        ):
            # Old work never retargets: a different binding is a different enrollment.
            raise AvailabilityError("coalescing_binding_mismatch")
        pending = self._session.scalars(
            select(PatientPortalMyCarlosAvailabilityOutbox)
            .where(
                PatientPortalMyCarlosAvailabilityOutbox.subscription_id == subscription_id,
                PatientPortalMyCarlosAvailabilityOutbox.epoch == epoch,
                PatientPortalMyCarlosAvailabilityOutbox.status == STATUS_PENDING,
            )
            .with_for_update()
        ).first()
        if pending is not None:
            existing = OutboxIntent(
                intent.owner,
                intent.destination_id,
                intent.platform,
                ReadyHint(intent.hint.subscription_id, intent.hint.epoch, pending.sequence),
                pending.expires_at,
            )
            merged = coalesce_pending(existing, intent, now=now)
            if merged == existing:
                return False
            if pending.expires_at <= now:
                # The slot had expired: the newer intent starts its own life window, but keeps
                # the slot's attempts and next attempt time.
                pending.created_at = now
            pending.sequence = merged.hint.sequence
            pending.expires_at = merged.expires_at
            self._session.flush()
            return True
        latest = self._session.scalar(
            select(func.max(PatientPortalMyCarlosAvailabilityOutbox.sequence)).where(
                PatientPortalMyCarlosAvailabilityOutbox.subscription_id == subscription_id,
                PatientPortalMyCarlosAvailabilityOutbox.epoch == epoch,
            )
        )
        if latest is not None and intent.hint.sequence <= latest:
            return False
        if intent.expires_at <= now:
            return False
        self._session.add(
            PatientPortalMyCarlosAvailabilityOutbox(
                subscription_id=subscription_id,
                epoch=epoch,
                sequence=intent.hint.sequence,
                expires_at=intent.expires_at,
                status=STATUS_PENDING,
                attempts=0,
                created_at=now,
            )
        )
        self._session.flush()
        return True
