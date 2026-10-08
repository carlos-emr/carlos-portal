# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

import logging
import os
import sqlite3
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import quote

from sqlalchemy import and_, delete, func, or_, select, update
from sqlalchemy.engine import make_url
from sqlalchemy.orm import Session, aliased

from carlos_patient_portal.booking_choices import close_lapsed_choices
from carlos_patient_portal.booking_offers import (
    BOOKED_TIME_RETENTION_AFTER_START,
    closed_after_expiry_notice,
)
from carlos_patient_portal.models import (
    BOOKING_CHOICE_STATE_BOOKED,
    BOOKING_CHOICE_STATE_EXPIRED,
    BOOKING_CHOICE_STATE_PENDING,
    BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE,
    BOOKING_CHOICE_STATE_WITHDRAWN,
    BOOKING_PROMPT_STATUS_BOOKED,
    BOOKING_PROMPT_STATUS_CHOICE_PENDING,
    BOOKING_PROMPT_STATUS_DECLINED_ALL,
    BOOKING_PROMPT_STATUS_WITHDRAWN,
    INVITE_STATUS_PENDING,
    INVITE_STATUS_PREPARED,
    INVITE_STATUS_REVOKED,
    INVITE_STATUS_SUPERSEDED,
    OUTBOX_STATUS_DELIVERED,
    OUTBOX_STATUS_FAILED,
    PatientPortalAuditEvent,
    PatientPortalBookingChoice,
    PatientPortalBookingOfferedSlot,
    PatientPortalBookingPrompt,
    PatientPortalEmailChangeRequest,
    PatientPortalInvite,
    PatientPortalMfaChallenge,
    PatientPortalOutboundDelivery,
    PatientPortalPasswordResetToken,
    PatientPortalSession,
    utc_now,
)

DEFAULT_AUDIT_PRUNE_BATCH_SIZE = 1000
MIN_AUDIT_PRUNE_BATCH_SIZE = 1
MAX_AUDIT_PRUNE_BATCH_SIZE = 10000
DEFAULT_TRANSIENT_RETENTION_DAYS = 30

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class TransientCleanupResult:
    sessions: int
    mfa_challenges: int
    reset_records: int
    email_change_requests: int
    invites: int
    outbound_deliveries: int
    booking_prompts: int = 0
    # Offered appointment times that can no longer be picked, deleted rather than kept.
    offered_slots: int = 0
    # Choices whose copy of the chosen time was cleared: booked ones a day after the appointment.
    booking_choice_times: int = 0
    # Picks whose time started before CARLOS answered, closed so they are neither booked nor kept.
    lapsed_booking_choices: int = 0

    @property
    def total(self) -> int:
        return (
            self.sessions
            + self.mfa_challenges
            + self.reset_records
            + self.email_change_requests
            + self.invites
            + self.outbound_deliveries
            + self.booking_prompts
            + self.offered_slots
            + self.booking_choice_times
            + self.lapsed_booking_choices
        )


class MaintenanceError(Exception):
    """Base error for operational maintenance tasks."""


class BackupUnsupportedError(MaintenanceError):
    """Raised when the configured database cannot use the built-in backup helper."""


class BackupUnavailableError(MaintenanceError):
    """Raised when a database backup or restore source is unavailable."""


class BackupDestinationExistsError(MaintenanceError):
    """Raised when a backup or restore target already exists and overwrite is disabled."""


def audit_retention_cutoff(retention_days: int, *, now: datetime | None = None) -> datetime:
    if retention_days < 1:
        raise ValueError("retention_days must be positive")
    reference_time = now or utc_now()
    if reference_time.tzinfo is None:
        reference_time = reference_time.replace(tzinfo=UTC)
    return reference_time - timedelta(days=retention_days)


def normalize_prune_batch_size(batch_size: int) -> int:
    if batch_size < MIN_AUDIT_PRUNE_BATCH_SIZE or batch_size > MAX_AUDIT_PRUNE_BATCH_SIZE:
        raise ValueError(
            "batch_size must be between "
            f"{MIN_AUDIT_PRUNE_BATCH_SIZE} and {MAX_AUDIT_PRUNE_BATCH_SIZE}"
        )
    return batch_size


def count_prunable_audit_events(session: Session, *, before: datetime) -> int:
    return int(
        session.scalar(
            select(func.count(PatientPortalAuditEvent.id)).where(
                PatientPortalAuditEvent.created_at < before
            )
        )
        or 0
    )


def prune_audit_events(
    session: Session,
    *,
    before: datetime,
    batch_size: int = DEFAULT_AUDIT_PRUNE_BATCH_SIZE,
) -> int:
    normalized_batch_size = normalize_prune_batch_size(batch_size)
    audit_event_ids = list(
        session.scalars(
            select(PatientPortalAuditEvent.id)
            .where(PatientPortalAuditEvent.created_at < before)
            .order_by(PatientPortalAuditEvent.created_at, PatientPortalAuditEvent.id)
            .limit(normalized_batch_size)
        )
    )
    if not audit_event_ids:
        return 0

    result = session.execute(
        delete(PatientPortalAuditEvent).where(PatientPortalAuditEvent.id.in_(audit_event_ids))
    )
    return int(result.rowcount or 0)


def export_audit_events(
    session: Session,
    *,
    after_id: int = 0,
    batch_size: int = DEFAULT_AUDIT_PRUNE_BATCH_SIZE,
) -> list[dict[str, object]]:
    """Return an ordered JSON-safe batch for an append-only external audit sink."""
    if after_id < 0:
        raise ValueError("after_id must not be negative")
    normalized_batch_size = normalize_prune_batch_size(batch_size)
    events = session.scalars(
        select(PatientPortalAuditEvent)
        .where(PatientPortalAuditEvent.id > after_id)
        .order_by(PatientPortalAuditEvent.id)
        .limit(normalized_batch_size)
    )
    field_names = tuple(column.name for column in PatientPortalAuditEvent.__table__.columns)
    return [
        {
            field_name: (
                value.isoformat() if isinstance(value, datetime) else value
            )
            for field_name in field_names
            if (value := getattr(event, field_name)) is not None
        }
        for event in events
    ]


def cleanup_transient_auth_rows(
    session: Session,
    *,
    before: datetime,
    batch_size: int = DEFAULT_AUDIT_PRUNE_BATCH_SIZE,
    dry_run: bool = False,
    now: datetime | None = None,
) -> TransientCleanupResult:
    """Delete expired transient rows, and appointment data the moment it is no longer needed.

    Most rows wait `before`, the retention cutoff. Offered appointment times and copies of chosen
    times do not: they are the portal's only appointment data, so they go at the first run after
    they stop being useful, whatever the retention window.
    """
    normalized_batch_size = normalize_prune_batch_size(batch_size)
    current_time = now or utc_now()
    booked_time_cutoff = current_time - BOOKED_TIME_RETENTION_AFTER_START
    prepared_replacement = aliased(PatientPortalInvite)
    has_prepared_replacement = (
        select(prepared_replacement.id)
        .where(
            prepared_replacement.supersedes_invite_id == PatientPortalInvite.id,
            prepared_replacement.status == INVITE_STATUS_PREPARED,
        )
        .exists()
    )
    settled_outbox_predicate = and_(
        PatientPortalOutboundDelivery.status.in_(
            (OUTBOX_STATUS_DELIVERED, OUTBOX_STATUS_FAILED)
        ),
        PatientPortalOutboundDelivery.created_at < before,
    )
    outbound_delivery_ids = list(
        session.scalars(
            select(PatientPortalOutboundDelivery.id)
            .where(settled_outbox_predicate)
            .order_by(PatientPortalOutboundDelivery.id)
            .limit(normalized_batch_size)
        )
    )
    remaining_linked_delivery = select(PatientPortalOutboundDelivery.id).where(
        PatientPortalOutboundDelivery.reset_token_id == PatientPortalPasswordResetToken.id
    )
    remaining_prompt_notice = select(PatientPortalOutboundDelivery.id).where(
        PatientPortalOutboundDelivery.booking_prompt_id == PatientPortalBookingPrompt.id
    )
    if dry_run and outbound_delivery_ids:
        # A dry run must model the bounded outbox pass that a live invocation performs first.
        # Excluding only that exact candidate set makes the reset forecast agree in both directions:
        # a linked row outside the batch still protects its parent, while a parent whose last linked
        # row is in the batch is reported as removable in this invocation.
        remaining_linked_delivery = remaining_linked_delivery.where(
            PatientPortalOutboundDelivery.id.not_in(outbound_delivery_ids)
        )
        remaining_prompt_notice = remaining_prompt_notice.where(
            PatientPortalOutboundDelivery.id.not_in(outbound_delivery_ids)
        )
    # A time the patient can no longer pick: it has started, or its prompt has expired or closed.
    # Closing a prompt deletes its times already; this also catches any a crash left behind.
    offered_slot_prompt_closed = (
        select(PatientPortalBookingPrompt.id)
        .where(
            PatientPortalBookingPrompt.id == PatientPortalBookingOfferedSlot.prompt_id,
            or_(
                PatientPortalBookingPrompt.expires_at <= current_time,
                PatientPortalBookingPrompt.status.in_(
                    (
                        BOOKING_PROMPT_STATUS_BOOKED,
                        BOOKING_PROMPT_STATUS_WITHDRAWN,
                        BOOKING_PROMPT_STATUS_DECLINED_ALL,
                    )
                ),
            ),
        )
        .correlate(PatientPortalBookingOfferedSlot)
        .exists()
    )
    booked_time_upcoming = (
        select(PatientPortalBookingChoice.id)
        .where(
            PatientPortalBookingChoice.prompt_id == PatientPortalBookingPrompt.id,
            PatientPortalBookingChoice.state == BOOKING_CHOICE_STATE_BOOKED,
            PatientPortalBookingChoice.starts_at > booked_time_cutoff,
        )
        .exists()
    )
    unresolved_choice = (
        select(PatientPortalBookingChoice.id)
        .where(
            PatientPortalBookingChoice.prompt_id == PatientPortalBookingPrompt.id,
            PatientPortalBookingChoice.state == BOOKING_CHOICE_STATE_PENDING,
        )
        .exists()
    )
    predicates = (
        # Ordered deliberately: outbound deliveries are removed before reset tokens, because
        # PatientPortalOutboundDelivery.reset_token_id is ON DELETE CASCADE. Deleting reset
        # tokens first destroyed delivery history the report never mentioned - it counted only
        # its own rowcounts while the database quietly removed more.
        (
            PatientPortalOutboundDelivery,
            # Never delete pending/processing work. Contact-change rows intentionally have no
            # reset-token parent, so including reset_token_id IS NULL here used to erase queued
            # security notices without a delivery outcome or terminal-failure audit. Settled rows
            # of either kind are retained for the configured window and are then safe to remove.
            settled_outbox_predicate,
        ),
        (
            PatientPortalSession,
            or_(
                PatientPortalSession.expires_at < before,
                PatientPortalSession.revoked_at < before,
            ),
        ),
        (PatientPortalMfaChallenge, PatientPortalMfaChallenge.expires_at < before),
        (
            PatientPortalPasswordResetToken,
            and_(
                PatientPortalPasswordResetToken.expires_at < before,
                # Removing a reset-token parent cascades every linked outbox row. Require every
                # linked row to be absent after the bounded outbox pass, rather than assuming every
                # old settled row fit in that independent batch. This keeps physical deletions and
                # reported counts within the requested limit. In dry-run mode the subquery excludes
                # precisely the outbox candidate IDs selected above, modelling the same ordering.
                ~remaining_linked_delivery.exists(),
            ),
        ),
        (PatientPortalEmailChangeRequest, PatientPortalEmailChangeRequest.expires_at < before),
        (
            PatientPortalInvite,
            and_(
                PatientPortalInvite.expires_at < before,
                # SET NULL on the self-reference must not turn a prepared resend into a
                # first invite and bypass the original invite's revocation/status checks.
                ~has_prepared_replacement,
                PatientPortalInvite.status.in_(
                    (
                        INVITE_STATUS_PREPARED,
                        INVITE_STATUS_PENDING,
                        INVITE_STATUS_REVOKED,
                        INVITE_STATUS_SUPERSEDED,
                    )
                ),
            ),
        ),
        (
            PatientPortalBookingOfferedSlot,
            or_(
                PatientPortalBookingOfferedSlot.starts_at <= current_time,
                offered_slot_prompt_closed,
            ),
        ),
        (
            PatientPortalBookingPrompt,
            and_(
                # Keep unanswered choices, even after expiry, until CARLOS reports a result.
                # Notice rows cascade too, so wait until the bounded outbox pass removes them.
                PatientPortalBookingPrompt.expires_at < before,
                PatientPortalBookingPrompt.status != BOOKING_PROMPT_STATUS_CHOICE_PENDING,
                ~unresolved_choice,
                ~remaining_prompt_notice.exists(),
                # A booked appointment stays shown to the patient until a day after it starts,
                # however long ago the prompt expired.
                ~booked_time_upcoming,
                # So does a pick reported taken, or lapsed, after the expiry, for its short notice.
                ~closed_after_expiry_notice(current_time),
            ),
        ),
    )
    # Keyed by field name rather than built positionally: these counts are what the operator reads
    # to decide whether cleanup did what they expected, and a reordering of `predicates` must not be
    # able to silently relabel them.
    counts: dict[str, int] = {}

    def close_and_clear_booking_choices() -> None:
        # The fallback for when CARLOS has stopped polling (the poll closes lapsed picks first, and
        # emails the patient), then the choice-time clearing. Both before the prompt pass, which can
        # delete a prompt and its choices with it, so the reported counts match a dry run; and after
        # the sign-in passes, so this transaction locks sessions before prompts, as turning an
        # account off does.
        counts["lapsed_booking_choices"] = close_lapsed_choices(
            session,
            delete_slots=False,
            limit=normalized_batch_size,
            dry_run=dry_run,
        )
        counts["booking_choice_times"] = _clear_booking_choice_times(
            session,
            booked_time_cutoff=booked_time_cutoff,
            batch_size=normalized_batch_size,
            dry_run=dry_run,
        )

    for field_name, (model, predicate) in zip(
        (
            "outbound_deliveries",
            "sessions",
            "mfa_challenges",
            "reset_records",
            "email_change_requests",
            "invites",
            "offered_slots",
            "booking_prompts",
        ),
        predicates,
        strict=True,
    ):
        if field_name == "offered_slots":
            close_and_clear_booking_choices()
        candidates = (
            select(model.id).where(predicate).order_by(model.id).limit(normalized_batch_size)
        )
        if model is PatientPortalBookingOfferedSlot and not dry_run:
            # Every booking writer locks the parent before touching slots or choices.
            candidates = candidates.join(
                PatientPortalBookingPrompt,
                PatientPortalBookingPrompt.id == PatientPortalBookingOfferedSlot.prompt_id,
            ).with_for_update(of=PatientPortalBookingPrompt, skip_locked=True)
        if model in (PatientPortalInvite, PatientPortalBookingPrompt) and not dry_run:
            # Preparation locks its original invite before inserting the replacement. Lock
            # deletion candidates too, so a new preparation cannot appear between selection
            # and DELETE. The DELETE rechecks the child predicate using a fresh snapshot.
            candidates = candidates.with_for_update(skip_locked=True)
        record_ids = (
            outbound_delivery_ids
            if field_name == "outbound_deliveries"
            else list(session.scalars(candidates))
        )
        if dry_run or not record_ids:
            counts[field_name] = len(record_ids)
            continue
        # The DELETE re-applies the predicate to close the resend-vs-cleanup race, so the
        # selected count can overstate; report what was actually removed, like prune_audit_events.
        result = session.execute(
            delete(model).where(
                model.id.in_(record_ids),
                predicate,
            )
        )
        counts[field_name] = int(result.rowcount or 0)
    return TransientCleanupResult(**counts)


def _clear_booking_choice_times(
    session: Session,
    *,
    booked_time_cutoff: datetime,
    batch_size: int,
    dry_run: bool,
) -> int:
    """Clear the copy of a chosen time once nobody needs it.

    A booked time is kept until a day after it starts, so the patient's confirmation survives
    the appointment day. A time that was taken, or whose prompt was withdrawn, is cleared when that
    happens; this catches any a crash left behind. The choice row itself stays with its prompt, so
    a repeated CARLOS result is still answered idempotently.
    """
    stale_copy = or_(
        and_(
            PatientPortalBookingChoice.state == BOOKING_CHOICE_STATE_BOOKED,
            PatientPortalBookingChoice.starts_at <= booked_time_cutoff,
        ),
        and_(
            PatientPortalBookingChoice.state.in_(
                (
                    BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE,
                    BOOKING_CHOICE_STATE_WITHDRAWN,
                    BOOKING_CHOICE_STATE_EXPIRED,
                )
            ),
            PatientPortalBookingChoice.slot_id.is_not(None),
        ),
    )
    candidates = (
        select(PatientPortalBookingChoice.id)
        .join(
            PatientPortalBookingPrompt,
            PatientPortalBookingPrompt.id == PatientPortalBookingChoice.prompt_id,
        )
        .where(stale_copy)
        .order_by(PatientPortalBookingChoice.id)
        .limit(batch_size)
    )
    if not dry_run:
        # Result processing takes prompt then choice. Skip busy parents so cleanup never
        # takes the opposite order or waits while holding another prompt's lock.
        candidates = candidates.with_for_update(of=PatientPortalBookingPrompt, skip_locked=True)
    choice_ids = list(session.scalars(candidates))
    if dry_run or not choice_ids:
        return len(choice_ids)
    result = session.execute(
        update(PatientPortalBookingChoice)
        .where(PatientPortalBookingChoice.id.in_(choice_ids), stale_copy)
        .values(
            slot_id=None,
            starts_at=None,
            duration_minutes=None,
            visit_mode=None,
            location_code=None,
        )
        .execution_options(synchronize_session=False)
    )
    return int(result.rowcount or 0)


def summarize_outbox(session: Session) -> list[dict[str, object]]:
    """Aggregate the outbox by kind and status, with the age of the oldest waiting row.

    Rows piled up in `failed` were previously invisible: /internal/readiness checks only
    connectivity and the schema head, the worker is a separate process with no metrics
    endpoint, and no CLI could answer "is anything stuck?". Every value here is a count, a
    status or a timestamp - never a recipient, a payload or a message id.
    """
    rows = session.execute(
        select(
            PatientPortalOutboundDelivery.kind,
            PatientPortalOutboundDelivery.status,
            func.count(PatientPortalOutboundDelivery.id),
            func.min(PatientPortalOutboundDelivery.available_at),
            func.max(PatientPortalOutboundDelivery.attempt_count),
        ).group_by(
            PatientPortalOutboundDelivery.kind,
            PatientPortalOutboundDelivery.status,
        )
    ).all()
    return [
        {
            "kind": kind,
            "status": status,
            "count": int(count),
            "oldest_available_at": (
                oldest_available_at.isoformat() if oldest_available_at is not None else None
            ),
            "max_attempt_count": int(max_attempt_count or 0),
        }
        for kind, status, count, oldest_available_at, max_attempt_count in rows
    ]


def sqlite_database_path(database_url: str) -> Path:
    parsed_url = make_url(database_url)
    if parsed_url.get_backend_name() != "sqlite":
        raise BackupUnsupportedError(
            "built-in backup/restore supports SQLite only; use managed PostgreSQL backups "
            "or pg_dump/pg_restore for PostgreSQL deployments"
        )

    database = parsed_url.database
    if database is None or database in {"", ":memory:"}:
        raise BackupUnsupportedError("in-memory SQLite databases cannot be backed up or restored")
    return Path(database).expanduser()


def paths_match(path_a: Path, path_b: Path) -> bool:
    return path_a.resolve(strict=False) == path_b.resolve(strict=False)


def require_regular_file(path: Path, *, description: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise BackupUnavailableError(f"{description} must be a regular file: {path}")


def validate_sqlite_database(path: Path) -> None:
    require_regular_file(path, description="SQLite database")
    try:
        with sqlite3.connect(sqlite_read_only_uri(path), uri=True) as connection:
            integrity_result = connection.execute("PRAGMA integrity_check").fetchone()
    except sqlite3.DatabaseError as exc:
        raise BackupUnavailableError(f"SQLite database is invalid: {path}") from exc
    if integrity_result != ("ok",):
        raise BackupUnavailableError(f"SQLite database failed integrity check: {path}")


def fsync_path(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def sqlite_read_only_uri(path: Path) -> str:
    """Build a SQLite URI without treating literal filename punctuation as URI syntax."""
    return f"file:{quote(str(path.resolve()), safe='/')}?mode=ro"


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_sqlite_copy(source_path: Path, destination_path: Path) -> Path:
    destination_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination_path.name}.",
        suffix=".tmp",
        dir=destination_path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        os.fchmod(temporary_descriptor, stat.S_IRUSR | stat.S_IWUSR)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        with sqlite3.connect(sqlite_read_only_uri(source_path), uri=True) as source_connection:
            with sqlite3.connect(temporary_path) as destination_connection:
                source_connection.backup(destination_connection)
                integrity_result = destination_connection.execute(
                    "PRAGMA integrity_check"
                ).fetchone()
                if integrity_result != ("ok",):
                    raise BackupUnavailableError("copied SQLite database failed integrity check")
        os.chmod(temporary_path, stat.S_IRUSR | stat.S_IWUSR)
        fsync_path(temporary_path)
        os.replace(temporary_path, destination_path)
        try:
            fsync_directory(destination_path.parent)
        except OSError as exc:
            # The atomic rename has already completed. Some network/virtual filesystems do not
            # support directory fsync; report the installed backup accurately and leave a
            # diagnostic for operators rather than claiming the copy itself failed.
            logger.debug("SQLite backup directory fsync unavailable: %s", type(exc).__name__)
        return destination_path
    except (OSError, sqlite3.DatabaseError) as exc:
        raise BackupUnavailableError("SQLite database copy failed") from exc
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        temporary_path.unlink(missing_ok=True)


def backup_sqlite_database(
    database_url: str,
    output_path: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    source_path = sqlite_database_path(database_url)
    destination_path = Path(output_path).expanduser()
    if paths_match(source_path, destination_path):
        raise BackupDestinationExistsError("backup destination must differ from database path")
    if not source_path.exists():
        raise BackupUnavailableError(f"database does not exist: {source_path}")
    require_regular_file(source_path, description="database")
    if destination_path.is_symlink():
        raise BackupUnavailableError(
            f"backup destination must not be a symlink: {destination_path}"
        )
    if destination_path.exists() and not destination_path.is_file():
        raise BackupUnavailableError(
            f"backup destination must be a regular file: {destination_path}"
        )
    if destination_path.exists() and not overwrite:
        raise BackupDestinationExistsError(f"backup destination already exists: {destination_path}")
    validate_sqlite_database(source_path)
    return atomic_sqlite_copy(source_path, destination_path)


def restore_sqlite_database(
    database_url: str,
    input_path: str | Path,
    *,
    overwrite: bool = False,
) -> Path:
    source_path = Path(input_path).expanduser()
    destination_path = sqlite_database_path(database_url)
    if paths_match(source_path, destination_path):
        raise BackupDestinationExistsError("restore source must differ from database path")
    if not source_path.exists():
        raise BackupUnavailableError(f"backup source does not exist: {source_path}")
    require_regular_file(source_path, description="backup source")
    if destination_path.is_symlink():
        raise BackupUnavailableError(
            f"restore destination must not be a symlink: {destination_path}"
        )
    if destination_path.exists() and not destination_path.is_file():
        raise BackupUnavailableError(
            f"restore destination must be a regular file: {destination_path}"
        )
    if destination_path.exists() and not overwrite:
        raise BackupDestinationExistsError(
            f"restore destination already exists: {destination_path}"
        )
    active_sidecars = [
        sidecar
        for sidecar in (
            Path(f"{destination_path}-wal"),
            Path(f"{destination_path}-shm"),
        )
        if sidecar.exists() or sidecar.is_symlink()
    ]
    if active_sidecars:
        raise BackupUnavailableError(
            "SQLite restore requires the portal to be stopped and WAL sidecars removed "
            "after a clean checkpoint"
        )
    validate_sqlite_database(source_path)
    restored_path = atomic_sqlite_copy(source_path, destination_path)
    validate_sqlite_database(restored_path)
    return restored_path
