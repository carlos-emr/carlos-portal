# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Durable footer-only attempt evidence, separate from patient message content.

Snapshots are immutable. An absent terminal record means acceptance was not
recorded, including a crash after SMTP accepted a message. Files are trusted private
storage; schema/hashes detect corruption, not replacement by their owner or root.
"""

import heapq
import json
import os
import re
import secrets
import stat
import time
import uuid
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

from carlos_patient_portal.clinic_footer import (
    FOOTER_FAILURE_REASONS,
    MAX_FOOTER_PAYLOAD_BYTES,
    MAX_FOOTER_RESPONSE_BYTES,
    ClinicFooterSnapshot,
    ClinicFooterUnavailableError,
    bounded_json,
)

FooterOutcome = Literal["accepted", "failed", "unknown"]
FOOTER_MESSAGE_KINDS = frozenset(
    {
        "mfa",
        "password_reset",
        "contact_change",
        "email_change_confirmation",
        "email_change_requested",
        "booking_prompt",
        "booking_prompt_update",
    }
)
ATTEMPT_ID_PATTERN = re.compile(r"[0-9]{20}-[0-9a-f]{32}")
HOUR_PATTERN = re.compile(r"(?:[01][0-9]|2[0-3])")
REVISION_PATTERN = re.compile(r"[0-9a-f]{64}")
# For the day folder, which holds only its (at most 24) hour folders. An hour folder has no limit:
# writing never stops for the audit's sake, and a page keeps only the newest few names it needs
# while it passes once over the folder, so any hour stays readable at any size.
MAX_AUDIT_DIRECTORY_ENTRIES = 10_000
# Each footer revision is stored once, named by its revision (a hash of its content), and every
# attempt names the revision it used. A logo (up to ~136 KB encoded) is no longer copied per email.
FOOTERS_DIRECTORY = "footers"
_SNAPSHOT_FIELDS = frozenset(
    {"schema", "attempt_id", "prepared_at", "kind", "footer_revision", "footer_skipped"}
)
# The only kinds that may go out without the footer while it is unavailable (Ben's D138 on #27):
# sign-in/MFA verification codes and password resets. Every other email fails closed.
FOOTER_SKIPPABLE_KINDS = frozenset({"mfa", "password_reset"})
_FOOTER_FIELDS = frozenset({"schema", "footer"})
_OUTCOME_FIELDS = frozenset({"schema", "attempt_id", "status", "status_at"})


class FooterAuditUnavailableError(Exception):
    """Footer attempt evidence cannot be durably written or safely read."""


def _failure() -> FooterAuditUnavailableError:
    return FooterAuditUnavailableError("clinic footer audit is unavailable")


def _timestamp(epoch_ns: int) -> str:
    return (
        datetime.fromtimestamp(epoch_ns // 1_000_000_000, UTC)
        .replace(
            microsecond=epoch_ns % 1_000_000_000 // 1_000,
        )
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _date(value: str) -> str:
    try:
        if date.fromisoformat(value).isoformat() != value:
            raise _failure()
    except (ValueError, TypeError):
        raise _failure() from None
    return value


@dataclass(frozen=True)
class FooterAuditAttempt:
    date: str
    attempt_id: str

    @property
    def hour(self) -> str:
        """The UTC hour folder the attempt lives in, from its own timestamp."""
        return _hour(self.attempt_id)


def _hour(attempt_id: str) -> str:
    if ATTEMPT_ID_PATTERN.fullmatch(attempt_id) is None:
        raise _failure()
    return _timestamp(int(attempt_id[:20]))[11:13]


class FooterAuditStore:
    def __init__(self, directory: str | None, clinic_id: str) -> None:
        path = Path(directory) if directory is not None else None
        if path is not None and not path.is_absolute():
            raise _failure()
        self._directory = path
        self._clinic_id = clinic_id

    @staticmethod
    def _private(fd: int, *, directory: bool) -> None:
        info = os.fstat(fd)
        valid = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not valid or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise _failure()

    def _open_root(self) -> int:
        if self._directory is None:
            raise _failure()
        if self._directory.resolve(strict=True) != self._directory:
            raise _failure()
        fd = os.open(self._directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            self._private(fd, directory=True)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def check_ready(self) -> None:
        """Probe durable exclusive publication and cleanup without an email or PHI."""
        fd = self._open_root()
        name = ".probe-" + secrets.token_hex(16)
        try:
            self._publish(fd, name, {"probe": 1})
            os.unlink(name, dir_fd=fd)
            os.fsync(fd)
        finally:
            os.close(fd)

    def _open_child(self, parent: int, name: str, *, create: bool) -> int:
        if create:
            try:
                os.mkdir(name, mode=0o700, dir_fd=parent)
                os.fsync(parent)
            except FileExistsError:
                pass
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            self._private(fd, directory=True)
        except BaseException:
            os.close(fd)
            raise
        return fd

    def _open_date(self, day: str, *, create: bool) -> int:
        day = _date(day)
        root = self._open_root()
        try:
            return self._open_child(root, day, create=create)
        finally:
            os.close(root)

    def _open_hour(self, day: str, hour: str, *, create: bool) -> int:
        if HOUR_PATTERN.fullmatch(hour) is None:
            raise _failure()
        day_fd = self._open_date(day, create=create)
        try:
            return self._open_child(day_fd, hour, create=create)
        finally:
            os.close(day_fd)

    def _open_footers(self, *, create: bool) -> int:
        root = self._open_root()
        try:
            return self._open_child(root, FOOTERS_DIRECTORY, create=create)
        finally:
            os.close(root)

    def _store_footer(self, snapshot: ClinicFooterSnapshot) -> None:
        """Publish this footer revision once; an existing copy must be byte-for-byte the same."""
        record = {"schema": 1, "footer": snapshot.to_dict()}
        name = snapshot.revision + ".json"
        fd = self._open_footers(create=True)
        try:
            try:
                existing = self._read(fd, name)
            except FileNotFoundError:
                try:
                    self._publish(fd, name, record)
                    return
                except FileExistsError:
                    # Another process published the same revision first; check its copy.
                    existing = self._read(fd, name)
            if existing != record:
                raise _failure()
        finally:
            os.close(fd)

    def _load_footer(self, revision: object) -> ClinicFooterSnapshot:
        if not isinstance(revision, str) or REVISION_PATTERN.fullmatch(revision) is None:
            raise _failure()
        fd = self._open_footers(create=False)
        try:
            value = self._read(fd, revision + ".json")
        finally:
            os.close(fd)
        if (
            set(value) != _FOOTER_FIELDS
            or type(value["schema"]) is not int
            or value["schema"] != 1
            or not isinstance(value["footer"], dict)
        ):
            raise _failure()
        try:
            snapshot = ClinicFooterSnapshot.from_dict(value["footer"])
        except ClinicFooterUnavailableError:
            raise _failure() from None
        if snapshot.revision != revision or snapshot.clinic_id != self._clinic_id:
            raise _failure()
        return snapshot

    @staticmethod
    def _publish(fd: int, name: str, value: dict[str, object]) -> None:
        encoded = json.dumps(
            value, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(encoded) > MAX_FOOTER_PAYLOAD_BYTES:
            raise _failure()
        temporary = ".tmp-" + secrets.token_hex(16)
        file_fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd
        )
        try:
            with os.fdopen(file_fd, "wb") as handle:
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            # link is atomic and refuses an existing target. replace/rename could overwrite
            # another attempt; the snapshot must remain immutable even on a name collision.
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.fsync(fd)
        finally:
            os.unlink(temporary, dir_fd=fd)
            os.fsync(fd)

    def prepare(self, snapshot: ClinicFooterSnapshot, kind: str) -> FooterAuditAttempt:
        if kind not in FOOTER_MESSAGE_KINDS or snapshot.clinic_id != self._clinic_id:
            raise _failure()
        epoch_ns = time.time_ns()
        prepared_at = _timestamp(epoch_ns)
        attempt = FooterAuditAttempt(prepared_at[:10], f"{epoch_ns:020d}-" + uuid.uuid4().hex)
        # The footer first: an attempt record never names a revision that isn't stored.
        self._store_footer(snapshot)
        fd = self._open_hour(attempt.date, attempt.hour, create=True)
        try:
            self._publish(
                fd,
                attempt.attempt_id + ".prepared.json",
                {
                    "schema": 2,
                    "attempt_id": attempt.attempt_id,
                    "prepared_at": prepared_at,
                    "kind": kind,
                    "footer_revision": snapshot.revision,
                    "footer_skipped": None,
                },
            )
        finally:
            os.close(fd)
        return attempt

    def prepare_skipped(self, kind: str, reason: str) -> FooterAuditAttempt:
        """Record an attempt that goes out WITHOUT the footer, and the fixed reason it was skipped.

        Only a sign-in code or a password reset may (FOOTER_SKIPPABLE_KINDS).
        """
        if kind not in FOOTER_SKIPPABLE_KINDS or reason not in FOOTER_FAILURE_REASONS:
            raise _failure()
        epoch_ns = time.time_ns()
        prepared_at = _timestamp(epoch_ns)
        attempt = FooterAuditAttempt(prepared_at[:10], f"{epoch_ns:020d}-" + uuid.uuid4().hex)
        fd = self._open_hour(attempt.date, attempt.hour, create=True)
        try:
            self._publish(
                fd,
                attempt.attempt_id + ".prepared.json",
                {
                    "schema": 2,
                    "attempt_id": attempt.attempt_id,
                    "prepared_at": prepared_at,
                    "kind": kind,
                    "footer_revision": None,
                    "footer_skipped": reason,
                },
            )
        finally:
            os.close(fd)
        return attempt

    def record_outcome(self, attempt: FooterAuditAttempt, status: FooterOutcome) -> None:
        if ATTEMPT_ID_PATTERN.fullmatch(attempt.attempt_id) is None or status not in {
            "accepted",
            "failed",
            "unknown",
        }:
            raise _failure()
        fd = self._open_hour(attempt.date, attempt.hour, create=False)
        try:
            # Never create a terminal outcome without its immutable preparation record.
            self._read_snapshot(fd, attempt.attempt_id, attempt.date)
            self._publish(
                fd,
                attempt.attempt_id + ".outcome.json",
                {
                    "schema": 1,
                    "attempt_id": attempt.attempt_id,
                    "status": status,
                    "status_at": _timestamp(time.time_ns()),
                },
            )
        finally:
            os.close(fd)

    @staticmethod
    def _read(fd: int, name: str) -> dict[str, object]:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            FooterAuditStore._private(file_fd, directory=False)
            if os.fstat(file_fd).st_size > MAX_FOOTER_PAYLOAD_BYTES:
                raise _failure()
            with os.fdopen(file_fd, "rb", closefd=False) as handle:
                encoded = handle.read(MAX_FOOTER_PAYLOAD_BYTES + 1)
            return bounded_json(encoded, maximum=MAX_FOOTER_PAYLOAD_BYTES)
        except ClinicFooterUnavailableError:
            raise _failure() from None
        finally:
            os.close(file_fd)

    def _read_snapshot(
        self,
        fd: int,
        attempt_id: str,
        day: str,
        footers: dict[object, ClinicFooterSnapshot] | None = None,
    ) -> tuple[dict[str, object], ClinicFooterSnapshot | None]:
        """One attempt and its footer (None when skipped). `footers` reads each revision once."""
        if ATTEMPT_ID_PATTERN.fullmatch(attempt_id) is None:
            raise _failure()
        value = self._read(fd, attempt_id + ".prepared.json")
        if (
            set(value) != _SNAPSHOT_FIELDS
            or type(value["schema"]) is not int
            or value["schema"] != 2
            or value["attempt_id"] != attempt_id
            or not isinstance(value["kind"], str)
            or value["kind"] not in FOOTER_MESSAGE_KINDS
            or value["prepared_at"] != _timestamp(int(attempt_id[:20]))
            or not isinstance(value["prepared_at"], str)
            or value["prepared_at"][:10] != day
        ):
            raise _failure()
        skipped = value["footer_skipped"]
        if skipped is not None:
            if (
                value["footer_revision"] is not None
                or not isinstance(skipped, str)
                or skipped not in FOOTER_FAILURE_REASONS
                or value["kind"] not in FOOTER_SKIPPABLE_KINDS
            ):
                raise _failure()
            return value, None
        footers = {} if footers is None else footers
        revision = value["footer_revision"]
        if revision not in footers:
            footers[revision] = self._load_footer(revision)
        return value, footers[revision]

    def _display(
        self,
        fd: int,
        attempt_id: str,
        day: str,
        footers: dict[object, ClinicFooterSnapshot] | None = None,
    ) -> dict[str, object]:
        value, snapshot = self._read_snapshot(fd, attempt_id, day, footers)
        status, status_at = "prepared", None
        try:
            outcome = self._read(fd, attempt_id + ".outcome.json")
        except FileNotFoundError:
            pass
        else:
            if (
                set(outcome) != _OUTCOME_FIELDS
                or type(outcome["schema"]) is not int
                or outcome["schema"] != 1
                or outcome["attempt_id"] != attempt_id
                or not isinstance(outcome["status"], str)
                or outcome["status"] not in {"accepted", "failed", "unknown"}
                or not isinstance(outcome["status_at"], str)
            ):
                raise _failure()
            try:
                instant = datetime.fromisoformat(outcome["status_at"])
                if instant.tzinfo != UTC or not outcome["status_at"].endswith("Z"):
                    raise _failure()
            except ValueError:
                raise _failure() from None
            status, status_at = outcome["status"], outcome["status_at"]
        item: dict[str, object] = {
            "attempt_id": attempt_id,
            "kind": value["kind"],
            "prepared_at": value["prepared_at"],
            "status": status,
            "status_at": status_at,
            "clinic_id": snapshot.clinic_id if snapshot else self._clinic_id,
            "revision": snapshot.revision if snapshot else None,
            "footer_text": snapshot.plain if snapshot else None,
            "logo_sha256": snapshot.logo.sha256 if snapshot and snapshot.logo else None,
        }
        # Only a skipped attempt carries footer_skipped, so every other item keeps the exact
        # field set CARLOS's reader checks (PortalEmailFooterAuditPage).
        if value["footer_skipped"] is not None:
            item["footer_skipped"] = value["footer_skipped"]
        return item

    @staticmethod
    def _hour_candidates(
        entries: Iterator[os.DirEntry[str]], hour: str, before: str | None
    ) -> Iterator[str]:
        """Attempt ids in one hour folder older than `before`; every record name is checked."""
        for entry in entries:
            if entry.name.endswith(".prepared.json"):
                candidate = entry.name.removesuffix(".prepared.json")
                if _hour(candidate) != hour:
                    raise _failure()
                if before is None or candidate < before:
                    yield candidate

    def list_attempts(
        self, *, day: str, limit: int = 50, before: str | None = None
    ) -> dict[str, object]:
        day = _date(day)
        if (
            type(limit) is not int
            or not 1 <= limit <= 100
            or (before is not None and ATTEMPT_ID_PATTERN.fullmatch(before) is None)
        ):
            raise _failure()
        first_hour = "23"
        if before is not None:
            # A cursor names an attempt of this day; listing resumes in its hour folder.
            if _timestamp(int(before[:20]))[:10] != day:
                raise _failure()
            first_hour = _hour(before)
        # Validate the root even for an empty day: wrong permissions/missing volume must
        # not be misrepresented as an empty audit history.
        root = self._open_root()
        os.close(root)
        try:
            day_fd = self._open_date(day, create=False)
        except FileNotFoundError:
            return {"date": day, "attempts": [], "next_before": None}
        try:
            hours: list[str] = []
            with os.scandir(day_fd) as entries:
                for count, entry in enumerate(entries, start=1):
                    if count > MAX_AUDIT_DIRECTORY_ENTRIES:
                        raise _failure()
                    if HOUR_PATTERN.fullmatch(entry.name) and entry.name <= first_hour:
                        hours.append(entry.name)
            hours.sort(reverse=True)
            attempts: list[dict[str, object]] = []
            footers: dict[object, ClinicFooterSnapshot] = {}
            for index, hour in enumerate(hours):
                fd = self._open_child(day_fd, hour, create=False)
                try:
                    # One pass over the folder, keeping only the newest names this page can
                    # still use (+1 to know whether more follow): memory stays bounded however
                    # many attempts the hour holds.
                    wanted = limit - len(attempts) + 1
                    with os.scandir(fd) as entries:
                        candidates = heapq.nlargest(
                            wanted, self._hour_candidates(entries, hour, before)
                        )
                    for position, candidate in enumerate(candidates):
                        item = self._display(fd, candidate, day, footers)
                        proposed = {
                            "date": day,
                            "attempts": [*attempts, item],
                            "next_before": candidate,
                        }
                        size = len(
                            json.dumps(proposed, ensure_ascii=True, separators=(",", ":")).encode(
                                "utf-8"
                            )
                        )
                        if size > MAX_FOOTER_RESPONSE_BYTES:
                            if not attempts:
                                raise _failure()
                            next_before = attempts[-1]["attempt_id"]
                            return {"date": day, "attempts": attempts, "next_before": next_before}
                        attempts.append(item)
                        if len(attempts) == limit:
                            # A full page stops here, without reading the next hour folder. An
                            # hour folder only exists once an attempt was written in it.
                            more = position + 1 < len(candidates) or index + 1 < len(hours)
                            next_before = candidate if more else None
                            return {"date": day, "attempts": attempts, "next_before": next_before}
                finally:
                    os.close(fd)
            return {"date": day, "attempts": attempts, "next_before": None}
        finally:
            os.close(day_fd)
