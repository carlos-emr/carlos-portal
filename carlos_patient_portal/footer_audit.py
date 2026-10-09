# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Durable footer-only attempt evidence, separate from patient message content.

Snapshots are immutable. An absent terminal record means acceptance was not
recorded, including a crash after SMTP accepted a message. Files are trusted private
storage; schema/hashes detect corruption, not replacement by their owner or root.
"""

import json
import os
import re
import secrets
import stat
import time
import uuid
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Literal

from carlos_patient_portal.clinic_footer import (
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
MAX_AUDIT_DIRECTORY_ENTRIES = 10_000
_SNAPSHOT_FIELDS = frozenset({"schema", "attempt_id", "prepared_at", "kind", "footer"})
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

    def _open_date(self, day: str, *, create: bool) -> int:
        day = _date(day)
        root = self._open_root()
        try:
            if create:
                try:
                    os.mkdir(day, mode=0o700, dir_fd=root)
                    os.fsync(root)
                except FileExistsError:
                    pass
            fd = os.open(day, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root)
            try:
                self._private(fd, directory=True)
            except BaseException:
                os.close(fd)
                raise
            return fd
        finally:
            os.close(root)

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
        fd = self._open_date(attempt.date, create=True)
        try:
            self._publish(
                fd,
                attempt.attempt_id + ".prepared.json",
                {
                    "schema": 1,
                    "attempt_id": attempt.attempt_id,
                    "prepared_at": prepared_at,
                    "kind": kind,
                    "footer": snapshot.to_dict(),
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
        fd = self._open_date(attempt.date, create=False)
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
        self, fd: int, attempt_id: str, day: str
    ) -> tuple[dict[str, object], ClinicFooterSnapshot]:
        if ATTEMPT_ID_PATTERN.fullmatch(attempt_id) is None:
            raise _failure()
        value = self._read(fd, attempt_id + ".prepared.json")
        if (
            set(value) != _SNAPSHOT_FIELDS
            or type(value["schema"]) is not int
            or value["schema"] != 1
            or value["attempt_id"] != attempt_id
            or not isinstance(value["kind"], str)
            or value["kind"] not in FOOTER_MESSAGE_KINDS
            or value["prepared_at"] != _timestamp(int(attempt_id[:20]))
            or not isinstance(value["prepared_at"], str)
            or value["prepared_at"][:10] != day
            or not isinstance(value["footer"], dict)
        ):
            raise _failure()
        try:
            snapshot = ClinicFooterSnapshot.from_dict(value["footer"])
        except ClinicFooterUnavailableError:
            raise _failure() from None
        if snapshot.clinic_id != self._clinic_id:
            raise _failure()
        return value, snapshot

    def _display(self, fd: int, attempt_id: str, day: str) -> dict[str, object]:
        value, snapshot = self._read_snapshot(fd, attempt_id, day)
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
        return {
            "attempt_id": attempt_id,
            "kind": value["kind"],
            "prepared_at": value["prepared_at"],
            "status": status,
            "status_at": status_at,
            "clinic_id": snapshot.clinic_id,
            "revision": snapshot.revision,
            "footer_text": snapshot.plain,
            "logo_sha256": snapshot.logo.sha256 if snapshot.logo else None,
        }

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
        # Validate the root even for an empty day: wrong permissions/missing volume must
        # not be misrepresented as an empty audit history.
        root = self._open_root()
        os.close(root)
        try:
            fd = self._open_date(day, create=False)
        except FileNotFoundError:
            return {"date": day, "attempts": [], "next_before": None}
        try:
            candidates: list[str] = []
            with os.scandir(fd) as entries:
                for count, entry in enumerate(entries, start=1):
                    if count > MAX_AUDIT_DIRECTORY_ENTRIES:
                        raise _failure()
                    if entry.name.endswith(".prepared.json"):
                        candidate = entry.name.removesuffix(".prepared.json")
                        if ATTEMPT_ID_PATTERN.fullmatch(candidate) is None:
                            raise _failure()
                        if before is None or candidate < before:
                            candidates.append(candidate)
            candidates.sort(reverse=True)
            attempts: list[dict[str, object]] = []
            next_before = None
            for candidate in candidates:
                item = self._display(fd, candidate, day)
                proposed = {"date": day, "attempts": [*attempts, item], "next_before": candidate}
                size = len(
                    json.dumps(proposed, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
                )
                if len(attempts) >= limit or size > MAX_FOOTER_RESPONSE_BYTES:
                    if not attempts:
                        raise _failure()
                    next_before = attempts[-1]["attempt_id"]
                    break
                attempts.append(item)
            return {"date": day, "attempts": attempts, "next_before": next_before}
        finally:
            os.close(fd)
