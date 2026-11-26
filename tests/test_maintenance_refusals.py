# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The maintenance helpers' refusals: the audit-retention limits and the SQLite backup and restore
guards beyond `test_operations.py` (FAKE data only).

A backup or a restore replaces a database file, so each refusal below is also checked to have left
the files it was asked not to touch exactly as they were.
"""

import logging
import os
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from carlos_patient_portal import maintenance
from carlos_patient_portal.maintenance import (
    MAX_AUDIT_PRUNE_BATCH_SIZE,
    MIN_AUDIT_PRUNE_BATCH_SIZE,
    BackupDestinationExistsError,
    BackupUnavailableError,
    BackupUnsupportedError,
    audit_retention_cutoff,
    backup_sqlite_database,
    export_audit_events,
    normalize_prune_batch_size,
    restore_sqlite_database,
    sqlite_database_path,
)


def make_database(path, value: str = "fake") -> None:
    with sqlite3.connect(path) as connection:
        connection.execute("CREATE TABLE note (value TEXT)")
        connection.execute("INSERT INTO note VALUES (?)", (value,))
    connection.close()


def read_value(path) -> str:
    with sqlite3.connect(path) as connection:
        value = connection.execute("SELECT value FROM note").fetchone()[0]
    connection.close()
    return value


def url(path) -> str:
    return f"sqlite+pysqlite:///{path}"


# --------------------------------------------------------------------------------------------
# Audit retention and export limits
# --------------------------------------------------------------------------------------------


def test_the_retention_cutoff_is_a_positive_number_of_days_before_a_utc_reference() -> None:
    now = datetime(2026, 7, 1, 12, 0, tzinfo=UTC)
    assert audit_retention_cutoff(30, now=now) == now - timedelta(days=30)
    # A reference with no zone is read as UTC, not as local time.
    naive = datetime(2026, 7, 1, 12, 0)
    assert audit_retention_cutoff(1, now=naive) == datetime(2026, 6, 30, 12, 0, tzinfo=UTC)
    for days in (0, -1):
        with pytest.raises(ValueError, match="retention_days must be positive"):
            audit_retention_cutoff(days, now=now)


def test_a_prune_batch_is_within_its_bounds() -> None:
    for size in (MIN_AUDIT_PRUNE_BATCH_SIZE, 500, MAX_AUDIT_PRUNE_BATCH_SIZE):
        assert normalize_prune_batch_size(size) == size
    for size in (MIN_AUDIT_PRUNE_BATCH_SIZE - 1, MAX_AUDIT_PRUNE_BATCH_SIZE + 1):
        with pytest.raises(ValueError, match="batch_size must be between 1 and 10000"):
            normalize_prune_batch_size(size)


def test_an_audit_export_cannot_start_before_the_beginning() -> None:
    with Session(create_engine("sqlite://")) as session:
        with pytest.raises(ValueError, match="after_id must not be negative"):
            export_audit_events(session, after_id=-1)


# --------------------------------------------------------------------------------------------
# Which databases can be backed up
# --------------------------------------------------------------------------------------------


def test_only_a_file_database_has_a_path_to_back_up() -> None:
    for memory in ("sqlite+pysqlite:///:memory:", "sqlite+pysqlite://"):
        with pytest.raises(BackupUnsupportedError, match="in-memory SQLite"):
            sqlite_database_path(memory)
    with pytest.raises(BackupUnsupportedError, match="SQLite only"):
        sqlite_database_path("postgresql+psycopg://portal@localhost/portal")


# --------------------------------------------------------------------------------------------
# Backup: what is refused, and what is left alone
# --------------------------------------------------------------------------------------------


def test_a_backup_of_a_database_that_is_missing_or_not_a_plain_file_is_refused(tmp_path) -> None:
    destination = tmp_path / "backup.db"
    with pytest.raises(BackupUnavailableError, match="database does not exist"):
        backup_sqlite_database(url(tmp_path / "missing.db"), destination)
    directory = tmp_path / "a-directory.db"
    directory.mkdir()
    with pytest.raises(BackupUnavailableError, match="database must be a regular file"):
        backup_sqlite_database(url(directory), destination)
    real = tmp_path / "real.db"
    make_database(real)
    link = tmp_path / "link.db"
    link.symlink_to(real)
    with pytest.raises(BackupUnavailableError, match="database must be a regular file"):
        backup_sqlite_database(url(link), destination)
    assert not destination.exists()


def test_a_backup_never_goes_onto_a_directory_or_over_a_file_without_overwrite(tmp_path) -> None:
    source = tmp_path / "live.db"
    make_database(source, "live")
    directory = tmp_path / "taken"
    directory.mkdir()
    with pytest.raises(BackupUnavailableError, match="destination must be a regular file"):
        backup_sqlite_database(url(source), directory)
    existing = tmp_path / "old.db"
    make_database(existing, "old")
    with pytest.raises(BackupDestinationExistsError, match="already exists"):
        backup_sqlite_database(url(source), existing)
    assert read_value(existing) == "old"
    # With overwrite it is replaced, by a copy that reads the same as the live database.
    backup_sqlite_database(url(source), existing, overwrite=True)
    assert read_value(existing) == "live"
    # A destination of the live file itself is refused before anything is read.
    with pytest.raises(BackupDestinationExistsError, match="must differ"):
        backup_sqlite_database(url(source), source, overwrite=True)


class Damaged:
    def __init__(self, real):
        self.real = real

    def execute(self, statement, *args):
        if statement == "PRAGMA integrity_check":
            return type("Result", (), {"fetchone": staticmethod(lambda: ("row 3 broken",))})
        return self.real.execute(statement, *args)

    def __getattr__(self, name):
        return getattr(self.real, name)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self.real.__exit__(*args)


def test_a_database_that_fails_its_integrity_check_is_not_backed_up(tmp_path, monkeypatch) -> None:
    source = tmp_path / "live.db"
    make_database(source)
    destination = tmp_path / "backup.db"
    make_database(destination, "kept")

    real_connect = sqlite3.connect
    monkeypatch.setattr(
        maintenance.sqlite3, "connect", lambda *a, **k: Damaged(real_connect(*a, **k))
    )
    with pytest.raises(BackupUnavailableError, match="SQLite database failed integrity check"):
        backup_sqlite_database(url(source), destination, overwrite=True)
    monkeypatch.setattr(maintenance.sqlite3, "connect", real_connect)
    assert read_value(destination) == "kept"
    assert [path.name for path in tmp_path.iterdir() if path.name.endswith(".tmp")] == []


def test_a_copy_that_fails_integrity_or_cannot_be_written_leaves_the_destination_and_no_temp_file(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "live.db"
    make_database(source, "live")
    destination = tmp_path / "backup.db"
    make_database(destination, "kept")

    def temp_files():
        return [path.name for path in tmp_path.iterdir() if path.name.endswith(".tmp")]

    # The operating system refuses the final rename.
    def refuse(*args, **kwargs):
        raise OSError("FAKE disk full")

    monkeypatch.setattr(maintenance.os, "replace", refuse)
    with pytest.raises(BackupUnavailableError, match="SQLite database copy failed"):
        backup_sqlite_database(url(source), destination, overwrite=True)
    monkeypatch.undo()
    assert read_value(destination) == "kept" and temp_files() == []
    # The permission change on the temporary file fails before it is closed: still no leak.
    descriptors = []
    real_close = os.close
    monkeypatch.setattr(maintenance.os, "fchmod", refuse)
    monkeypatch.setattr(
        maintenance.os, "close", lambda fd: (descriptors.append(fd), real_close(fd))[1]
    )
    with pytest.raises(BackupUnavailableError, match="SQLite database copy failed"):
        backup_sqlite_database(url(source), destination, overwrite=True)
    monkeypatch.undo()
    assert len(descriptors) == 1  # the temporary file's descriptor was closed once
    assert read_value(destination) == "kept" and temp_files() == []


def test_a_backup_whose_directory_cannot_be_synced_is_still_reported_as_made(
    tmp_path, monkeypatch, caplog
) -> None:
    source = tmp_path / "live.db"
    make_database(source, "live")
    destination = tmp_path / "out" / "backup.db"

    def unsupported(path):
        raise OSError("FAKE: directory fsync not supported")

    monkeypatch.setattr(maintenance, "fsync_directory", unsupported)
    caplog.set_level(logging.DEBUG, logger="carlos_patient_portal.maintenance")
    assert backup_sqlite_database(url(source), destination) == destination
    assert read_value(destination) == "live"
    assert "directory fsync unavailable: OSError" in caplog.text


# --------------------------------------------------------------------------------------------
# Restore
# --------------------------------------------------------------------------------------------


def test_a_restore_refuses_a_missing_source_and_a_destination_that_is_not_a_plain_file(
    tmp_path,
) -> None:
    live = tmp_path / "live.db"
    make_database(live, "live")
    with pytest.raises(BackupUnavailableError, match="backup source does not exist"):
        restore_sqlite_database(url(live), tmp_path / "missing.db", overwrite=True)
    backup = tmp_path / "backup.db"
    make_database(backup, "backup")
    directory = tmp_path / "dir.db"
    directory.mkdir()
    with pytest.raises(BackupUnavailableError, match="restore destination must be a regular file"):
        restore_sqlite_database(url(directory), backup, overwrite=True)
    link = tmp_path / "link.db"
    link.symlink_to(live)
    with pytest.raises(BackupUnavailableError, match="restore destination must not be a symlink"):
        restore_sqlite_database(url(link), backup, overwrite=True)
    with pytest.raises(BackupUnavailableError, match="backup source must be a regular file"):
        restore_sqlite_database(url(live), directory, overwrite=True)
    assert read_value(live) == "live"
    # Without overwrite a live database is never replaced; with it, it is.
    with pytest.raises(BackupDestinationExistsError, match="restore destination already exists"):
        restore_sqlite_database(url(live), backup)
    assert read_value(live) == "live"
    restore_sqlite_database(url(live), backup, overwrite=True)
    assert read_value(live) == "backup"


class DamagedCopy(sqlite3.Connection):
    """A real connection (the backup API needs one) whose integrity check reports damage."""

    def execute(self, statement, *args):
        if statement == "PRAGMA integrity_check":
            return super().execute("SELECT 'row 3 broken'")
        return super().execute(statement, *args)


def test_a_copy_that_fails_its_own_integrity_check_is_never_installed(
    tmp_path, monkeypatch
) -> None:
    source = tmp_path / "live.db"
    make_database(source, "live")
    destination = tmp_path / "backup.db"
    make_database(destination, "kept")
    real_connect = sqlite3.connect

    def connect(*args, **kwargs):
        # Only the connection that writes the copy (not the read-only ones) reports damage.
        return (
            real_connect(*args, **kwargs)
            if kwargs.get("uri")
            else real_connect(*args, factory=DamagedCopy, **kwargs)
        )

    monkeypatch.setattr(maintenance.sqlite3, "connect", connect)
    with pytest.raises(BackupUnavailableError, match="copied SQLite database failed integrity"):
        backup_sqlite_database(url(source), destination, overwrite=True)
    monkeypatch.undo()
    assert read_value(destination) == "kept"
    assert [path.name for path in tmp_path.iterdir() if path.name.endswith(".tmp")] == []
