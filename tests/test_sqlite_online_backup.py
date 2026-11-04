import shutil
import sqlite3
from contextlib import closing

from carlos_patient_portal.maintenance import backup_sqlite_database


def test_online_backup_includes_committed_wal_without_copying_pending_writer_data(tmp_path) -> None:
    source = tmp_path / "private-live.db"
    main_only = tmp_path / "main-file-only.db"
    backup = tmp_path / "standalone-backup.db"
    writer = sqlite3.connect(source, isolation_level=None)
    try:
        assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        writer.execute("PRAGMA wal_autocheckpoint=0")
        writer.execute("CREATE TABLE sample (value TEXT PRIMARY KEY)")
        assert writer.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
        writer.execute("INSERT INTO sample (value) VALUES (?)", ("FAKE committed",))
        assert writer.execute("SELECT value FROM sample").fetchall() == [("FAKE committed",)]
        assert (tmp_path / "private-live.db-wal").stat().st_size > 0

        # Prove a main-file-only copy misses this committed WAL row. Immutable mode reads
        # just the owned snapshot file, without borrowing journal/shm files from the writer.
        shutil.copyfile(source, main_only)
        with closing(sqlite3.connect(main_only.as_uri() + "?immutable=1", uri=True)) as snapshot:
            assert snapshot.execute("SELECT value FROM sample").fetchall() == []

        writer.execute("BEGIN IMMEDIATE")
        writer.execute("INSERT INTO sample (value) VALUES (?)", ("FAKE pending",))
        assert writer.in_transaction
        assert set(writer.execute("SELECT value FROM sample").fetchall()) == {
            ("FAKE committed",),
            ("FAKE pending",),
        }

        result = backup_sqlite_database(f"sqlite+pysqlite:///{source}", backup)

        assert result == backup
        with closing(sqlite3.connect(backup.as_uri() + "?immutable=1", uri=True)) as restored:
            assert restored.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
            assert restored.execute("SELECT value FROM sample").fetchall() == [("FAKE committed",)]
        # Taking a backup must not commit or roll back the caller's open source transaction.
        assert writer.in_transaction
        assert set(writer.execute("SELECT value FROM sample").fetchall()) == {
            ("FAKE committed",),
            ("FAKE pending",),
        }
        writer.rollback()
        assert writer.execute("SELECT value FROM sample").fetchall() == [("FAKE committed",)]
    finally:
        writer.rollback()
        writer.close()
