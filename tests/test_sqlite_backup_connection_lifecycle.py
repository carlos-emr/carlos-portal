import gc
import sqlite3
from contextlib import closing

from carlos_patient_portal.maintenance import backup_sqlite_database, restore_sqlite_database


def test_backup_closes_its_readers_before_the_last_writer_stops_and_restore_starts(tmp_path):
    control = tmp_path / "control.db"
    source = tmp_path / "source.db"
    backup = tmp_path / "backup.db"
    gc_was_enabled = gc.isenabled()
    writer = None
    try:
        # Connection ownership must not depend on the next cyclic-GC pass. Both the
        # positive control and real backup path run under the same collection state.
        gc.disable()
        for path in (control, source):
            writer = sqlite3.connect(path, isolation_level=None)
            assert writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
            writer.execute("CREATE TABLE sample (value TEXT)")
            writer.execute("INSERT INTO sample VALUES ('FAKE owned row')")
            assert (tmp_path / (path.name + "-wal")).exists()
            if path == source:
                assert backup_sqlite_database(f"sqlite+pysqlite:///{source}", backup) == backup
            writer.close()
            writer = None

        # Without a helper reader left open, the last writer's normal close removes
        # WAL sidecars. No manual checkpoint, unlink, retry, or GC is required.
        assert not (tmp_path / "control.db-wal").exists()
        assert not (tmp_path / "control.db-shm").exists()
        assert (
            restore_sqlite_database(f"sqlite+pysqlite:///{source}", backup, overwrite=True)
            == source
        )
        with closing(sqlite3.connect(source)) as restored:
            assert restored.execute("SELECT value FROM sample").fetchall() == [("FAKE owned row",)]
    finally:
        if writer is not None:
            writer.close()
        if gc_was_enabled:
            gc.enable()
        gc.collect()
