import json
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal import cli
from carlos_patient_portal.audit import record_audit_event
from carlos_patient_portal.database import create_portal_engine
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalSession,
    PatientPortalUnlockSecret,
    utc_now,
)
from carlos_patient_portal.unlock_secrets import create_unlock_secret, decrypt_unlock_secret_payload
from tests.support import development_settings, upgrade_to_head


@pytest.mark.parametrize(
    "command", ["cleanup-transient-auth", "rotate-unlock-secrets", "prune-audit"]
)
def test_maintenance_write_success_is_not_printed_when_actual_database_commit_fails(
    command, tmp_path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'commit-output.db'}"
    old_key, active_key = "o" * 32, "a" * 32
    settings = development_settings(
        database_url=database_url,
        unlock_secret_active_key_id="active",
        unlock_secret_encryption_keyring=json.dumps({"retired": old_key, "active": active_key}),
    )
    engine = create_portal_engine(database_url)
    target_model = {
        "cleanup-transient-auth": PatientPortalSession,
        "rotate-unlock-secrets": PatientPortalUnlockSecret,
        "prune-audit": PatientPortalAuditEvent,
    }[command]
    table = target_model.__table__
    pending_changes = []

    def rows(connection):
        return [
            dict(row) for row in connection.execute(select(table).order_by(table.c.id)).mappings()
        ]

    def observe_pending_commit(session, flush_context=None):
        if session.get_bind().url.database != engine.url.database:
            return
        connection = session.connection()
        if connection.scalar(text("SELECT COUNT(*) FROM fake_commit_child")):
            pending_changes.append(rows(connection))

    try:
        upgrade_to_head(engine)
        with Session(engine) as session, session.begin():
            if command == "cleanup-transient-auth":
                account = PatientPortalAccount(
                    clinic_id="FAKE-clinic",
                    demographic_no=1234,
                    username="fake.commit",
                    email="fake.commit@example.test",
                    password_hash="FAKE-unused-password-hash",
                    status="active",
                )
                session.add(account)
                session.flush()
                session.add(
                    PatientPortalSession(
                        account_id=account.id,
                        token_hash="1" * 64,
                        created_at=utc_now() - timedelta(days=60),
                        expires_at=utc_now() - timedelta(days=50),
                    )
                )
            elif command == "rotate-unlock-secrets":
                create_unlock_secret(
                    session,
                    clinic_id="FAKE-clinic",
                    demographic_no=1234,
                    created_by="FAKE provider",
                    encryption_secret=old_key,
                    encryption_key_id="retired",
                    secret="FAKE document passphrase",
                    source_reference="FAKE-commit-output",
                )
            else:
                audit = record_audit_event(
                    session, event_type="login", outcome="success", actor_type="system"
                )
                audit.created_at = datetime(2000, 1, 1, tzinfo=UTC)

        with engine.begin() as connection:
            before = rows(connection)
            assert before
            connection.execute(text("CREATE TABLE fake_commit_parent (id INTEGER PRIMARY KEY)"))
            connection.execute(
                text("""
                CREATE TABLE fake_commit_child (
                    id INTEGER PRIMARY KEY,
                    parent_id INTEGER NOT NULL REFERENCES fake_commit_parent(id)
                        DEFERRABLE INITIALLY DEFERRED
                )
            """)
            )
            operation = "UPDATE" if command == "rotate-unlock-secrets" else "DELETE"
            # Both identifiers come only from the closed command/model map in this fixture.
            connection.execute(
                text(f"""
                CREATE TRIGGER fake_commit_refusal AFTER {operation} ON {table.name}
                BEGIN
                    INSERT INTO fake_commit_child (parent_id) VALUES (999);
                END
            """)  # noqa: S608
            )

        if command == "prune-audit":
            # CLI role/target declarations need distinct usernames. Route only these declared
            # URLs to this real SQLite fixture; no PostgreSQL identity/role/TLS claim is made.
            settings = development_settings(
                database_url="postgresql+psycopg://fake_runtime@localhost/fake_commit",
                maintenance_database_url="postgresql+psycopg://fake_maintenance@localhost/fake_commit",
            )
            real_create_engine = cli.create_portal_engine

            def private_engine(declared_url, **kwargs):
                assert declared_url in (settings.database_url, settings.maintenance_database_url)
                return real_create_engine(database_url, **kwargs)

            monkeypatch.setattr(cli, "create_portal_engine", private_engine)
        monkeypatch.setattr(cli, "get_settings", lambda: settings)
        capsys.readouterr()
        event.listen(Session, "before_commit", observe_pending_commit)
        event.listen(Session, "after_flush_postexec", observe_pending_commit)
        try:
            with pytest.raises(IntegrityError, match="FOREIGN KEY constraint failed"):
                cli.maintenance([command, "--batch-size", "1"])
        finally:
            event.remove(Session, "before_commit", observe_pending_commit)
            event.remove(Session, "after_flush_postexec", observe_pending_commit)
        failed_output = capsys.readouterr()

        assert pending_changes
        if command == "rotate-unlock-secrets":
            assert pending_changes[-1][0]["encryption_key_id"] == "active"
            assert pending_changes[-1][0]["encrypted_secret"] != before[0]["encrypted_secret"]
        else:
            assert pending_changes[-1] == []
        with engine.begin() as connection:
            assert rows(connection) == before
            assert connection.scalar(text("SELECT COUNT(*) FROM fake_commit_child")) == 0
            connection.execute(text("DROP TRIGGER fake_commit_refusal"))

        cli.maintenance([command, "--batch-size", "1"])
        retry_output = capsys.readouterr()
        with engine.connect() as connection:
            after = rows(connection)
        if command == "rotate-unlock-secrets":
            assert after[0]["encryption_key_id"] == "active"
            with Session(engine) as session:
                record = session.get(PatientPortalUnlockSecret, before[0]["id"])
                assert (
                    decrypt_unlock_secret_payload(record, encryption_keys={"active": active_key})
                    == "FAKE document passphrase"
                )
            assert retry_output.out.strip() == "rotated 1 unlock secrets"
        elif command == "cleanup-transient-auth":
            assert after == []
            assert "cleanup completed: sessions=1" in retry_output.out
        else:
            assert after == []
            assert retry_output.out.strip() == "deleted 1 audit events older than retention"
        # A reported write success must reflect a durable commit, not rolled-back SQL work.
        assert failed_output.out == ""
    finally:
        engine.dispose()
