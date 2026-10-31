from datetime import timedelta

import pytest
from sqlalchemy import select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal import cli
from carlos_patient_portal.config import Settings
from carlos_patient_portal.database import create_portal_engine
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalMfaChallenge,
    PatientPortalSession,
    utc_now,
)
from tests.support import upgrade_to_head


def test_cleanup_cli_rolls_back_earlier_deletion_after_later_pass_refusal_and_retries(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    database_url = f"sqlite+pysqlite:///{tmp_path / 'cleanup-rollback.db'}"
    monkeypatch.setattr(
        cli, "get_settings", lambda: Settings(environment="development", database_url=database_url)
    )
    engine = create_portal_engine(database_url)
    tables = [
        model.__table__
        for model in (PatientPortalAccount, PatientPortalSession, PatientPortalMfaChallenge)
    ]

    def snapshot():
        with engine.connect() as connection:
            return {
                table.name: [
                    dict(row)
                    for row in connection.execute(select(table).order_by(table.c.id)).mappings()
                ]
                for table in tables
            }

    try:
        upgrade_to_head(engine)
        now = utc_now()
        old_created = now - timedelta(days=60)
        old_expiry = now - timedelta(days=50)
        with Session(engine) as session, session.begin():
            account = PatientPortalAccount(
                clinic_id="FAKE-clinic",
                demographic_no=1234,
                username="fake.cleanup",
                email="fake.cleanup@example.test",
                password_hash="FAKE-unused-password-hash",
                status="active",
            )
            session.add(account)
            session.flush()
            session.add_all(
                [
                    PatientPortalSession(
                        id=session_id,
                        account_id=account.id,
                        token_hash=str(session_id) * 64,
                        created_at=old_created if session_id == 1 else now,
                        expires_at=old_expiry if session_id == 1 else now + timedelta(days=1),
                    )
                    for session_id in (1, 2)
                ]
            )
            session.add(
                PatientPortalMfaChallenge(
                    account_id=account.id,
                    challenge_token_hash="3" * 64,
                    code_hash="4" * 64,
                    delivery_method="email",
                    status="pending",
                    created_at=old_created,
                    expires_at=old_expiry,
                )
            )
        before = snapshot()
        with engine.begin() as connection:
            # This fault fires only after the earlier session pass really deleted row 1.
            connection.execute(
                text("""
                CREATE TRIGGER fake_cleanup_refusal
                BEFORE DELETE ON patient_portal_mfa_challenges
                WHEN NOT EXISTS (SELECT 1 FROM patient_portal_sessions WHERE id = 1)
                BEGIN
                    SELECT RAISE(ABORT, 'FAKE late cleanup refusal after session deletion');
                END
            """)
            )
        capsys.readouterr()

        with pytest.raises(
            IntegrityError, match="FAKE late cleanup refusal after session deletion"
        ):
            cli.maintenance(["cleanup-transient-auth", "--batch-size", "1"])

        assert "cleanup completed" not in capsys.readouterr().out
        assert snapshot() == before
        with engine.begin() as connection:
            connection.execute(text("DROP TRIGGER fake_cleanup_refusal"))

        cli.maintenance(["cleanup-transient-auth", "--batch-size", "1"])

        output = capsys.readouterr().out
        assert "cleanup completed" in output
        assert "sessions=1" in output
        assert "mfa_challenges=1" in output
        assert "total=2" in output
        after = snapshot()
        assert after[tables[0].name] == before[tables[0].name]
        assert after[tables[1].name] == [before[tables[1].name][1]]
        assert after[tables[2].name] == []
    finally:
        engine.dispose()
