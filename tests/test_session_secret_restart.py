from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import select

from carlos_patient_portal.main import create_app
from carlos_patient_portal.models import PatientPortalAccount, PatientPortalSession
from tests.support import (
    activate_seeded_patient_account,
    bearer_headers,
    expire_email_mfa_cooldown,
    migrated_development_app,
    sign_in_patient_api_session,
)


def test_session_survives_same_secret_restart_but_not_secret_rotation(tmp_path) -> None:
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'private-restart.sqlite'}",
        session_secret="FAKE-old-session-secret-000000001",
    )
    settings = app.state.settings
    with TestClient(app) as client:
        account_id = activate_seeded_patient_account(app, client)
        original_token = sign_in_patient_api_session(client)
        original = client.get("/auth/session", headers=bearer_headers(original_token))
        assert original.status_code == 200
        expected_identity = original.json()
        assert expected_identity["username"] == "patient.user"
        with app.state.session_factory() as session:
            password_hash = session.get(PatientPortalAccount, account_id).password_hash
            original_session = session.scalar(select(PatientPortalSession))
            original_session_id = original_session.id
            original_token_hash = original_session.token_hash
            original_expiry = original_session.expires_at

    # Fresh runtimes reconnect to the migrated file; no session is seeded for either restart.
    restarted = create_app(settings)
    with TestClient(restarted) as client:
        accepted = client.get("/auth/session", headers=bearer_headers(original_token))
        assert accepted.status_code == 200
        assert accepted.json() == expected_identity

    rotated_settings = settings.model_copy(
        update={"session_secret": SecretStr("FAKE-new-session-secret-000000002")}
    )
    rotated = create_app(rotated_settings)
    with TestClient(rotated) as client:
        refused = client.get("/auth/session", headers=bearer_headers(original_token))
        assert refused.status_code == 401
        assert expected_identity["username"] not in refused.text
        assert original_token not in refused.text
        # Rotation makes the old token unfindable; it must not rewrite the account or old row.
        with rotated.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            old_session = session.get(PatientPortalSession, original_session_id)
            assert account.password_hash == password_hash
            assert account.locked_at is None
            assert account.force_password_reset is False
            assert old_session.token_hash == original_token_hash
            assert old_session.expires_at == original_expiry
            assert old_session.revoked_at is None
            assert old_session.revoked_reason is None

        # Fixture-only cooldown advancement lets a fresh real password/MFA sign-in run now.
        expire_email_mfa_cooldown(rotated)
        fresh_token = sign_in_patient_api_session(client)
        assert fresh_token != original_token
        fresh_session = client.get("/auth/session", headers=bearer_headers(fresh_token))
        assert fresh_session.status_code == 200
        assert fresh_session.json() == expected_identity
        assert (
            client.get("/auth/session", headers=bearer_headers(original_token)).status_code == 401
        )
