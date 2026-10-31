import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    migrated_development_app,
)


@pytest.mark.parametrize("stamp_shape", ["replacement", "extra"])
def test_readiness_rejects_unrecognized_schema_heads_and_recovers_without_restart(
    stamp_shape,
) -> None:
    health_token = "FAKE-readiness-health-token-00000001"
    app = migrated_development_app(
        database_url="sqlite+pysqlite:///:memory:",
        internal_health_token=health_token,
        maintenance_mode=False,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
    )
    engine = app.state.database_engine
    headers = {"Authorization": f"Bearer {health_token}"}
    read_heads = text("SELECT version_num FROM alembic_version")
    insert_head = text("INSERT INTO alembic_version (version_num) VALUES (:head)")
    unexpected = "FAKE-unknown-schema-head"
    with TestClient(app) as client:
        healthy = client.get("/internal/readiness", headers=headers)
        assert healthy.status_code == 200
        assert healthy.json()["schema"] == "ok"
        with engine.begin() as connection:
            original_heads = list(connection.scalars(read_heads))
            assert original_heads
            assert unexpected not in original_heads
            if stamp_shape == "replacement":
                connection.execute(text("DELETE FROM alembic_version"))
            connection.execute(insert_head, {"head": unexpected})
            broken_heads = set(connection.scalars(read_heads))

        try:
            unavailable = client.get("/internal/readiness", headers=headers)
            assert unavailable.status_code == 503
            assert unavailable.json() == {
                "status": "unavailable",
                "database": "ok",
                "schema": "mismatch",
                "maintenance": False,
            }
            assert client.get("/health").status_code == 200
            assert client.get("/internal/health/db", headers=headers).status_code == 200
            with engine.connect() as connection:
                assert set(connection.scalars(read_heads)) == broken_heads
        finally:
            # Restore only this private fixture's stamps; probes must never repair them.
            with engine.begin() as connection:
                connection.execute(text("DELETE FROM alembic_version"))
                connection.execute(insert_head, [{"head": head} for head in original_heads])

        recovered = client.get("/internal/readiness", headers=headers)
        assert recovered.status_code == 200
        assert recovered.json()["schema"] == "ok"
        assert recovered.json()["database"] == "ok"
