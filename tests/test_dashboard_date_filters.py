"""A selected clinic-local calendar day can contain 23, 24, or 25 hours of UTC records."""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal.models import UNLOCK_SECRET_TYPE_EMAIL
from carlos_patient_portal.unlock_secrets import create_unlock_secret
from tests.support import (
    UNLOCK_SECRET_ENCRYPTION_SECRET,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    browser_sign_in_seeded_patient,
    migrated_development_app,
)


@pytest.mark.parametrize(
    ("clinic_timezone", "selected_date", "start_utc", "end_utc"),
    [
        (
            "America/Toronto",
            "2026-03-08",
            datetime(2026, 3, 8, 5, tzinfo=UTC),
            datetime(2026, 3, 9, 4, tzinfo=UTC),
        ),
        (
            "America/Toronto",
            "2026-11-01",
            datetime(2026, 11, 1, 4, tzinfo=UTC),
            datetime(2026, 11, 2, 5, tzinfo=UTC),
        ),
        (
            "Pacific/Auckland",
            "2026-01-01",
            datetime(2025, 12, 31, 11, tzinfo=UTC),
            datetime(2026, 1, 1, 11, tzinfo=UTC),
        ),
    ],
)
def test_dashboard_day_filter_includes_local_midnight_and_excludes_the_next_midnight(
    clinic_timezone, selected_date, start_utc, end_utc
):
    app = migrated_development_app(
        clinic_timezone=clinic_timezone,
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
    )
    client = TestClient(app)
    try:
        account_id = browser_sign_in_seeded_patient(app, client)
        records = [
            ("FAKE excluded before day", start_utc - timedelta(microseconds=1)),
            ("FAKE included at start", start_utc),
            ("FAKE included at end", end_utc - timedelta(microseconds=1)),
            ("FAKE excluded next day", end_utc),
        ]
        with app.state.session_factory() as session, session.begin():
            for label, created_at in records:
                created = create_unlock_secret(
                    session,
                    clinic_id="default",
                    demographic_no=1234,
                    account_id=account_id,
                    secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                    secret="FAKE date filter test value",
                    created_by="FAKE test clinic",
                    encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                    label=label,
                )
                created.unlock_secret.created_at = created_at
                created.unlock_secret.updated_at = created_at

        unfiltered = client.get("/portal/email-passwords")
        filtered = client.get(
            "/portal/email-passwords",
            params={"date_from": selected_date, "date_to": selected_date},
        )

        assert unfiltered.status_code == 200
        assert all(label in unfiltered.text for label, _ in records)
        assert filtered.status_code == 200
        assert "FAKE included at start" in filtered.text
        assert "FAKE included at end" in filtered.text
        assert "FAKE excluded before day" not in filtered.text
        assert "FAKE excluded next day" not in filtered.text
    finally:
        client.close()
        app.state.database_engine.dispose()
