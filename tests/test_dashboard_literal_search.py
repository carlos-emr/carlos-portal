import re

from fastapi.testclient import TestClient

from carlos_patient_portal.unlock_secrets import create_unlock_secret
from tests.support import (
    UNLOCK_SECRET_ENCRYPTION_SECRET,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    browser_sign_in_seeded_patient,
    migrated_development_app,
)


def test_dashboard_search_treats_sql_pattern_characters_as_literal_text() -> None:
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    labels = (
        r"FAKE lab\100%_report",
        r"FAKE lab\100X_report",  # A percent wildcard would also match this row.
        r"FAKE lab\100%Xreport",  # An underscore wildcard would also match this row.
        "FAKE lab100%_report",  # An unescaped backslash would consume the literal separator.
    )
    with TestClient(app) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        record_ids = []
        with app.state.session_factory() as session, session.begin():
            for index, label in enumerate(labels):
                created = create_unlock_secret(
                    session,
                    clinic_id="default",
                    demographic_no=1234,
                    account_id=account_id,
                    created_by="FAKE Test Clinic",
                    encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                    secret=f"FAKE hidden search passphrase {index}",
                    label=label,
                )
                record_ids.append(created.unlock_secret.id)

        # The decoys really are accessible rows; reflected search input cannot satisfy
        # this oracle, which reads actual disclosure controls from the returned table.
        unfiltered = client.get("/portal/email-passwords")
        assert unfiltered.status_code == 200
        row_pattern = r'data-reveal-url="/portal/email-passwords/(\d+)/reveal"'
        assert {int(value) for value in re.findall(row_pattern, unfiltered.text)} == set(record_ids)

        filtered = client.get("/portal/email-passwords", params={"q": r"lab\100%_"})

        assert filtered.status_code == 200
        assert [int(value) for value in re.findall(row_pattern, filtered.text)] == [record_ids[0]]
        assert "FAKE hidden search passphrase" not in unfiltered.text
        assert "FAKE hidden search passphrase" not in filtered.text
