from concurrent.futures import ThreadPoolExecutor
from threading import Event
from urllib.parse import parse_qs, urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.account_settings import ACCOUNT_SETTINGS_REASON_DELIVERY_UNAVAILABLE
from carlos_patient_portal.email_delivery import PortalEmailDeliveryError
from carlos_patient_portal.models import (
    AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_REQUEST,
    AUDIT_OUTCOME_FAILURE,
    EMAIL_CHANGE_STATUS_CONFIRMED,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalContactReviewRequest,
    PatientPortalEmailChangeRequest,
)
from tests.support import (
    STRONG_PASSWORD,
    RecordingPortalEmailSender,
    browser_sign_in_seeded_patient,
    confirm_seeded_email_change,
    csrf_token_from_response,
    migrated_development_app,
)


def test_late_delivery_failure_cannot_revoke_an_already_confirmed_contact_change(tmp_path) -> None:
    sent = Event()
    finish_delivery = Event()

    class HeldConfirmationSender(RecordingPortalEmailSender):
        def send_email_change_confirmation(self, **kwargs):
            super().send_email_change_confirmation(**kwargs)
            sent.set()
            assert finish_delivery.wait(10), "the test did not release its fake sender"
            raise PortalEmailDeliveryError(
                "FAKE late provider refusal after recipient received link"
            )

    sender = HeldConfirmationSender()
    app = migrated_development_app(
        email_sender=sender,
        database_url=f"sqlite+pysqlite:///{tmp_path / 'private-contact-race.sqlite'}",
    )
    with TestClient(app, raise_server_exceptions=False) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        csrf_token = csrf_token_from_response(client.get("/portal/account"))
        new_email = "FAKE-confirmed@example.test"
        with ThreadPoolExecutor(max_workers=1) as pool:
            waiting = pool.submit(
                client.post,
                "/portal/account/contact",
                data={
                    "csrf_token": csrf_token,
                    "current_password": STRONG_PASSWORD,
                    "email": new_email,
                    "phone_number": "",
                },
                follow_redirects=False,
            )
            try:
                assert sent.wait(10), "the fake confirmation sender was not called"
                message = next(
                    item
                    for item in sender.messages
                    if item.get("type") == "email_change_confirmation"
                )
                token = parse_qs(urlsplit(message["confirmation_url"]).fragment)["token"][0]
                # A separate browser can use the delivered link before the sender acknowledges it.
                with TestClient(app, raise_server_exceptions=False) as recipient:
                    confirmed = confirm_seeded_email_change(recipient, token)
                    assert confirmed.status_code == 200
                with app.state.session_factory() as session:
                    request = session.scalar(select(PatientPortalEmailChangeRequest))
                    assert request.status == EMAIL_CHANGE_STATUS_CONFIRMED
                    assert request.confirmed_at is not None
            finally:
                finish_delivery.set()
                response = waiting.result(timeout=10)

        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            request = session.scalar(select(PatientPortalEmailChangeRequest))
            reviews = list(session.scalars(select(PatientPortalContactReviewRequest)))
            assert account.email == new_email.lower()
            assert request.status == EMAIL_CHANGE_STATUS_CONFIRMED
            assert request.confirmed_at is not None
            assert len(reviews) == 1
            failures = list(
                session.scalars(
                    select(PatientPortalAuditEvent).where(
                        PatientPortalAuditEvent.account_id == account_id,
                        PatientPortalAuditEvent.event_type
                        == AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_REQUEST,
                        PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_FAILURE,
                    )
                )
            )
            assert [event.reason for event in failures] == [
                ACCOUNT_SETTINGS_REASON_DELIVERY_UNAVAILABLE
            ]
        assert response.status_code == 303
