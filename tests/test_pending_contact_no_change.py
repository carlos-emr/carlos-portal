"""Saving the displayed current contacts does not strand an emailed pending proof."""

from html.parser import HTMLParser
from urllib.parse import urlsplit

from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.models import (
    EMAIL_CHANGE_STATUS_CONFIRMED,
    EMAIL_CHANGE_STATUS_PENDING,
    PatientPortalAccount,
    PatientPortalContactReviewRequest,
    PatientPortalEmailChangeRequest,
    PatientPortalSession,
)
from carlos_patient_portal.web_support import PORTAL_SESSION_COOKIE_NAME
from tests.support import (
    SEEDED_INVITE_EMAIL,
    STRONG_PASSWORD,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    browser_sign_in_seeded_patient,
    confirm_seeded_email_change,
    migrated_development_app,
    request_seeded_email_change,
)


class ContactForm(HTMLParser):
    def __init__(self):
        super().__init__()
        self.active = False
        self.action = None
        self.values = {}

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag == "form":
            self.active = urlsplit(attributes.get("action", "")).path == "/portal/account/contact"
            if self.active:
                self.action = attributes["action"]
        if tag == "input" and self.active and "name" in attributes:
            self.values[attributes["name"]] = attributes.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self.active = False


def test_saving_displayed_current_contacts_preserves_the_original_pending_email_link(tmp_path):
    email_sender, sms_sender = RecordingPortalEmailSender(), RecordingPortalSmsSender()
    app = migrated_development_app(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'private-pending-contact.sqlite'}",
        email_sender=email_sender,
        sms_sender=sms_sender,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    patient = TestClient(app)
    proposed_email = "fake-pending-contact@example.test"
    try:
        account_id = browser_sign_in_seeded_patient(app, patient)
        original_token = request_seeded_email_change(
            app, patient, email_sender, email=proposed_email
        )
        original_cookie = patient.cookies.get(PORTAL_SESSION_COOKIE_NAME)
        assert original_cookie
        provider_counts = (len(email_sender.messages), len(sms_sender.messages))
        with app.state.session_factory() as session:
            pending = session.scalars(select(PatientPortalEmailChangeRequest)).one()
            original_proof_identity = (pending.id, pending.token_hash)
            authorizing_session_id = session.scalars(select(PatientPortalSession.id)).one()

        account_page = patient.get("/portal/account")
        assert account_page.status_code == 200
        form = ContactForm()
        form.feed(account_page.text)
        assert form.action is not None
        assert urlsplit(form.action).path == "/portal/account/contact"
        assert form.values["email"] == SEEDED_INVITE_EMAIL
        assert form.values["phone_number"] == ""
        assert form.values["csrf_token"]
        saved = patient.post(
            form.action,
            data={**form.values, "current_password": STRONG_PASSWORD},
            follow_redirects=False,
        )
        assert saved.status_code == 303
        assert saved.headers["location"] == "/portal/account?status=no-change"
        notice_page = patient.get(saved.headers["location"])
        assert notice_page.status_code == 200
        assert "No account changes." in notice_page.text
        assert patient.cookies.get(PORTAL_SESSION_COOKIE_NAME) == original_cookie
        assert (len(email_sender.messages), len(sms_sender.messages)) == provider_counts
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            pending = session.scalars(select(PatientPortalEmailChangeRequest)).one()
            assert (account.email, account.phone_number) == (SEEDED_INVITE_EMAIL, None)
            assert (pending.id, pending.token_hash) == original_proof_identity
            assert pending.new_email == proposed_email
            assert pending.status == EMAIL_CHANGE_STATUS_PENDING
            assert pending.confirmed_at is None
            assert session.scalar(select(PatientPortalContactReviewRequest)) is None
            assert session.get(PatientPortalSession, authorizing_session_id).revoked_at is None

        # Use the originally delivered link, not a new proof or a service-level shortcut.
        completed = confirm_seeded_email_change(patient, original_token)
        assert completed.status_code == 200
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            proof = session.scalars(select(PatientPortalEmailChangeRequest)).one()
            assert account.email == proposed_email
            assert (proof.id, proof.token_hash) == original_proof_identity
            assert proof.status == EMAIL_CHANGE_STATUS_CONFIRMED
    finally:
        patient.close()
        app.state.database_engine.dispose()
