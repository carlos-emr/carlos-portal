# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""What the patient's myCarlos linking pages refuse, say, and leave untouched (FAKE data only)."""

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from carlos_patient_portal.auth import MfaDeliveryUnavailableError, MfaRateLimitedError
from carlos_patient_portal.email_delivery import PortalEmailDeliveryError
from carlos_patient_portal.i18n import MYCARLOS_TEXT_CATALOG
from carlos_patient_portal.models import (
    AUDIT_EVENT_MYCARLOS_LINK_CODE_CREATE,
    Base,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    PatientPortalSession,
)
from carlos_patient_portal.mycarlos_links import LinkingPausedError
from carlos_patient_portal.routes import mycarlos_portal
from carlos_patient_portal.sms_delivery import PortalSmsDeliveryError
from tests import test_mycarlos_portal as portal_tests
from tests.support import RecordingPortalEmailSender, get_csrf_token, migrated_development_app
from tests.test_mycarlos_portal import (
    code_count,
    form_token,
    make_portal,
    sign_in,
    stored_device,
)

CODE, STEP_UP = "/portal/mycarlos/code", "/portal/mycarlos/mfa"
KEY = "A" * 43


def say(key):
    """What the page says for `key`, in the language the tests run in."""
    return MYCARLOS_TEXT_CATALOG["en"][key]


def refusals(app):
    with app.state.session_factory() as session:
        return [
            row.reason
            for row in session.scalars(
                select(PatientPortalAuditEvent)
                .where(PatientPortalAuditEvent.event_type == AUDIT_EVENT_MYCARLOS_LINK_CODE_CREATE)
                .order_by(PatientPortalAuditEvent.id)
            )
        ]


def signed_in(**options):
    app, client, sms, _ = make_portal(**options)
    sign_in(client, sms)
    return app, client, sms


# ---- nobody signed in ----


@pytest.mark.parametrize(
    "path",
    ["/portal/mycarlos", f"/portal/account/mycarlos/devices/{KEY}/remove"],
    ids=["page", "confirm removal"],
)
def test_a_signed_out_visitor_is_sent_to_sign_in_from_the_linking_pages(path):
    app, client, sms, _ = make_portal()
    reply = client.get(path, follow_redirects=False)
    assert reply.status_code in (303, 307)
    assert reply.headers["location"] == "/"
    assert code_count(app) == 0 and not sms.messages


@pytest.mark.parametrize(
    "path",
    [CODE, STEP_UP, f"/portal/account/mycarlos/devices/{KEY}/remove"],
    ids=["code", "step-up", "remove"],
)
def test_a_post_with_no_session_is_refused_and_does_nothing(path):
    app, client, sms, _ = make_portal()
    reply = client.post(path, data={"csrf_token": get_csrf_token(client)}, follow_redirects=False)
    assert reply.status_code == 403
    assert code_count(app) == 0 and not sms.messages


@pytest.mark.parametrize(
    "path",
    [CODE, STEP_UP, f"/portal/account/mycarlos/devices/{KEY}/remove"],
    ids=["code", "step-up", "remove"],
)
def test_a_session_that_ends_between_the_form_and_the_action_goes_to_sign_in(path):
    app, client, sms = signed_in()
    csrf = form_token(client)
    with app.state.session_factory() as session, session.begin():
        session.execute(delete(PatientPortalSession))
    reply = client.post(path, data={"csrf_token": csrf}, follow_redirects=False)
    assert reply.status_code in (303, 307), reply.text[:200]
    assert reply.headers["location"] == "/"
    assert code_count(app) == 0


# ---- the code ----


def test_a_clinic_with_no_active_key_cannot_issue_a_code_and_says_so(app_options=None):
    app, client, sms = signed_in()
    with app.state.session_factory() as session, session.begin():
        session.execute(delete(PatientPortalClinicKey))
    refused = client.post(CODE, data={"csrf_token": form_token(client)})
    assert refused.status_code == 409
    assert say("mycarlos_unavailable") in refused.text
    assert code_count(app) == 0
    assert refusals(app) == ["clinic_keys_missing"]


def test_a_paused_linking_is_told_to_wait_and_is_written_down(monkeypatch):
    app, client, sms = signed_in()

    def paused(*args, **kwargs):
        raise LinkingPausedError()

    monkeypatch.setattr(mycarlos_portal, "create_link_code", paused)
    refused = client.post(CODE, data={"csrf_token": form_token(client)})
    assert refused.status_code == 429
    assert say("mycarlos_paused") in refused.text
    assert code_count(app) == 0
    assert refusals(app) == ["linking_paused"]


def test_a_session_whose_account_is_gone_is_refused_not_served(monkeypatch):
    app, client, sms = signed_in()
    csrf = form_token(client)
    commit, gone = Session.commit, []

    def commit_then_lose_the_account(self):
        commit(self)
        if not gone:
            gone.append(True)
            for table in reversed(Base.metadata.sorted_tables):
                self.execute(delete(table))
            commit(self)

    monkeypatch.setattr(Session, "commit", commit_then_lose_the_account)
    refused = client.post(CODE, data={"csrf_token": csrf}, follow_redirects=False)
    assert refused.status_code == 401
    assert code_count(app) == 0


# ---- the step-up ----


def password_only(**options):
    """Signed in by password alone, so the step-up below is the first code this account is sent."""
    app, client, sms, _ = make_portal(require_mfa=False, **options)
    sign_in(client, sms, mfa=False)
    return app, client, sms


def step_up(client):
    return client.post(STEP_UP, data={"csrf_token": form_token(client)})


def test_a_step_up_for_an_account_with_no_phone_and_no_mail_path_is_unavailable():
    app, client, sms = password_only()
    with app.state.session_factory() as session, session.begin():
        session.scalar(select(PatientPortalAccount)).phone_number = None
    refused = step_up(client)
    assert refused.status_code == 409
    assert say("mycarlos_unavailable") in refused.text
    assert not sms.messages


def test_in_development_an_account_with_no_phone_gets_its_code_by_the_portals_own_mail(
    monkeypatch,
):
    mail = RecordingPortalEmailSender()
    monkeypatch.setattr(
        portal_tests,
        "migrated_development_app",
        lambda **options: migrated_development_app(email_sender=mail, **options),
    )
    app, client, sms = password_only()
    with app.state.session_factory() as session, session.begin():
        session.scalar(select(PatientPortalAccount)).phone_number = None
    reply = step_up(client)
    assert reply.status_code == 200
    assert "mfa_challenge_token" in reply.text
    assert not sms.messages and len(mail.messages) == 1


@pytest.mark.parametrize(
    "error,status,key",
    [
        (MfaRateLimitedError, 429, "mycarlos_mfa_rate_limited"),
        (MfaDeliveryUnavailableError, 409, "mycarlos_unavailable"),
    ],
    ids=["asked too often", "no way to deliver"],
)
def test_a_step_up_the_challenge_refuses_says_so_and_sends_nothing(monkeypatch, error, status, key):
    app, client, sms = password_only()
    sent = len(sms.messages)

    def refuses(*args, **kwargs):
        raise error(30) if error is MfaRateLimitedError else error()

    monkeypatch.setattr(mycarlos_portal, "create_mfa_challenge", refuses)
    refused = step_up(client)
    assert refused.status_code == status
    assert say(key) in refused.text
    assert len(sms.messages) == sent


@pytest.mark.parametrize("failure", [PortalSmsDeliveryError, PortalEmailDeliveryError])
def test_a_code_that_could_not_be_delivered_is_a_503_and_the_failure_is_recorded(
    monkeypatch, failure
):
    app, client, sms = password_only()

    def cannot_send(*args, **kwargs):
        raise failure("FAKE provider detail")

    monkeypatch.setattr(mycarlos_portal, "send_mfa_challenge", cannot_send)
    refused = step_up(client)
    assert refused.status_code == 503
    assert say("mycarlos_unavailable") in refused.text
    assert "FAKE provider detail" not in refused.text


# ---- removing a device ----


def test_a_device_that_is_not_the_patients_is_not_found_to_confirm_or_to_remove():
    app, client, sms = signed_in()
    with app.state.session_factory() as session, session.begin():
        other = PatientPortalAccount(
            clinic_id=app.state.settings.clinic_id,
            demographic_no=7002,
            username="fake.other",
            email="fake.other@example.test",
            preferred_mfa_method="email",
            password_hash="FAKE-not-a-hash",
            status="active",
        )
        session.add(other)
        session.flush()
        other_id = other.id
    stranger = stored_device(app, other_id, "FAKE someone else")
    for path in (
        f"/portal/account/mycarlos/devices/{stranger}/remove",
        f"/portal/account/mycarlos/devices/{KEY}/remove",
    ):
        assert client.get(path).status_code == 404
        posted = client.post(path, data={"csrf_token": form_token(client)})
        assert posted.status_code == 404, path
    with app.state.session_factory() as session:
        status = session.scalar(
            select(PatientPortalMyCarlosDevice.status).where(
                PatientPortalMyCarlosDevice.device_key_id == stranger
            )
        )
    assert status == "active"


def test_a_removal_needs_the_same_step_up_as_a_code_and_removes_nothing_without_it():
    app, client, sms = password_only()
    with app.state.session_factory() as session:
        account_id = session.scalar(select(PatientPortalAccount.id))
    own = stored_device(app, account_id, "FAKE own phone")
    refused = client.post(
        f"/portal/account/mycarlos/devices/{own}/remove",
        data={"csrf_token": form_token(client)},
    )
    assert refused.status_code == 403
    assert say("mycarlos_mfa_required") in refused.text
    with app.state.session_factory() as session:
        status = session.scalar(
            select(PatientPortalMyCarlosDevice.status).where(
                PatientPortalMyCarlosDevice.device_key_id == own
            )
        )
    assert status == "active"


@pytest.mark.parametrize("path", [CODE, STEP_UP], ids=["code", "step-up"])
def test_a_linking_form_that_carries_anything_but_its_token_is_refused_whole(path):
    app, client, sms = signed_in()
    refused = client.post(
        path,
        data={"csrf_token": form_token(client), "account_id": "1", "extra": "x"},
    )
    assert refused.status_code == 400
    assert code_count(app) == 0
    assert len(sms.messages) == 1  # the sign-in code only
