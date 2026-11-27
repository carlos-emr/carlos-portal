# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

"""The Account tab shows the phone confirmation code field only while one is waiting (#150).

The code field, "Confirm phone number" and "Send another code" used to be on the Account tab
whether or not a phone number had been added. The presenter now decides, through
`PhoneConfirmationViewModel`: shown for a number whose code was sent and is still valid, a notice
and the resend button alone once the code ran out, nothing otherwise. The confirm and resend
routes are unchanged and keep refusing with nothing pending (a hidden form is not the boundary).
"""

import logging
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME, SUPPORTED_LOCALES, portal_text
from carlos_patient_portal.models import (
    EMAIL_CHANGE_STATUS_PENDING,
    EMAIL_CHANGE_STATUS_REVOKED,
    PatientPortalAccount,
    PatientPortalEmailChangeRequest,
    utc_now,
)
from carlos_patient_portal.presenters import assemble_phone_confirmation, mask_phone_number
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    browser_sign_in_seeded_patient,
    csrf_token_from_response,
    migrated_development_app,
    submit_contact_change,
)

NEW_PHONE = "+16135550198"
CONFIRM_ACTION = "/portal/account/contact/confirm-phone"
RESEND_ACTION = "/portal/account/contact/resend-phone"
CODE_FIELD = 'name="phone_confirmation_code"'


def signed_in_app():
    sms_sender = RecordingPortalSmsSender()
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(),
        sms_sender=sms_sender,
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    return app, client, sms_sender


def only_the_pending_request(app) -> PatientPortalEmailChangeRequest:
    with app.state.session_factory() as session:
        request = session.scalars(select(PatientPortalEmailChangeRequest)).one()
        session.expunge(request)
        return request


def account_page(client: TestClient):
    page = client.get("/portal/account")
    assert page.status_code == 200
    return page


def assert_block_hidden(page) -> None:
    assert CODE_FIELD not in page.text
    assert CONFIRM_ACTION not in page.text
    assert RESEND_ACTION not in page.text
    assert portal_text("en")["phone_confirmation_code"] not in page.text
    assert portal_text("en")["resend_phone_confirmation"] not in page.text


def test_no_phone_added_hides_the_code_field_and_the_routes_still_refuse() -> None:
    app, client, sms_sender = signed_in_app()

    page = account_page(client)

    assert_block_hidden(page)
    # The hidden form is not the boundary: with nothing pending the routes refuse as before.
    confirm = client.post(
        CONFIRM_ACTION,
        data={
            "csrf_token": csrf_token_from_response(page),
            "phone_confirmation_code": "000000",
        },
        follow_redirects=False,
    )
    resend = client.post(
        RESEND_ACTION,
        data={"csrf_token": csrf_token_from_response(page)},
        follow_redirects=False,
    )
    assert confirm.status_code == 303
    assert "phone-confirmation-invalid" in confirm.headers["location"]
    assert resend.status_code == 303
    assert "phone-confirmation-invalid" in resend.headers["location"]
    assert sms_sender.messages == []


def test_a_phone_added_with_its_code_sent_shows_the_field_masked_and_never_the_number(
    caplog: pytest.LogCaptureFixture,
) -> None:
    app, client, sms_sender = signed_in_app()
    requested = submit_contact_change(app, client, phone_number=NEW_PHONE)
    assert requested.status_code == 303
    assert len(sms_sender.messages) == 1

    with caplog.at_level(logging.DEBUG):
        page = account_page(client)

    assert CODE_FIELD in page.text
    assert CONFIRM_ACTION in page.text
    assert RESEND_ACTION in page.text
    sent_to = portal_text("en")["phone_confirmation_sent_to"].format(number="••• ••• 0198")
    assert sent_to in page.text
    # The page and the logs carry the last four digits at most, never the number.
    for text in (page.text, caplog.text):
        assert NEW_PHONE not in text
        assert "6135550198" not in text
        assert "613 555" not in text
        assert "613-555" not in text


def test_a_confirmed_phone_hides_the_block_again() -> None:
    app, client, sms_sender = signed_in_app()
    submit_contact_change(app, client, phone_number=NEW_PHONE)
    page = account_page(client)
    assert CODE_FIELD in page.text

    confirmed = client.post(
        CONFIRM_ACTION,
        data={
            "csrf_token": csrf_token_from_response(page),
            "phone_confirmation_code": str(sms_sender.messages[0]["code"]),
        },
        follow_redirects=False,
    )

    assert confirmed.status_code == 303
    assert only_the_pending_request(app).phone_confirmed_at is not None
    assert_block_hidden(account_page(client))


def test_an_expired_code_shows_a_clear_notice_and_only_the_resend_button() -> None:
    app, client, sms_sender = signed_in_app()
    submit_contact_change(app, client, phone_number=NEW_PHONE)
    with app.state.session_factory() as session:
        request = session.scalars(select(PatientPortalEmailChangeRequest)).one()
        # The code ran out (the default lifetime is ten minutes) but the change itself is open.
        request.phone_code_sent_at = utc_now() - timedelta(minutes=11)
        session.commit()

    page = account_page(client)

    assert CODE_FIELD not in page.text
    assert CONFIRM_ACTION not in page.text
    assert RESEND_ACTION in page.text
    expired = portal_text("en")["phone_confirmation_expired"].format(number="••• ••• 0198")
    assert expired in page.text
    # "Send another code" works from there, and the field returns with the new code.
    resent = client.post(
        RESEND_ACTION,
        data={"csrf_token": csrf_token_from_response(page)},
        follow_redirects=False,
    )
    assert resent.status_code == 303
    assert len(sms_sender.messages) == 2
    assert CODE_FIELD in account_page(client).text


def test_a_change_that_expired_or_was_cancelled_hides_the_block() -> None:
    app, client, _sms = signed_in_app()
    submit_contact_change(app, client, phone_number=NEW_PHONE)
    with app.state.session_factory() as session:
        request = session.scalars(select(PatientPortalEmailChangeRequest)).one()
        request.created_at = utc_now() - timedelta(days=3)
        request.expires_at = utc_now() - timedelta(days=2)
        session.commit()
    assert_block_hidden(account_page(client))

    with app.state.session_factory() as session:
        request = session.scalars(select(PatientPortalEmailChangeRequest)).one()
        request.created_at = utc_now() - timedelta(minutes=1)
        request.expires_at = utc_now() + timedelta(days=1)
        request.status = EMAIL_CHANGE_STATUS_REVOKED
        session.commit()
    assert_block_hidden(account_page(client))


def test_an_email_only_change_has_no_phone_to_confirm() -> None:
    app, client, sms_sender = signed_in_app()
    submit_contact_change(app, client, phone_number="")

    assert_block_hidden(account_page(client))
    assert sms_sender.messages == []


@pytest.mark.parametrize("locale", [option.code for option in SUPPORTED_LOCALES])
def test_the_masked_notice_is_shown_in_every_language(locale: str) -> None:
    app, client, _sms = signed_in_app()
    submit_contact_change(app, client, phone_number=NEW_PHONE)
    client.cookies.set(LOCALE_COOKIE_NAME, locale)

    page = account_page(client)

    text = portal_text(locale)
    sent_to = text["phone_confirmation_sent_to"].format(number="••• ••• 0198")
    assert sent_to in page.text
    assert "{number}" not in page.text
    if locale != "en":
        assert sent_to != portal_text("en")["phone_confirmation_sent_to"].format(
            number="••• ••• 0198"
        )
    assert text["phone_confirmation_expired"].count("{number}") == 1


def test_the_presenter_decides_and_masks_without_a_request() -> None:
    app, client, _sms = signed_in_app()
    submit_contact_change(app, client, phone_number=NEW_PHONE)
    ttl = timedelta(minutes=10)
    with app.state.session_factory() as session:
        account = session.scalars(select(PatientPortalAccount)).one()
        pending = assemble_phone_confirmation(session, account, code_ttl=ttl)
        later = assemble_phone_confirmation(
            session, account, code_ttl=ttl, now=utc_now() + timedelta(minutes=11)
        )
        much_later = assemble_phone_confirmation(
            session, account, code_ttl=ttl, now=utc_now() + timedelta(days=30)
        )
    assert (pending.code_pending, pending.code_expired) == (True, False)
    assert pending.masked_phone == "••• ••• 0198"
    assert (later.code_pending, later.code_expired) == (False, True)
    assert (much_later.code_pending, much_later.code_expired) == (False, False)
    assert much_later.masked_phone == ""
    assert only_the_pending_request(app).status == EMAIL_CHANGE_STATUS_PENDING


@pytest.mark.parametrize(
    ("number", "masked"),
    [
        ("+16135550198", "••• ••• 0198"),
        ("+1 (613) 555-0198", "••• ••• 0198"),
        ("5550198", "••• ••• 0198"),
        ("123", "••• •••"),
        ("", "••• •••"),
    ],
)
def test_masking_keeps_the_last_four_digits_at_most(number: str, masked: str) -> None:
    assert mask_phone_number(number) == masked
