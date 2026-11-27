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

"""The optional clinic contact details on the Help page (phone, email, hours, website).

Blank settings keep "Contact the clinic". Synthetic values only.
"""

import re

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME, SUPPORTED_LOCALES, portal_text
from carlos_patient_portal.web_support import clinic_contact_for_help, phone_tel_href
from tests.support import (
    browser_sign_in_seeded_patient,
    development_settings,
    migrated_development_app,
)

ALL = {
    "clinic_contact_phone": "555-123-4567 ext. 2",
    "clinic_contact_email": "frontdesk@clinic.example",
    "clinic_contact_hours": "Mon-Fri 9:00-17:00",
    "clinic_contact_url": "https://clinic.example/contact",
}


def help_page(locale: str | None = None, **overrides: object) -> str:
    app = migrated_development_app(**overrides)
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    if locale:
        client.cookies.set(LOCALE_COOKIE_NAME, locale)
    return client.get("/portal/help").text


# --- Blank keeps "Contact the clinic" ------------------------------------------------------------


def test_with_nothing_configured_help_still_says_contact_the_clinic() -> None:
    page = help_page()
    assert "<dd>Contact the clinic</dd>" in page
    assert "contact-list" not in page and "mailto:" not in page and "tel:" not in page
    assert clinic_contact_for_help(development_settings()) is None


def test_blank_settings_are_the_same_as_unset() -> None:
    settings = development_settings(**{name: "   " for name in ALL})
    assert all(getattr(settings, name) is None for name in ALL)
    assert clinic_contact_for_help(settings) is None
    assert "<dd>Contact the clinic</dd>" in help_page(**{name: "  " for name in ALL})


# --- What is shown -------------------------------------------------------------------------------


def test_every_detail_set_is_shown_with_a_phone_email_and_web_link() -> None:
    page = help_page(**ALL)
    assert "<dd>Contact the clinic</dd>" not in page
    assert '<a href="tel:5551234567;ext=2">555-123-4567 ext. 2</a>' in page
    assert '<a href="mailto:frontdesk@clinic.example">frontdesk@clinic.example</a>' in page
    assert "<span>Mon-Fri 9:00-17:00</span>" in page
    assert (
        '<a href="https://clinic.example/contact" rel="noopener noreferrer">'
        "clinic.example/contact</a>"
    ) in page
    for label in ("Phone", "Email", "Hours", "Website"):
        assert f'<span class="contact-label">{label}</span>' in page


@pytest.mark.parametrize("name", sorted(ALL))
def test_each_detail_can_be_set_alone(name: str) -> None:
    page = help_page(**{name: ALL[name]})
    assert "<dd>Contact the clinic</dd>" not in page
    assert page.count('<span class="contact-label">') == 1


def test_a_value_is_escaped_in_the_page() -> None:
    page = help_page(clinic_contact_hours="Mon <b>9</b> & Fri")
    assert "Mon &lt;b&gt;9&lt;/b&gt; &amp; Fri" in page
    assert "<b>9</b>" not in page


@pytest.mark.parametrize("option", SUPPORTED_LOCALES, ids=lambda option: option.code)
def test_the_labels_are_translated_in_every_language(option) -> None:
    page = help_page(option.code, **ALL)
    text = portal_text(option.code)
    for key in ("contact_phone", "contact_email", "contact_hours", "contact_website"):
        assert text[key].strip()
        assert f'<span class="contact-label">{text[key]}</span>' in page
    # The clinic writes its own hours: shown as written, whatever the language.
    assert "Mon-Fri 9:00-17:00" in page


# --- The tel: link -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("phone", "href"),
    [
        ("555-123-4567", "tel:5551234567"),
        ("+1 (416) 555-0100 ext. 22", "tel:+14165550100;ext=22"),
        ("416.555.0100 x3", "tel:4165550100;ext=3"),
        ("(555) 123 4567", "tel:5551234567"),
    ],
)
def test_the_tel_link_has_only_digits_a_plus_and_an_extension(phone: str, href: str) -> None:
    assert phone_tel_href(phone) == href
    assert re.fullmatch(r"tel:\+?[0-9]+(;ext=[0-9]{1,6})?", phone_tel_href(phone))


# --- Validation ----------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["555-123-4567", "+1 (416) 555-0100 ext. 22", "  555 123 4567  "])
def test_the_contact_phone_accepts_phone_numbers(value: str) -> None:
    assert development_settings(clinic_contact_phone=value).clinic_contact_phone == value.strip()


@pytest.mark.parametrize("value", ["call the clinic", "555<b>1234</b>", "5" * 30, "x123", "12)"])
def test_the_contact_phone_refuses_anything_else(value: str) -> None:
    with pytest.raises(ValidationError, match="CLINIC_CONTACT_PHONE"):
        development_settings(clinic_contact_phone=value)


@pytest.mark.parametrize("value", ["a@b.example", "front.desk+x@clinic.example"])
def test_the_contact_email_accepts_one_address(value: str) -> None:
    assert development_settings(clinic_contact_email=value).clinic_contact_email == value


@pytest.mark.parametrize(
    "value",
    [
        "frontdesk",
        "Front Desk <f@clinic.example>",
        "a@clinic.example, b@clinic.example",
        "a@clinic.example?cc=x@y.example",
        # Characters that would become mail-client headers or a second recipient in `mailto:`.
        "a?bcc=x@evil.example",
        "a?subject=hi&body=x@clinic.example",
        "a&cc=x@clinic.example",
        "a%0d%0abcc:x@evil.example@clinic.example",
        "a%0D%0A@clinic.example",
        "a#frag@clinic.example",
        "a=b@clinic.example",
        "a/b@clinic.example",
        "a b@clinic.example",
        "javascript:alert(1)@x.example",
        "a@clinic",
    ],
)
def test_the_contact_email_refuses_anything_else(value: str) -> None:
    with pytest.raises(ValidationError, match="CLINIC_CONTACT_EMAIL"):
        development_settings(clinic_contact_email=value)


@pytest.mark.parametrize("value", ["line one\nline two", "tab\there", "bell\x07"])
def test_the_contact_hours_must_be_one_line(value: str) -> None:
    with pytest.raises(ValidationError, match="CLINIC_CONTACT_HOURS"):
        development_settings(clinic_contact_hours=value)


def test_the_contact_hours_are_limited_in_length() -> None:
    assert development_settings(clinic_contact_hours="h" * 200).clinic_contact_hours
    with pytest.raises(ValidationError):
        development_settings(clinic_contact_hours="h" * 201)


@pytest.mark.parametrize(
    "value",
    [
        "https://clinic.example",
        "https://clinic.example/contact?topic=help",
        "https://clinic.example:8443/a",
    ],
)
def test_the_contact_url_accepts_https_addresses(value: str) -> None:
    assert development_settings(clinic_contact_url=value).clinic_contact_url == value


@pytest.mark.parametrize(
    "value",
    [
        "http://clinic.example",
        "javascript:alert(1)",
        "data:text/html,x",
        "//clinic.example/x",
        "clinic.example",
        "https://user:pass@clinic.example",
        "https://",
        "https://clinic.example/a b",
        "https://clinic.example:notaport/",
        "https://clinic.example/\x00",
    ],
)
def test_the_contact_url_refuses_anything_but_a_plain_https_address(value: str) -> None:
    with pytest.raises(ValidationError, match="CLINIC_CONTACT_URL"):
        development_settings(clinic_contact_url=value)


def test_only_the_help_page_builds_the_contact_details() -> None:
    app = migrated_development_app(**ALL)
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    assert "frontdesk@clinic.example" not in client.get("/portal").text
    assert "frontdesk@clinic.example" in client.get("/portal/help").text
