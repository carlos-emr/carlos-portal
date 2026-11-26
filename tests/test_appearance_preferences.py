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

"""The Preferences module: appearance (System, Light, Dark, and High contrast) and language.

The choice is two cookies, applied on the server as `data-theme` and `data-contrast` on `<html>`
(so there is no flash), and the language buttons moved here from the signed-in header. Synthetic
accounts and values only.
"""

import re

import pytest
from fastapi import Response
from fastapi.testclient import TestClient

from carlos_patient_portal import web_support
from carlos_patient_portal.appearance import (
    APPEARANCE_COOKIE_MAX_AGE_SECONDS,
    CONTRAST_COOKIE_NAME,
    THEME_COOKIE_NAME,
    Appearance,
    normalize_contrast,
    normalize_theme,
    read_appearance,
    set_appearance_cookies,
)
from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME, SUPPORTED_LOCALES, portal_text
from carlos_patient_portal.locales import en as locale_en
from tests.support import (
    CSRF_TOKEN_PATTERN,
    browser_sign_in_seeded_patient,
    migrated_development_app,
)

NEW_KEYS = (
    "preferences",
    "preferences_appearance",
    "preferences_appearance_legend",
    "appearance_system",
    "appearance_light",
    "appearance_dark",
    "appearance_high_contrast",
    "appearance_high_contrast_help",
    "preferences_save",
    "preferences_saved",
    "preferences_language",
)
HTML_TAG = re.compile(r"<html\b[^>]*>")
COLOR_SCHEME_META = re.compile(r'<meta name="color-scheme" content="([^"]*)">')


# --- The choice and its cookies (appearance.py) ---------------------------------------------------


def test_no_cookie_and_unknown_values_read_as_the_default() -> None:
    assert read_appearance({}) == Appearance("system", "standard")
    assert read_appearance(None) == Appearance()
    assert read_appearance(object()) == Appearance()
    hostile = {THEME_COOKIE_NAME: 'dark"><script>', CONTRAST_COOKIE_NAME: "MORE"}
    assert read_appearance(hostile) == Appearance()
    assert read_appearance({THEME_COOKIE_NAME: "Dark"}) == Appearance(), "values are exact"
    assert read_appearance({THEME_COOKIE_NAME: ""}).theme == "system"


@pytest.mark.parametrize("value", [None, 7, ["dark"], b"dark", "", "dark ", "DARK", "auto"])
def test_a_theme_or_contrast_that_is_not_on_the_allow_list_is_the_default(value) -> None:
    assert normalize_theme(value) == "system"
    assert normalize_contrast(value) == "standard"


def test_the_html_attributes_are_set_only_for_what_was_explicitly_chosen() -> None:
    assert str(Appearance().html_attributes) == ""
    assert str(Appearance("system", "standard").html_attributes) == ""
    assert str(Appearance("dark").html_attributes) == ' data-theme="dark"'
    assert str(Appearance("light").html_attributes) == ' data-theme="light"'
    assert str(Appearance("system", "more").html_attributes) == ' data-contrast="more"'
    assert (
        str(Appearance("dark", "more").html_attributes) == ' data-theme="dark" data-contrast="more"'
    )


def test_the_color_scheme_meta_says_both_until_one_is_chosen() -> None:
    assert Appearance().color_scheme == "light dark"
    assert Appearance("system", "more").color_scheme == "light dark"
    assert Appearance("light").color_scheme == "light"
    assert Appearance("dark", "more").color_scheme == "dark"


@pytest.mark.parametrize("secure", [True, False])
def test_the_choice_is_two_year_long_http_only_lax_cookies_for_the_whole_site(secure) -> None:
    response = Response()
    set_appearance_cookies(response, Appearance("dark", "more"), secure=secure)
    cookies = {value.split("=", 1)[0]: value for value in response.headers.getlist("set-cookie")}
    assert set(cookies) == {THEME_COOKIE_NAME, CONTRAST_COOKIE_NAME}
    for name, expected in ((THEME_COOKIE_NAME, "dark"), (CONTRAST_COOKIE_NAME, "more")):
        header = cookies[name]
        assert header.startswith(f"{name}={expected};")
        assert f"Max-Age={APPEARANCE_COOKIE_MAX_AGE_SECONDS}" in header
        assert "Path=/" in header and "HttpOnly" in header and "SameSite=lax" in header
        assert ("Secure" in header) is secure


# --- The strings: all seven languages -------------------------------------------------------------


@pytest.mark.parametrize("locale", [option.code for option in SUPPORTED_LOCALES])
def test_every_language_has_every_preferences_string(locale: str) -> None:
    text = portal_text(locale)
    for key in NEW_KEYS:
        assert text[key].strip(), f"{locale}: {key} is empty"
        if locale != "en":
            assert text[key] != locale_en.TEXT[key], f"{locale}: {key} is still English"


# --- The page, signed in --------------------------------------------------------------------------


def signed_in_client() -> tuple[TestClient, object]:
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    return client, app


def preferences_form_token(client: TestClient) -> str:
    match = CSRF_TOKEN_PATTERN.search(client.get("/portal/preferences").text)
    assert match is not None
    return match.group(1)


def save_preferences(client: TestClient, **fields: str):
    """Post the form with a fresh token: every page the portal renders rotates the CSRF cookie."""
    return client.post(
        "/portal/preferences",
        data={"csrf_token": preferences_form_token(client), **fields},
        follow_redirects=False,
    )


def test_the_sidebar_has_a_preferences_tab_right_after_help() -> None:
    client, _ = signed_in_client()
    page = client.get("/portal/preferences").text
    links = re.findall(r'<a\s+class="module-link[^"]*"\s+href="([^"]+)"', page)
    assert links.index("/portal/preferences") == links.index("/portal/help") + 1
    assert re.search(r'href="/portal/preferences"\s+aria-current="page"', page)
    assert "<title>Preferences - " in page
    # Every other module's page has the tab too.
    assert 'href="/portal/preferences"' in client.get("/portal/help").text


def test_appearance_is_a_named_radio_group_of_three_and_high_contrast_a_described_checkbox() -> (
    None
):
    client, _ = signed_in_client()
    page = client.get("/portal/preferences").text
    group = page[page.index('<fieldset class="preference-group">') : page.index("</fieldset>")]
    assert "<legend>Colour scheme</legend>" in group
    radios = re.findall(r'<input type="radio" name="theme" value="(\w+)"( checked)?>', group)
    assert radios == [("system", " checked"), ("light", ""), ("dark", "")]
    for label in ("System", "Light", "Dark"):
        assert f"<span>{label}</span>" in group
    # High contrast is its own checkbox, off by default, described by the line under it.
    assert re.search(
        r'<input type="checkbox" name="contrast" value="more" '
        r'aria-describedby="preferences-contrast-help">',
        page,
    )
    assert 'id="preferences-contrast-help"' in page
    assert "High contrast" in page and "Save preferences" in page
    # The form is a POST with the CSRF token.
    assert re.search(r'method="post" action="[^"]*/portal/preferences"', page)
    assert CSRF_TOKEN_PATTERN.search(page) is not None


def test_saving_dark_with_high_contrast_sets_the_cookies_and_the_html_attributes() -> None:
    client, _ = signed_in_client()
    token = preferences_form_token(client)
    saved = client.post(
        "/portal/preferences",
        data={"csrf_token": token, "theme": "dark", "contrast": "more"},
        follow_redirects=False,
    )
    assert saved.status_code == 303
    assert saved.headers["location"] == "/portal/preferences?status=saved"
    assert client.cookies.get(THEME_COOKIE_NAME) == "dark"
    assert client.cookies.get(CONTRAST_COOKIE_NAME) == "more"

    page = client.get("/portal/preferences?status=saved").text
    html = HTML_TAG.search(page).group(0)
    assert html == '<html lang="en" data-theme="dark" data-contrast="more">'
    assert COLOR_SCHEME_META.search(page).group(1) == "dark"
    assert "Preferences saved." in page
    # The form shows what is chosen.
    assert re.search(r'name="theme" value="dark" checked', page)
    assert re.search(r'name="contrast" value="more"[^>]*checked', page)
    assert not re.search(r'name="theme" value="system" checked', page)


def test_light_is_chosen_explicitly_and_system_sets_no_attribute_at_all() -> None:
    client, _ = signed_in_client()
    save_preferences(client, theme="light")
    page = client.get("/portal/help").text
    assert HTML_TAG.search(page).group(0) == '<html lang="en" data-theme="light">'
    assert COLOR_SCHEME_META.search(page).group(1) == "light"
    # System again: the cookie is stored, but the page carries nothing and the device decides.
    save_preferences(client, theme="system")
    assert client.cookies.get(THEME_COOKIE_NAME) == "system"
    page = client.get("/portal/help").text
    assert HTML_TAG.search(page).group(0) == '<html lang="en">'
    assert COLOR_SCHEME_META.search(page).group(1) == "light dark"


def test_an_unchecked_high_contrast_box_turns_it_back_off() -> None:
    client, _ = signed_in_client()
    save_preferences(client, theme="dark", contrast="more")
    assert 'data-contrast="more"' in client.get("/portal/help").text
    save_preferences(client, theme="dark")
    assert client.cookies.get(CONTRAST_COOKIE_NAME) == "standard"
    assert "data-contrast" not in client.get("/portal/help").text


@pytest.mark.parametrize(
    ("theme", "contrast"),
    [
        ('dark"><script>alert(1)</script>', "more"),
        ("DARK", "MORE"),
        ("", "yes"),
        ("light\r\nSet-Cookie: x=1", "more "),
    ],
)
def test_a_hand_edited_form_can_only_ever_get_the_default_look(theme: str, contrast: str) -> None:
    client, _ = signed_in_client()
    token = preferences_form_token(client)
    response = client.post(
        "/portal/preferences",
        data={"csrf_token": token, "theme": theme, "contrast": contrast},
        follow_redirects=False,
    )
    assert response.status_code == 303
    assert client.cookies.get(THEME_COOKIE_NAME) == "system"
    wanted = "more" if contrast == "more" else "standard"
    assert client.cookies.get(CONTRAST_COOKIE_NAME) == wanted
    assert "<script>alert" not in client.get("/portal/preferences").text
    assert "x=1" not in "".join(response.headers.get_list("set-cookie"))


def test_a_hand_edited_cookie_is_never_echoed_into_the_page() -> None:
    client = TestClient(migrated_development_app())
    client.cookies.set(THEME_COOKIE_NAME, 'dark" onload="alert(1)')
    client.cookies.set(CONTRAST_COOKIE_NAME, "<b>more</b>")
    page = client.get("/").text
    assert HTML_TAG.search(page).group(0) == '<html lang="en">'
    assert "onload" not in page and "<b>more</b>" not in page


def test_saving_needs_the_csrf_token_and_a_signed_in_session() -> None:
    client, _ = signed_in_client()
    refused = client.post("/portal/preferences", data={"theme": "dark"}, follow_redirects=False)
    assert refused.status_code == 403
    assert THEME_COOKIE_NAME not in client.cookies
    wrong = client.post(
        "/portal/preferences",
        data={"csrf_token": "FAKE-token", "theme": "dark"},
        follow_redirects=False,
    )
    assert wrong.status_code == 403
    # Signed out: the sign-in page, and no cookie is set for a stranger.
    stranger = TestClient(migrated_development_app())
    answer = stranger.post("/portal/preferences", data={"theme": "dark"}, follow_redirects=False)
    assert answer.status_code in {303, 403}
    assert THEME_COOKIE_NAME not in stranger.cookies
    assert stranger.get("/portal/preferences", follow_redirects=False).status_code == 303


def test_an_unknown_status_shows_no_notice() -> None:
    client, _ = signed_in_client()
    assert "Preferences saved." not in client.get("/portal/preferences?status=other").text
    assert "Preferences saved." in client.get("/portal/preferences?status=saved").text


# --- Where the choice applies ---------------------------------------------------------------------


@pytest.mark.parametrize("path", ["/", "/auth/password-reset"])
def test_the_choice_applies_to_the_pages_before_sign_in_too(path: str) -> None:
    client = TestClient(migrated_development_app())
    client.cookies.set(THEME_COOKIE_NAME, "dark")
    client.cookies.set(CONTRAST_COOKIE_NAME, "more")
    response = client.get(path)
    assert response.status_code == 200
    assert HTML_TAG.search(response.text).group(0) == (
        '<html lang="en" data-theme="dark" data-contrast="more">'
    )
    assert COLOR_SCHEME_META.search(response.text).group(1) == "dark"
    # Different per browser, so nothing may be cached and shared.
    assert response.headers["cache-control"] == "no-store"


def test_a_page_with_no_choice_has_a_plain_html_tag_and_both_schemes() -> None:
    client = TestClient(migrated_development_app())
    page = client.get("/").text
    assert HTML_TAG.search(page).group(0) == '<html lang="en">'
    assert COLOR_SCHEME_META.search(page).group(1) == "light dark"


def test_every_full_page_template_puts_the_attributes_on_its_html_tag() -> None:
    templates = web_support.PACKAGE_DIR / "templates"
    pages = [path for path in templates.glob("*.jinja") if "<html" in path.read_text()]
    assert len(pages) >= 11
    for path in pages:
        assert '<html lang="{{ locale }}"{{ appearance_html_attributes() }}>' in path.read_text(), (
            path.name
        )


# --- The language buttons moved -------------------------------------------------------------------


def test_the_sign_in_page_keeps_its_language_buttons() -> None:
    client = TestClient(migrated_development_app())
    page = client.get("/").text
    assert 'class="language-switch"' in page
    assert 'href="/locale/fr?next=/"' in page


def test_the_signed_in_header_no_longer_has_them_and_preferences_does() -> None:
    client, _ = signed_in_client()
    for path in ("/portal", "/portal/account", "/portal/help", "/portal/messages"):
        page = client.get(path).text
        assert 'class="language-switch"' not in page, path
    page = client.get("/portal/preferences").text
    assert page.count('class="language-switch"') == 1
    switch = page[page.index('class="language-switch"') :]
    switch = switch[: switch.index("</nav>")]
    for option in SUPPORTED_LOCALES:
        if option.code == "en":
            assert 'aria-current="true"' in switch and ">EN</span>" in switch
        else:
            assert f'href="/locale/{option.code}?next=/portal/preferences"' in switch
            assert f'lang="{option.code}"' in switch
    # It sits inside the main landmark, under its own heading, not in the top bar.
    assert page.index("<main") < page.index('class="language-switch"') < page.index("</main>")
    assert "<h2>Language</h2>" in page


def test_choosing_a_language_in_preferences_comes_back_to_preferences_in_that_language() -> None:
    client, _ = signed_in_client()
    chosen = client.get("/locale/fr?next=/portal/preferences", follow_redirects=False)
    assert chosen.status_code == 303
    assert chosen.headers["location"] == "/portal/preferences"
    assert client.cookies.get(LOCALE_COOKIE_NAME) == "fr"
    page = client.get("/portal/preferences").text
    assert '<html lang="fr"' in page
    assert "<h1>Préférences</h1>" in page and "Enregistrer les préférences" in page


@pytest.mark.parametrize("option", SUPPORTED_LOCALES, ids=lambda option: option.code)
def test_the_preferences_page_is_fully_translated_in_every_language(option) -> None:
    client, _ = signed_in_client()
    client.cookies.set(LOCALE_COOKIE_NAME, option.code)
    page = client.get("/portal/preferences").text
    text = portal_text(option.code)
    assert f'<html lang="{option.code}"' in page
    for key in (
        "preferences",
        "preferences_appearance",
        "preferences_appearance_legend",
        "appearance_system",
        "appearance_light",
        "appearance_dark",
        "appearance_high_contrast",
        "appearance_high_contrast_help",
        "preferences_save",
        "preferences_language",
    ):
        assert text[key] in page, f"{option.code}: {key}"
    # The appearance choice is kept across a language change: it is a different cookie.
    assert 'class="language-switch"' in page
