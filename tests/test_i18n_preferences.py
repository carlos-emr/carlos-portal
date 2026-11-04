"""Browser preferences must not override an explicit portal language selection."""

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal import main
from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME, parse_accept_language
from tests.support import development_settings


@pytest.mark.parametrize(
    ("header", "expected"),
    [
        ("fr;q=0.2,es;q=0.9,en;q=0.5", "es"),
        ("de-DE;q=1,pt-BR;q=0.8,en;q=0.5", "pt-BR"),
        ("es;q=0.7,fr;q=0.7", "es"),
        ("fr;q=0.7,es;q=0.7", "fr"),
        ("fr;q=0,pt;q=0.4", "pt-BR"),
        (";q=1, , *;q=1,pt;q=0.5", "pt-BR"),
        ("fr;q=broken,es;q=-0.1,pl;q=0.4", "pl"),
        ("fr;q=,pl;q=0.5", "pl"),
    ],
)
def test_browser_preference_uses_the_best_acceptable_supported_language(
    header: str, expected: str
) -> None:
    assert parse_accept_language(header) == expected


@pytest.mark.parametrize("header", [None, "", "de-DE,*;q=0.5", "fr;q=0,es;q=0"])
def test_no_acceptable_supported_language_leaves_the_default_to_the_caller(
    header: str | None,
) -> None:
    assert parse_accept_language(header) is None


@pytest.mark.parametrize(
    ("cookie", "header", "expected"),
    [
        # Choosing English explicitly must win even though it is also the default.
        ("en", "fr;q=1", "en"),
        # Stored browser-style locale aliases still represent an explicit choice.
        ("PT_br", "es;q=1", "pt-BR"),
        # An obsolete or unsupported preference must not suppress a usable header.
        ("de-DE", "pl;q=0.8,en;q=0.5", "pl"),
        ("de-DE", "de-DE,*;q=0.5", "en"),
    ],
)
def test_sign_in_page_respects_the_chosen_language_and_falls_back_safely(
    cookie: str, header: str, expected: str
) -> None:
    app = main.create_app(development_settings())
    client = TestClient(app)
    client.cookies.set(LOCALE_COOKIE_NAME, cookie)

    response = client.get("/", headers={"Accept-Language": header})

    assert response.status_code == 200
    assert f'<html lang="{expected}">' in response.text
    assert f'<span class="text-tab selected" aria-current="true" lang="{expected}"' in response.text
    # Rendering a fallback must not silently rewrite the user's saved choice.
    assert LOCALE_COOKIE_NAME not in response.headers.get("set-cookie", "")
