"""Accessibility basics that must not slip back (carlos-emr/carlos-portal#57): a skip link and a
focusable <main> on every full page, a page title that names the page, text sizes that follow the
browser's text size, and no live region around a whole page. Browser checks (an automatic axe run)
are in scripts/patient-portal-playwright-checks.js; these run without a browser. FAKE data only."""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal import main
from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME
from carlos_patient_portal.locales import en, es, fr, pl, pt_BR, zh_CN, zh_TW
from tests.support import development_settings

PACKAGE = Path(main.__file__).resolve().parent
TEMPLATES = PACKAGE / "templates"
STYLES = PACKAGE / "static" / "styles.css"

# Every full page (the ones with their own <html>); the partials are included in them.
FULL_PAGES = sorted(
    path.name
    for path in TEMPLATES.glob("*.jinja")
    if "<html" in path.read_text(encoding="utf-8")
)


def test_the_full_pages_are_the_ones_that_are_checked() -> None:
    # A new full page must be added to the checks below by being a full page; this fails if the
    # list is ever empty or loses a known page.
    assert {"index.jinja", "dashboard.jinja", "mfa.jinja", "activate.jinja"} <= set(FULL_PAGES)


@pytest.mark.parametrize("name", FULL_PAGES)
def test_every_full_page_has_a_skip_link_to_a_focusable_main(name: str) -> None:
    source = (TEMPLATES / name).read_text(encoding="utf-8")
    # The skip link is the first thing in the body.
    assert re.search(r"<body>\s*\{% include \"_skip_link\.jinja\" %\}", source), name
    assert '<main class="app-shell" id="main-content" tabindex="-1">' in source, name


def test_the_skip_link_points_at_the_main_it_skips_to() -> None:
    link = (TEMPLATES / "_skip_link.jinja").read_text(encoding="utf-8")
    assert 'href="#main-content"' in link
    assert "{{ text.skip_to_content }}" in link


@pytest.mark.parametrize("name", FULL_PAGES)
def test_every_full_page_title_names_the_page(name: str) -> None:
    source = (TEMPLATES / name).read_text(encoding="utf-8")
    title = re.search(r"<title>(.*?)</title>", source, re.S)
    assert title, name
    # Not the service name alone: the page's own words come first (WCAG 2.4.2).
    assert title.group(1).strip() != "{{ service_name }}", name
    assert title.group(1).strip().endswith("- {{ service_name }}"), name


def test_the_dashboard_title_follows_the_module_shown() -> None:
    source = (TEMPLATES / "dashboard.jinja").read_text(encoding="utf-8")
    for module in ("mycarlos", "account", "email-passwords", "messages", "help"):
        assert f'"{module}":' in source
    assert "{{ page_heading }} - {{ service_name }}" in source


def test_the_module_workspace_is_not_one_big_live_region() -> None:
    # Status messages carry their own role="status" / role="alert"; a live region around the
    # whole workspace announces every change in it together (WCAG 4.1.3 done badly).
    source = (TEMPLATES / "dashboard.jinja").read_text(encoding="utf-8")
    assert 'class="module-workspace"' in source
    assert 'class="module-workspace" aria-live' not in source


def test_text_sizes_follow_the_browsers_text_size() -> None:
    css = STYLES.read_text(encoding="utf-8")
    pixel_sizes = re.findall(r"font-size:\s*[0-9.]+px", css)
    assert pixel_sizes == [], "font sizes in px ignore the browser's text size; use rem"
    assert "font-size: 0.8125rem;" in css  # the former 13px


def test_the_skip_link_is_hidden_until_it_has_the_focus() -> None:
    css = STYLES.read_text(encoding="utf-8")
    assert re.search(r"\.skip-link\s*\{[^}]*transform:\s*translateY\(-120%\)", css, re.S)
    assert re.search(r"\.skip-link:focus\s*\{[^}]*transform:\s*translateY\(0\)", css, re.S)


@pytest.mark.parametrize("module", [es, fr, pl, pt_BR, zh_CN, zh_TW])
def test_the_skip_link_words_are_translated_in_every_language(module) -> None:
    words = module.TEXT["skip_to_content"]
    assert words.strip()
    assert words != en.TEXT["skip_to_content"]


@pytest.mark.parametrize(
    ("code", "module"),
    [("en", en), ("es", es), ("fr", fr), ("pl", pl), ("pt-BR", pt_BR), ("zh-CN", zh_CN), ("zh-TW", zh_TW)],
)
def test_the_sign_in_page_has_the_skip_link_and_a_page_title(code: str, module) -> None:
    client = TestClient(main.create_app(development_settings()))
    client.cookies.set(LOCALE_COOKIE_NAME, code)

    response = client.get("/")

    assert response.status_code == 200
    page = response.text
    assert f'<a class="skip-link" href="#main-content">{module.TEXT["skip_to_content"]}</a>' in page
    assert '<main class="app-shell" id="main-content" tabindex="-1">' in page
    title = re.search(r"<title>(.*?)</title>", page, re.S)
    assert title
    assert module.TEXT["sign_in_heading"] in title.group(1)
    # The skip link comes before the header's language buttons in the page.
    assert page.index('class="skip-link"') < page.index('class="language-switch"')
