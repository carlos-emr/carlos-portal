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
    assert source.count('<main id="main-content" tabindex="-1">') == 1, name
    assert source.count("<main") == 1 and source.count("</main>") == 1, name


@pytest.mark.parametrize("name", FULL_PAGES)
def test_every_full_page_has_a_banner_before_main_and_a_footer_after_it(name: str) -> None:
    # The top bar is a <header> whose ancestors are only <div>s, so it is the banner landmark
    # (inside <main> or a <section> it would not be); the footer stays the contentinfo.
    source = (TEMPLATES / name).read_text(encoding="utf-8")
    assert "<section class=\"portal-screen" not in source, name
    top_bar = min(
        i for i in (source.find("<header class=\"patient-topbar"), source.find("_public_header.jinja")) if i >= 0
    )
    assert top_bar < source.index("<main"), name
    assert source.index("</main>") < source.index("_page_footer.jinja"), name


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
    assert '<main id="main-content" tabindex="-1">' in page
    assert page.index("<header") < page.index("<main")
    title = re.search(r"<title>(.*?)</title>", page, re.S)
    assert title
    assert module.TEXT["sign_in_heading"] in title.group(1)
    # The skip link comes before the header's language buttons in the page.
    assert page.index('class="skip-link"') < page.index('class="language-switch"')


DASHBOARD = (TEMPLATES / "dashboard.jinja").read_text(encoding="utf-8")


@pytest.mark.parametrize("key", ["mycarlos", "account", "email-passwords", "help", "messages"])
def test_a_module_tile_link_is_named_by_its_heading_and_not_by_view(key: str) -> None:
    link = re.search(rf'<a class="module-tile"[^>]*aria-labelledby="tile-{key}-title[^"]*"[^>]*>(.*?)</a>', DASHBOARD, re.S)
    assert link, key
    body = link.group(1)
    assert f'id="tile-{key}-title"' in body
    assert f'id="tile-{key}-description"' in body
    assert 'aria-describedby="tile-' + key + '-description"' in link.group(0)
    # The trailing "View" is for the eye only.
    assert '<span aria-hidden="true">{{ text.view_module }}</span>' in body


def test_the_unread_count_is_part_of_the_messages_tile_name() -> None:
    assert 'aria-labelledby="tile-messages-title{% if new_message_count %} tile-messages-count{% endif %}"' in DASHBOARD
    assert 'id="tile-messages-count"' in DASHBOARD


def test_the_disabled_documents_tile_has_no_meaningless_aria_disabled() -> None:
    assert 'class="module-tile disabled">' in DASHBOARD
    assert "aria-disabled" not in DASHBOARD


def test_repeated_reveal_and_copy_buttons_say_which_password_they_are_for() -> None:
    assert 'id="email-password-subject-{{ row.id }}"' in DASHBOARD
    # Reveal and Copy both describe themselves by the row's subject; their own words stay first.
    assert DASHBOARD.count('aria-describedby="email-password-subject-{{ row.id }}"') == 2
    # The password itself is a named, read-only text box (a name on a plain <code> is not announced).
    assert re.search(r'<code[^>]*role="textbox"[^>]*aria-readonly="true"[^>]*aria-label=', DASHBOARD, re.S)


@pytest.mark.parametrize(
    ("template", "error_id"), [("index.jinja", "sign-in-error"), ("mfa.jinja", "mfa-error")]
)
def test_a_failed_sign_in_or_code_marks_the_boxes_and_points_them_at_the_error(
    template: str, error_id: str
) -> None:
    source = (TEMPLATES / template).read_text(encoding="utf-8")
    assert f'role="alert" id="{error_id}"' in source
    marked = f'{{% if error_message %}}aria-invalid="true" aria-describedby="{error_id}"{{% endif %}}'
    assert source.count(marked) == (2 if template == "index.jinja" else 1)


def test_what_a_button_changes_by_its_words_alone_is_announced() -> None:
    script = (PACKAGE / "static" / "portal.js").read_text(encoding="utf-8")
    assert 'liveStatus.setAttribute("role", "status")' in script
    assert 'liveStatus.setAttribute("aria-live", "polite")' in script
    # Revealing, reveal failed, copied, copy failed.
    assert script.count("announce(") == 4  # the four uses
    css = STYLES.read_text(encoding="utf-8")
    assert re.search(r"\.sr-only\s*\{[^}]*clip:", css, re.S)


def test_language_buttons_are_big_enough_to_touch() -> None:
    css = STYLES.read_text(encoding="utf-8")
    block = re.search(r"@media \(pointer: coarse\)\s*\{\s*\.text-tab\s*\{([^}]*)\}", css, re.S)
    assert block
    assert "min-width: 2.75rem" in block.group(1)
    assert "min-height: 2.75rem" in block.group(1)
