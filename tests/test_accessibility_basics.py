"""Accessibility basics that must not slip back (carlos-emr/carlos-portal#57): a skip link and a
focusable <main> on every full page, a page title that names the page, text sizes that follow the
browser's text size, and no live region around a whole page. Browser checks (an automatic axe run)
are in scripts/patient-portal-playwright-checks.js; these run without a browser. FAKE data only."""

import re
from html.parser import HTMLParser
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


# --- Structure, read from the parsed page rather than grepped from the template text ----------

_VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


class _Outline(HTMLParser):
    """The elements of a page in document order, each with the tags it sits inside."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, dict[str, str | None]]] = []
        self.elements: list[tuple[str, dict[str, str | None], tuple[tuple[str, dict[str, str | None]], ...]]] = []

    def handle_starttag(self, tag, attrs) -> None:
        attributes = dict(attrs)
        self.elements.append((tag, attributes, tuple(self.stack)))
        if tag not in _VOID:
            self.stack.append((tag, attributes))

    def handle_startendtag(self, tag, attrs) -> None:
        self.elements.append((tag, dict(attrs), tuple(self.stack)))

    def handle_endtag(self, tag) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                del self.stack[index:]
                return


def _outline(html: str) -> _Outline:
    parser = _Outline()
    parser.feed(html)
    return parser


def _page_source(name: str) -> str:
    """A template as the browser would get it: its includes written in, its Jinja tags removed
    (every branch of a conditional stays, which is why this is for structure, not for words)."""
    source = (TEMPLATES / name).read_text(encoding="utf-8")
    source = re.sub(
        r"\{%-?\s*include\s+\"([^\"]+)\"\s*-?%\}",
        lambda match: _page_source(match.group(1)),
        source,
    )
    source = re.sub(r"\{#.*?#\}", "", source, flags=re.S)
    source = re.sub(r"\{%.*?%\}", "", source, flags=re.S)
    return re.sub(r"\{\{.*?\}\}", "x", source, flags=re.S)


def _is_focusable(tag: str, attributes: dict[str, str | None]) -> bool:
    if "hidden" in attributes or attributes.get("type") == "hidden":
        return False
    if tag in {"button", "select", "textarea"}:
        return "disabled" not in attributes
    if tag == "input":
        return "disabled" not in attributes
    if tag == "a":
        return "href" in attributes
    return attributes.get("tabindex") not in (None, "-1")


def _check_skip_link_structure(html: str, label: str) -> None:
    outline = _outline(html)
    mains = [e for e in outline.elements if e[0] == "main"]
    assert len(mains) == 1, label
    assert mains[0][1].get("id") == "main-content", label
    assert mains[0][1].get("tabindex") == "-1", label
    # The skip link points at that main, and is the first thing a keyboard reaches.
    focusables = [(i, e) for i, e in enumerate(outline.elements) if _is_focusable(e[0], e[1])]
    first = focusables[0][1]
    assert first[0] == "a" and first[1].get("href") == "#main-content", label
    assert "skip-link" in (first[1].get("class") or ""), label
    main_at = outline.elements.index(mains[0])
    inside_main = [i for i, e in focusables if any(tag == "main" for tag, _ in e[2])]
    assert inside_main, f"{label}: nothing in the page content can be reached"
    # What the skip link skips: the top bar, which comes before main and is not inside it.
    before_main = [e for i, e in focusables if i < main_at]
    assert len(before_main) > 1, f"{label}: the skip link would skip nothing"
    # The first stop after main begins is inside main.
    after = [e for i, e in focusables if i >= main_at][0]
    assert any(tag == "main" for tag, _ in after[2]), label
    for tag, attributes, ancestors in outline.elements:
        in_main = any(t == "main" for t, _ in ancestors)
        classes = (attributes.get("class") or "").split()
        # The top bar (banner) and the language switch are outside main; so is the footer.
        if "patient-topbar" in classes or "page-footer" in classes or "language-switch" in classes:
            assert not in_main, f"{label}: {tag}.{'.'.join(classes)} is inside main"
    topbars = [e for e in outline.elements if "patient-topbar" in (e[1].get("class") or "").split()]
    assert len(topbars) == 1 and topbars[0][0] == "header", label
    # A <header> is the page's banner only when no section, article, aside, nav or main holds it.
    assert not any(t in {"main", "section", "article", "aside", "nav"} for t, _ in topbars[0][2]), label


@pytest.mark.parametrize("name", FULL_PAGES)
def test_the_skip_link_skips_the_top_bar_on_every_page(name: str) -> None:
    _check_skip_link_structure(_page_source(name), name)


@pytest.mark.parametrize("code", ["en", "es", "fr", "pl", "pt-BR", "zh-CN", "zh-TW"])
def test_the_rendered_sign_in_page_has_the_same_structure(code: str) -> None:
    client = TestClient(main.create_app(development_settings()))
    client.cookies.set(LOCALE_COOKIE_NAME, code)
    _check_skip_link_structure(client.get("/").text, f"rendered / in {code}")


def test_every_message_the_script_puts_into_a_button_is_announced_or_deliberately_not() -> None:
    script = (PACKAGE / "static" / "portal.js").read_text(encoding="utf-8")
    # Announced: Revealing..., the failed reveal, Copied, Copy failed.
    for words in (
        "revealButton.dataset.revealingLabel",
        "revealButton.dataset.revealFailedLabel",
        "copyButton.dataset.copiedLabel",
        "copyButton.dataset.copyFailedLabel",
    ):
        block = script[script.index(words) :].split(";", 1)[1:2]
        assert block and "announce(" in script[script.index(words) : script.index(words) + 260], words
    # Not announced on purpose: putting a label back (after 2.5 s, on hiding the page), the
    # password box (the focus moves to it), the modal (a dialog) and the booking notice
    # (its element is role="status" already).
    assert 'role="status"' in DASHBOARD
