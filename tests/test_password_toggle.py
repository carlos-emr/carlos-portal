"""Every patient-portal password box has a Show password control (#29)."""

import html
import re

import pytest
from fastapi.testclient import TestClient

from tests.support import browser_sign_in_seeded_patient, migrated_development_app

PASSWORD_BOX = re.compile(r'<input[^>]*type="password"[^>]*>', re.S)
TOGGLE = re.compile(r"<button[^>]*data-password-toggle[^>]*>", re.S)


def assert_every_password_box_has_a_toggle(page: str) -> int:
    controlled: set[str] = set()
    toggles = TOGGLE.findall(page)
    for toggle in toggles:
        assert 'type="button"' in toggle, toggle
        assert " name=" not in toggle, "the control must never be submitted"
        # The changing words carry the state; no aria-pressed (D133, as GOV.UK does it).
        assert "aria-pressed" not in toggle, toggle
        # Shown only by the script: without JavaScript there is no control.
        assert re.search(r"\shidden\s*>", toggle), toggle
        controls = re.search(r'aria-controls="([^"]+)"', toggle)
        assert controls, toggle
        controlled.update(controls.group(1).split())
    boxes = PASSWORD_BOX.findall(page)
    assert boxes, "the page has no password box"
    for box in boxes:
        box_id = re.search(r'\sid="([^"]+)"', box)
        assert box_id and box_id.group(1) in controlled, f"no Show password control for {box}"
        # Password managers keep working: autocomplete is still set on every box.
        assert "autocomplete=" in box, box
        # Shown as text, a password must not be capitalised, corrected or spell-checked.
        for attribute in ('spellcheck="false"', 'autocapitalize="none"', 'autocorrect="off"'):
            assert attribute in box, f"{attribute} missing on {box}"
    return len(boxes)


@pytest.mark.parametrize(
    ("path", "boxes"),
    [("/", 1), ("/auth/activate", 2), ("/auth/password-reset/complete", 2)],
)
def test_public_password_boxes_have_a_show_password_control(path: str, boxes: int) -> None:
    response = TestClient(migrated_development_app()).get(path)

    assert response.status_code == 200
    assert assert_every_password_box_has_a_toggle(response.text) == boxes


@pytest.mark.parametrize(
    ("path", "boxes"), [("/portal/account", 5), ("/portal/email-passwords", 1)]
)
def test_signed_in_password_boxes_have_a_show_password_control(path: str, boxes: int) -> None:
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)

    response = client.get(path)

    assert response.status_code == 200
    assert assert_every_password_box_has_a_toggle(response.text) == boxes


def test_activation_shares_one_control_for_the_password_and_its_confirmation() -> None:
    page = TestClient(migrated_development_app()).get("/auth/activate").text

    toggles = TOGGLE.findall(page)
    assert len(toggles) == 1
    assert 'aria-controls="activation-password activation-password-confirmation"' in toggles[0]


def test_show_password_control_is_in_the_patients_language() -> None:
    client = TestClient(migrated_development_app())
    client.cookies.set("portal_locale", "fr")

    toggle = TOGGLE.search(client.get("/auth/activate").text).group(0)

    assert 'data-show-label="Afficher le mot de passe"' in html.unescape(toggle)
    assert 'data-hide-label="Masquer le mot de passe"' in html.unescape(toggle)
