"""Maintenance exports public notice metadata without authenticated-flow setup."""

import json

import pytest
from sqlalchemy import select

from carlos_patient_portal.i18n import DEFAULT_LOCALE, LOCALE_COOKIE_NAME, portal_text
from carlos_patient_portal.models import PatientPortalAccount
from tests import seed_browser_session as seed
from tests.support import development_settings, migrated_development_app


def test_maintenance_seed_needs_no_session_configuration_or_database(tmp_path, monkeypatch):
    fixture = tmp_path / "maintenance.json"
    fixture.write_text("old public fixture")
    fixture.chmod(0o644)
    settings = development_settings(
        database_url="sqlite+pysqlite:///" + str(tmp_path / "unused.db")
    )
    assert settings.sms_webhook_url is None
    assert settings.session_idle_timeout_seconds > 120
    monkeypatch.setenv("PORTAL_SESSION_STEPS", " maintenance ")
    monkeypatch.setenv("PORTAL_SESSION_FIXTURE_FILE", str(fixture))
    monkeypatch.setattr(seed, "get_settings", lambda: settings)

    def no_session_setup(*_args, **_kwargs):
        pytest.fail("maintenance must not validate or seed authenticated session flows")

    for name in ["require_browser_settings", "create_portal_engine", "generated_password"]:
        monkeypatch.setattr(seed, name, no_session_setup)
    seed.main()

    payload = json.loads(fixture.read_text())
    assert fixture.stat().st_mode & 0o777 == 0o600
    assert payload["settings"] == {
        "defaultLocale": DEFAULT_LOCALE,
        "localeCookieName": LOCALE_COOKIE_NAME,
    }
    assert payload["text"] == portal_text(DEFAULT_LOCALE)
    assert {DEFAULT_LOCALE, "pl"} <= {locale["code"] for locale in payload["locales"]}
    assert all(locale["text"] == portal_text(locale["code"]) for locale in payload["locales"])
    assert "accounts" not in payload and "newPhone" not in payload
    assert not (tmp_path / "unused.db").exists()


@pytest.mark.parametrize("steps", ["", "idle"])
def test_nonmaintenance_seed_keeps_its_session_configuration_requirements(monkeypatch, steps):
    monkeypatch.setenv("PORTAL_SESSION_STEPS", steps)
    monkeypatch.setattr(seed, "get_settings", lambda: development_settings())
    with pytest.raises(RuntimeError, match="SMS_WEBHOOK"):
        seed.main()


def test_default_seed_still_creates_all_five_session_accounts(tmp_path, monkeypatch):
    app = migrated_development_app(
        database_url="sqlite+pysqlite:///" + str(tmp_path / "session.db"),
        sms_webhook_url="http://127.0.0.1:1/sms",
        sms_webhook_token="FAKE-session-capture-token-00000001",
    )
    fixture = tmp_path / "session.json"
    monkeypatch.delenv("PORTAL_SESSION_STEPS", raising=False)
    monkeypatch.setenv("PORTAL_SESSION_FIXTURE_FILE", str(fixture))
    monkeypatch.setattr(seed, "get_settings", lambda: app.state.settings)
    try:
        seed.main()
        payload = json.loads(fixture.read_text())
        assert set(payload["accounts"]) == {"sms", "phone", "locale", "throttle", "idle"}
        assert payload["newPhone"] == seed.NEW_PHONE
        assert payload["settings"]["sessionCookieName"] == seed.PORTAL_SESSION_COOKIE_NAME
        assert (
            payload["settings"]["idleTimeoutSeconds"]
            == app.state.settings.session_idle_timeout_seconds
        )
        assert fixture.stat().st_mode & 0o777 == 0o600
        with app.state.session_factory() as session:
            actual = set(session.scalars(select(PatientPortalAccount.username)))
        assert actual == {value["username"] for value in payload["accounts"].values()}
        assert all(value["password"] for value in payload["accounts"].values())
    finally:
        app.state.database_engine.dispose()
