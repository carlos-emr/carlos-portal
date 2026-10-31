"""Patients can change display language while a browser notice prevents normal portal use."""

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal import main
from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME
from tests.support import development_settings


def prefix_stripping_proxy(app, prefix):
    """The deployment proxy strips the external prefix; FastAPI retains root_path."""

    async def proxy(scope, receive, send):
        if scope["type"] == "http" and prefix:
            assert scope["path"].startswith(prefix + "/")
            scope = dict(scope)
            scope["path"] = scope["path"][len(prefix) :]
            scope["raw_path"] = scope["raw_path"][len(prefix.encode()) :]
        await app(scope, receive, send)

    return proxy


@pytest.mark.parametrize("prefix", ["", "/patient", "/clinic/patient"])
@pytest.mark.parametrize("notice_status", [503, 429])
def test_language_switch_on_a_service_notice_persists_without_bypassing_the_notice(
    notice_status, prefix
):
    app = main.create_app(
        development_settings(
            database_url="sqlite+pysqlite:///:memory:",
            maintenance_mode=notice_status == 503,
            public_base_url="https://portal.example.test" + prefix,
            global_rate_limit_max_requests=1,
        )
    )
    client = TestClient(prefix_stripping_proxy(app, prefix), base_url="https://portal.example.test")
    try:
        initial = client.get(prefix + "/")
        if notice_status == 429:
            assert initial.status_code == 200
            initial = client.get(prefix + "/")
        assert initial.status_code == notice_status
        assert f'href="{prefix}/locale/fr?next={prefix}/"' in initial.text

        selected = client.get(
            prefix + "/locale/fr", params={"next": prefix + "/"}, follow_redirects=False
        )

        assert selected.status_code == 303
        assert selected.headers["location"] == prefix + "/"
        assert client.cookies[LOCALE_COOKIE_NAME] == "fr"
        translated_notice = client.get(prefix + "/")
        assert translated_notice.status_code == notice_status
        assert '<html lang="fr">' in translated_notice.text
        assert '<span class="text-tab selected" aria-current="true" lang="fr"' in (
            translated_notice.text
        )
        assert translated_notice.headers["retry-after"]
        assert translated_notice.headers["cache-control"] == "no-store"
    finally:
        client.close()
        app.state.database_engine.dispose()


@pytest.mark.parametrize("prefix", ["", "/patient", "/clinic/patient"])
def test_maintenance_language_exception_keeps_route_and_redirect_guards(prefix):
    app = main.create_app(
        development_settings(
            database_url="sqlite+pysqlite:///:memory:",
            maintenance_mode=True,
            public_base_url="https://portal.example.test" + prefix,
        )
    )
    client = TestClient(prefix_stripping_proxy(app, prefix), base_url="https://portal.example.test")
    try:
        for path in ["/auth/login", "/api/patient/email-passwords", "/api/mycarlos/deliveries"]:
            assert client.get(prefix + path).status_code == 503
        assert client.get(prefix + "/locale/zz", follow_redirects=False).status_code == 404
        refused_redirect = client.get(
            prefix + "/locale/fr",
            params={"next": "https://offsite.example.test"},
            follow_redirects=False,
        )
        assert refused_redirect.status_code == 303
        assert refused_redirect.headers["location"] == prefix + "/"
    finally:
        client.close()
        app.state.database_engine.dispose()
