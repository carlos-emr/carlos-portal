"""Patients can change display language while a browser notice prevents normal portal use."""

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal import main
from carlos_patient_portal.i18n import LOCALE_COOKIE_NAME
from carlos_patient_portal.web_support import PACKAGE_DIR
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
        if notice_status == 503:
            assert '<h1 id="notice-title">Portail indisponible</h1>' in translated_notice.text
            assert "Le portail est temporairement indisponible pour cause d’entretien." in (
                translated_notice.text
            )
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
        for path in [
            "/auth/login",
            "/portal/account",
            "/api/patient/email-passwords",
            "/api/mycarlos/deliveries",
            "/fhir/metadata",
            "/internal/carlos/FAKE-maintenance-guard",
        ]:
            assert client.get(prefix + path).status_code == 503
            assert client.post(prefix + path, json={}).status_code == 503
        for filename, content_type in [
            ("styles.css", "text/css"),
            ("portal.js", "javascript"),
            ("carlos-birdman.png", "image/png"),
        ]:
            target = prefix + "/static/" + filename
            asset = client.get(target)
            assert asset.status_code == 200
            assert content_type in asset.headers["content-type"]
            assert asset.content == (PACKAGE_DIR / "static" / filename).read_bytes()
            head = client.head(target)
            assert head.status_code == 200
            assert head.content == b""
            assert head.headers["content-length"] == asset.headers["content-length"]
            assert client.post(target).status_code == 503
        assert client.get(prefix + "/static/FAKE-unlisted-notice-asset").status_code == 503
        assert client.post(prefix + "/static/FAKE-unlisted-notice-asset").status_code == 503
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


@pytest.mark.parametrize(
    ("locale", "help_title", "help_message", "close_label", "back_label"),
    [
        (
            "fr",
            "Aide de la clinique",
            "Contactez la clinique si vous ne pouvez pas accéder à votre compte ou à votre "
            "méthode de vérification.",
            "OK",
            "Retour à la connexion",
        ),
        (
            "es",
            "Ayuda de la clínica",
            "Contacte con la clínica si no puede acceder a su cuenta o a su método de "
            "verificación.",
            "Aceptar",
            "Volver al inicio de sesión",
        ),
        (
            "pl",
            "Pomoc przychodni",
            "W razie braku dostępu do konta lub metody weryfikacji proszę skontaktować się "
            "z przychodnią.",
            "OK",
            "Powrót do logowania",
        ),
        (
            "pt-BR",
            "Ajuda da clínica",
            "Entre em contato com a clínica se você não conseguir acessar sua conta ou seu "
            "método de verificação.",
            "OK",
            "Voltar para o login",
        ),
    ],
)
def test_maintenance_notice_renders_translated_help_and_return_controls(
    locale, help_title, help_message, close_label, back_label
):
    app = main.create_app(
        development_settings(database_url="sqlite+pysqlite:///:memory:", maintenance_mode=True)
    )
    try:
        with TestClient(app) as client:
            selected = client.get(f"/locale/{locale}", follow_redirects=False)
            assert selected.status_code == 303
            assert client.cookies[LOCALE_COOKIE_NAME] == locale
            notice = client.get("/")
            assert notice.status_code == 503
            assert notice.headers["cache-control"] == "no-store"
            assert f'<html lang="{locale}">' in notice.text
            assert f'data-modal-title="{help_title}"' in notice.text
            assert f'data-modal-message="{help_message}"' in notice.text
            assert f">{help_title}</button>" in notice.text
            assert f"data-modal-close>{close_label}</button>" in notice.text
            assert f'class="auth-back-link" href="/">{back_label}</a>' in notice.text
    finally:
        app.state.database_engine.dispose()
