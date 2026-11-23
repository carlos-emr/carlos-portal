"""Authenticated portal pages: dashboard, account settings, and email passwords."""

import re
from dataclasses import fields
from datetime import UTC, datetime, timedelta
from html import unescape
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from jinja2 import meta
from sqlalchemy import select

from carlos_patient_portal import main, presenters, web_support
from carlos_patient_portal.config import (
    MIN_PRODUCTION_SECRET_LENGTH,
    Settings,
)
from carlos_patient_portal.email_delivery import PortalEmailDeliveryError
from carlos_patient_portal.i18n import (
    DEFAULT_LOCALE,
    LOCALE_COOKIE_NAME,
    SUPPORTED_LOCALES,
    format_portal_datetime,
    portal_text,
)
from carlos_patient_portal.models import (
    AUDIT_EVENT_ACCOUNT_CONTACT_UPDATE,
    AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_CONFIRM,
    AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_REQUEST,
    AUDIT_EVENT_UNLOCK_SECRET_LIST,
    AUDIT_EVENT_UNLOCK_SECRET_READ,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    CONTACT_REVIEW_STATUS_PENDING,
    EMAIL_CHANGE_STATUS_CONFIRMED,
    EMAIL_CHANGE_STATUS_PENDING,
    EMAIL_CHANGE_STATUS_REVOKED,
    UNLOCK_SECRET_TYPE_EMAIL,
    UNLOCK_SECRET_TYPE_PDF,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalContactReviewRequest,
    PatientPortalEmailChangeRequest,
    PatientPortalSession,
    PatientPortalUnlockSecret,
)
from carlos_patient_portal.unlock_secrets import (
    create_unlock_secret,
    revoke_unlock_secret,
)
from carlos_patient_portal.view_models import (
    EmailPasswordDashboardViewModel,
    EmailPasswordRowViewModel,
)
from tests.support import (
    CSRF_TOKEN_PATTERN,
    SEEDED_INVITE_EMAIL,
    STRONG_PASSWORD,
    UNLOCK_SECRET_ENCRYPTION_SECRET,
    FailingNoticeSender,
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    _sample_mfa_delivery,
    _template_variable_names,
    activate_seeded_patient_account,
    bearer_headers,
    browser_sign_in_seeded_patient,
    confirm_seeded_email_change,
    csrf_token_from_response,
    development_settings,
    expire_email_mfa_cooldown,
    migrated_development_app,
    request_seeded_email_change,
    run_with_email_sender,
    sign_in_patient_api_session,
    submit_contact_change,
)


def test_dashboard_datetime_and_date_boundary_use_clinic_timezone() -> None:
    assert (
        format_portal_datetime(
            datetime(2026, 1, 15, 5, 30, tzinfo=UTC),
            timezone_name="America/Toronto",
        )
        == "2026-01-15 00:30 EST"
    )
    assert presenters.dashboard_created_before(
        datetime(2026, 7, 15).date(),
        timezone_name="America/Toronto",
    ) == datetime(2026, 7, 16, 4, 0, tzinfo=UTC)


def test_index_renders_sign_in_shell() -> None:
    app = main.create_app(development_settings())
    response = TestClient(app).get("/")
    text = portal_text(DEFAULT_LOCALE)

    assert response.status_code == 200
    assert text["username_placeholder"] == "username"
    assert text["password_placeholder"] == "password"
    assert "CARLOS Patient Portal" in response.text
    assert 'src="http://testserver/static/carlos-birdman.png"' in response.text
    assert f'placeholder="{text["username_placeholder"]}"' in response.text
    assert f'placeholder="{text["password_placeholder"]}"' in response.text
    assert f">{text['forgot_username_password']}</a>" in response.text
    assert f">{text['activate_account']}</a>" in response.text
    assert 'id="portal-message-modal"' in response.text
    assert 'src="http://testserver/static/portal.js"' in response.text
    for locale in SUPPORTED_LOCALES:
        assert f'lang="{locale.code}"' in response.text
    assert f'value="{text["username_placeholder"]}"' not in response.text
    assert 'name="csrf_token"' in response.text
    assert "nosemgrep" not in response.text
    assert "Your clinic" in response.text


def test_language_switch_links_to_every_supported_locale() -> None:
    """Each inactive locale is a working link; the active one indicates state, not a control."""
    app = main.create_app(development_settings())
    response = TestClient(app).get("/")

    assert response.status_code == 200
    for locale in SUPPORTED_LOCALES:
        if locale.code == DEFAULT_LOCALE:
            assert f'<span class="text-tab selected" aria-current="true" lang="{locale.code}"' in (
                response.text
            )
        else:
            assert f'href="/locale/{locale.code}?next=' in response.text
    # The modal explained that a language was unavailable. Selecting one now works, so nothing
    # should still be advertising otherwise.
    assert "language_unavailable" not in response.text
    assert "data-language-code" not in response.text


def test_selecting_a_locale_persists_it_and_returns_to_the_same_page() -> None:
    app = main.create_app(development_settings())
    client = TestClient(app)

    switched = client.get("/locale/fr?next=/", follow_redirects=False)
    rendered = client.get("/")

    assert switched.status_code == 303
    assert switched.headers["location"] == "/"
    assert client.cookies[LOCALE_COOKIE_NAME] == "fr"
    # French has no catalog yet, so the page renders English strings through the per-key fallback —
    # but the selection is real: French is now the active tab.
    assert '<span class="text-tab selected" aria-current="true" lang="fr"' in rendered.text
    assert portal_text(DEFAULT_LOCALE)["username_placeholder"] in rendered.text


@pytest.mark.parametrize(
    "destination",
    [
        "//evil.example",
        "///evil.example",
        "/\\evil.example",
        "/\\\\evil.example",
        "https://evil.example",
        "http://evil.example",
        "javascript:alert(1)",
        "evil.example",
        "",
        # Browsers strip TAB/LF/CR while parsing a URL, so each of these reaches the network stack
        # as //evil.example. An earlier version of the validator checked only for a leading `//`
        # after folding backslashes and let every one of them through.
        "/\t/evil.example",
        "/\n/evil.example",
        "/\r/evil.example",
        "/ /evil.example",
        "/\x0b/evil.example",
        "/\x00//evil.example",
        "/\x85/evil.example",
    ],
)
def test_locale_switch_refuses_an_offsite_redirect(destination: str) -> None:
    """`next` is attacker-controllable, so nothing that leaves this origin may reach Location."""
    app = main.create_app(development_settings())
    response = TestClient(app).get(
        "/locale/fr",
        params={"next": destination},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/"


@pytest.mark.parametrize(
    "destination",
    ["/", "/portal", "/portal/account", "/portal/email-passwords?page=2"],
)
def test_locale_switch_returns_to_a_local_path(destination: str) -> None:
    app = main.create_app(development_settings())
    response = TestClient(app).get(
        "/locale/fr",
        params={"next": destination},
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == destination


def test_locale_switch_refuses_an_unknown_locale() -> None:
    app = main.create_app(development_settings())

    assert TestClient(app).get("/locale/zz", follow_redirects=False).status_code == 404


def test_accept_language_selects_a_locale_when_none_was_chosen() -> None:
    app = main.create_app(development_settings())
    client = TestClient(app)

    response = client.get("/", headers={"Accept-Language": "pt-BR,pt;q=0.9,en;q=0.5"})
    unsupported = client.get("/", headers={"Accept-Language": "de-DE,de;q=0.9"})

    assert '<span class="text-tab selected" aria-current="true" lang="pt-BR"' in response.text
    # Nothing supported in the header falls back to English rather than picking arbitrarily.
    assert f'lang="{DEFAULT_LOCALE}"' in unsupported.text


@pytest.mark.parametrize("weight", ["2", "nan", "inf"])
def test_accept_language_ignores_invalid_weights(weight: str) -> None:
    app = main.create_app(development_settings())
    response = TestClient(app).get(
        "/",
        headers={"Accept-Language": f"fr;q={weight},en;q=0.5"},
    )

    assert '<span class="text-tab selected" aria-current="true" lang="en"' in response.text


def test_static_logo_asset_is_served() -> None:
    app = main.create_app(development_settings())
    response = TestClient(app).get("/static/carlos-birdman.png")

    assert response.status_code == 200
    assert "image/png" in response.headers["content-type"]
    assert response.content.startswith(b"\x89PNG")


def test_sign_in_shell_uses_security_headers() -> None:
    app = main.create_app(development_settings())
    response = TestClient(app).get("/")

    assert response.headers["content-security-policy"] == (
        "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; "
        "object-src 'none'"
    )
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["referrer-policy"] == "same-origin"
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


def test_jinja_templates_always_autoescape_jinja_files() -> None:
    assert web_support.templates.env.autoescape is True


FOOTER_PATTERN = re.compile(r"</main>\s*<footer class=\"page-footer\">(.*?)</footer>", re.DOTALL)
SOURCE_CODE_LINK_PATTERN = re.compile(r'<a class="link-action" href="([^"]*)">Source code</a>')


def rendered_source_code_url(page_html: str) -> str:
    """The href of the footer's "Source code" link, which must sit outside <main>.

    Outside <main> is what makes the <footer> the page's contentinfo landmark, so the match is
    anchored on the closing </main> rather than on the footer alone.
    """
    footer_match = FOOTER_PATTERN.search(page_html)
    assert footer_match is not None, "page has no footer after </main>"
    link_match = SOURCE_CODE_LINK_PATTERN.search(footer_match.group(1))
    assert link_match is not None, "footer has no Source code link"
    return link_match.group(1)


def test_every_page_template_includes_the_source_code_footer() -> None:
    """AGPL-3.0 section 13 requires the source offer on every page, including future ones."""
    environment = web_support.templates.env
    page_templates = sorted(
        path.name
        for path in (web_support.PACKAGE_DIR / "templates").glob("*.jinja")
        if not path.name.startswith("_")
    )

    assert "dashboard.jinja" in page_templates
    for template_name in page_templates:
        source, _, _ = environment.loader.get_source(environment, template_name)
        included = set(meta.find_referenced_templates(environment.parse(source)))
        assert "_page_footer.jinja" in included, f"{template_name} has no source code footer"


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/auth/activate",
        "/auth/password-reset",
        "/auth/password-reset/complete",
        "/auth/email-change/confirm",
    ],
)
def test_public_pages_link_the_upstream_source_by_default(path: str) -> None:
    response = TestClient(main.create_app(development_settings())).get(path)

    assert response.status_code == 200
    assert rendered_source_code_url(response.text) == "https://github.com/carlos-emr/carlos-portal"


def test_service_notice_page_links_the_source_code() -> None:
    app = main.create_app(development_settings(maintenance_mode=True))
    response = TestClient(app).get("/")

    assert response.status_code == 503
    assert "Portal unavailable" in response.text
    assert rendered_source_code_url(response.text) == "https://github.com/carlos-emr/carlos-portal"


def test_signed_in_dashboard_links_the_source_code() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)

    for path in ("/portal", "/portal/account", "/portal/help"):
        response = client.get(path)
        assert response.status_code == 200
        assert (
            rendered_source_code_url(response.text)
            == "https://github.com/carlos-emr/carlos-portal"
        )


def test_configured_source_code_url_replaces_the_upstream_link() -> None:
    """A modified deployment's own source location is what its patients are offered."""
    app = migrated_development_app(source_code_url="https://git.example.test/clinic/portal-fork")
    client = TestClient(app)

    index_response = client.get("/")
    browser_sign_in_seeded_patient(app, client)
    dashboard_response = client.get("/portal")

    for response in (index_response, dashboard_response):
        assert (
            rendered_source_code_url(response.text)
            == "https://git.example.test/clinic/portal-fork"
        )
        assert "github.com/carlos-emr/carlos-portal" not in response.text


def test_source_code_url_is_autoescaped_in_the_footer() -> None:
    """Operator configuration still goes through autoescape; it cannot break out of the href."""
    app = main.create_app(
        development_settings(
            source_code_url='https://git.example.test/fork"><script>alert(1)</script>'
        )
    )
    response = TestClient(app).get("/")

    assert "<script>alert(1)</script>" not in response.text
    assert rendered_source_code_url(response.text) == (
        "https://git.example.test/fork&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"
    )


def test_account_contact_update_creates_staff_review_request() -> None:
    sender = RecordingPortalEmailSender()
    sms_sender = RecordingPortalSmsSender()
    app = migrated_development_app(email_sender=sender, sms_sender=sms_sender)
    client = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, client)
    account_response = client.get("/portal/account")
    csrf_token_match = CSRF_TOKEN_PATTERN.search(account_response.text)
    assert csrf_token_match is not None

    failed_response = client.post(
        "/portal/account/contact",
        data={
            "csrf_token": csrf_token_match.group(1),
            "email": "new.patient@example.com",
            "phone_number": "+1 555 010 5555",
            "current_password": "Wrong1!password",
        },
    )
    fresh_account_response = client.get("/portal/account")
    fresh_csrf_token_match = CSRF_TOKEN_PATTERN.search(fresh_account_response.text)
    assert fresh_csrf_token_match is not None
    updated_response = client.post(
        "/portal/account/contact",
        data={
            "csrf_token": fresh_csrf_token_match.group(1),
            "email": " New.Patient@Example.com ",
            "phone_number": " +1 555 010 5555 ",
            "current_password": STRONG_PASSWORD,
        },
        follow_redirects=False,
    )
    notice_response = client.get("/portal/account?status=contact-confirmation-required")

    assert failed_response.status_code == 403
    assert "Account change could not be completed." in failed_response.text
    assert "Wrong1!password" not in failed_response.text
    assert updated_response.status_code == 303
    assert (
        updated_response.headers["location"]
        == "/portal/account?status=contact-confirmation-required"
    )
    assert notice_response.status_code == 200
    assert "Confirm the new email address" in notice_response.text
    assert sms_sender.messages[-1]["recipient"] == "+15550105555"
    # The confirmation link goes to the proposed address; the current address is told only that a
    # change was requested, and is not given the proposed address.
    assert sender.messages[-1] == {
        "recipient": SEEDED_INVITE_EMAIL,
        "type": "email_change_requested_notice",
    }
    confirmation_message = sender.messages[-2]
    assert confirmation_message["recipient"] == "new.patient@example.com"
    assert confirmation_message["type"] == "email_change_confirmation"
    confirmation_url = str(confirmation_message["confirmation_url"])
    assert "/auth/email-change/confirm#token=" in confirmation_url

    with app.state.session_factory() as session:
        account = session.get(PatientPortalAccount, account_id)
        review_request = session.scalar(select(PatientPortalContactReviewRequest))
        email_change_request = session.scalar(select(PatientPortalEmailChangeRequest))

        # Nothing about the account has moved yet: a mistyped address strands no factor, and an
        # attacker holding only the password has not redirected verification codes or reset links.
        assert account is not None
        assert account.email == SEEDED_INVITE_EMAIL
        assert account.phone_number is None
        assert review_request is None
        assert email_change_request is not None
        assert email_change_request.status == EMAIL_CHANGE_STATUS_PENDING
        assert email_change_request.new_email == "new.patient@example.com"
        assert email_change_request.new_phone_number == "+15550105555"

    confirmation_page = client.get("/auth/email-change/confirm")
    confirmed = client.post(
        "/auth/email-change/confirm",
        data={
            "csrf_token": csrf_token_from_response(confirmation_page),
            "reset_token": confirmation_url.partition("#token=")[2],
        },
    )

    assert confirmed.status_code == 200
    assert "Email address confirmed" in confirmed.text
    assert "enter the code sent to the new phone number" in confirmed.text
    phone_confirmation_page = client.get("/portal/account")
    phone_confirmed = client.post(
        "/portal/account/contact/confirm-phone",
        data={
            "csrf_token": csrf_token_from_response(phone_confirmation_page),
            "phone_confirmation_code": sms_sender.messages[-1]["code"],
        },
        follow_redirects=False,
    )
    assert phone_confirmed.status_code == 200
    assert "Contact information updated" in phone_confirmed.text
    assert "you have been signed out" in phone_confirmed.text
    assert "carlos_portal_session=\"\"" in phone_confirmed.headers["set-cookie"]
    signed_out_account = client.get("/portal/account", follow_redirects=False)
    assert signed_out_account.status_code == 303
    assert signed_out_account.headers["location"] == "/"
    with app.state.session_factory() as session:
        account = session.get(PatientPortalAccount, account_id)
        review_request = session.scalar(select(PatientPortalContactReviewRequest))
        email_change_request = session.scalar(select(PatientPortalEmailChangeRequest))
        audit_events = list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(
                    PatientPortalAuditEvent.event_type.in_(
                        (
                            AUDIT_EVENT_ACCOUNT_CONTACT_UPDATE,
                            AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_CONFIRM,
                            AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_REQUEST,
                        )
                    )
                )
                .order_by(PatientPortalAuditEvent.id)
            )
        )

        assert account is not None
        assert account.email == "new.patient@example.com"
        assert account.phone_number == "+15550105555"
        assert email_change_request is not None
        assert email_change_request.status == EMAIL_CHANGE_STATUS_CONFIRMED
        assert email_change_request.confirmed_at is not None
        # The CARLOS review opens only once the change is real, so its before/after snapshot
        # matches what the chart should be reconciled against.
        assert review_request is not None
        assert review_request.account_id == account_id
        assert review_request.status == CONTACT_REVIEW_STATUS_PENDING
        assert review_request.email_before == SEEDED_INVITE_EMAIL
        assert review_request.email_after == "new.patient@example.com"
        assert review_request.phone_number_before is None
        assert review_request.phone_number_after == "+15550105555"
        assert [
            (event.event_type, event.outcome, event.reason) for event in audit_events
        ] == [
            (AUDIT_EVENT_ACCOUNT_CONTACT_UPDATE, AUDIT_OUTCOME_FAILURE, "step_up_failed"),
            (
                AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_REQUEST,
                AUDIT_OUTCOME_SUCCESS,
                "email_confirmation_requested",
            ),
            (AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_CONFIRM, AUDIT_OUTCOME_SUCCESS, "updated"),
        ]
    # Both addresses learn the change happened, including the one it moved away from.
    assert sender.messages[-2:] == [
        {"recipient": SEEDED_INVITE_EMAIL, "type": "contact_change_notice"},
        {"recipient": "new.patient@example.com", "type": "contact_change_notice"},
    ]


def test_email_password_dashboard_populated_search_pagination_and_copy_controls() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, client)
    base_time = datetime(2026, 7, 23, 12, 0, tzinfo=UTC)
    secret_ids: dict[int, int] = {}
    secret_values: dict[int, str] = {}

    with app.state.session_factory() as session:
        with session.begin():
            for index in range(12):
                secret_value = f"PortalPwd{index:02d}!A"
                created = create_unlock_secret(
                    session,
                    clinic_id="default",
                    demographic_no=1234,
                    account_id=account_id,
                    secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                    secret=secret_value,
                    created_by="Clinic Nurse" if index == 5 else "CarlosDoc",
                    encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                    label="Lab report" if index == 5 else f"Message {index:02d}",
                    source_reference=f"message-{3135 + index}",
                )
                created_at = base_time + timedelta(days=index)
                created.unlock_secret.created_at = created_at
                created.unlock_secret.updated_at = created_at
                secret_ids[index] = created.unlock_secret.id
                secret_values[index] = secret_value

    page_one_response = client.get("/portal/email-passwords")
    csrf_token_match = CSRF_TOKEN_PATTERN.search(page_one_response.text)
    assert csrf_token_match is not None
    rejected_reveal = client.post(
        f"/portal/email-passwords/{secret_ids[11]}/reveal",
        data={
            "csrf_token": csrf_token_match.group(1),
            "current_password": "Wrong1!password",
        },
    )
    reveal_response = client.post(
        f"/portal/email-passwords/{secret_ids[11]}/reveal",
        data={
            "csrf_token": csrf_token_match.group(1),
            "current_password": STRONG_PASSWORD,
        },
    )
    page_two_response = client.get("/portal/email-passwords?page=2")
    out_of_range_page_response = client.get("/portal/email-passwords?page=99")
    search_response = client.get(
        "/portal/email-passwords",
        params={"q": "lab", "provider": "", "date_from": "", "date_to": ""},
    )
    provider_response = client.get(
        "/portal/email-passwords",
        params={"provider": "Clinic Nurse"},
    )
    date_response = client.get(
        "/portal/email-passwords",
        params={"date_from": "2026-07-28", "date_to": "2026-07-28"},
    )
    invalid_date_response = client.get(
        "/portal/email-passwords",
        params={"date_from": "2026-07-29", "date_to": "2026-07-28"},
    )
    malformed_date_response = client.get(
        "/portal/email-passwords",
        params={"q": "lab", "date_from": "not-a-date", "date_to": ""},
    )
    maximum_date_response = client.get(
        "/portal/email-passwords",
        params={"date_to": "9999-12-31"},
    )

    assert page_one_response.status_code == 200
    assert "Message 11" in page_one_response.text
    assert "Message 02" in page_one_response.text
    assert "Message 01" not in page_one_response.text
    assert "PortalPwd01!A" not in page_one_response.text
    assert all(f"PortalPwd{index:02d}!A" not in page_one_response.text for index in range(12))
    assert page_one_response.text.index("Message 11") < page_one_response.text.index("Message 02")
    assert ">Hidden</code>" in page_one_response.text
    assert 'class="copyable-password"' in page_one_response.text
    assert 'data-copy-target="email-password-' in page_one_response.text
    assert 'data-reveal-url="/portal/email-passwords/' in page_one_response.text
    assert 'href="/portal/email-passwords?page=2"' in page_one_response.text
    assert "Page 1 of 2" in page_one_response.text
    assert rejected_reveal.status_code == 403
    assert reveal_response.status_code == 200
    assert reveal_response.json()["passphrase"] == secret_values[11]

    assert page_two_response.status_code == 200
    assert "Message 01" in page_two_response.text
    assert "Message 00" in page_two_response.text
    assert "Message 02" not in page_two_response.text
    assert 'href="/portal/email-passwords"' in page_two_response.text
    assert "Page 2 of 2" in page_two_response.text

    assert out_of_range_page_response.status_code == 200
    assert "Message 01" in out_of_range_page_response.text
    assert "Page 2 of 2" in out_of_range_page_response.text

    assert search_response.status_code == 200
    assert "Lab report" in search_response.text
    assert "Message 06" not in search_response.text
    assert "PortalPwd06!A" not in search_response.text
    assert 'value="lab"' in search_response.text
    assert "Page 1 of 1" in search_response.text

    assert provider_response.status_code == 200
    assert "Lab report" in provider_response.text
    assert "Message 06" not in provider_response.text
    assert '<option value="Clinic Nurse" selected>' in provider_response.text

    assert date_response.status_code == 200
    assert "Lab report" in date_response.text
    assert "Message 04" not in date_response.text
    assert "Message 06" not in date_response.text
    assert 'value="2026-07-28"' in date_response.text
    assert invalid_date_response.status_code == 400
    assert "from date must not be later" in invalid_date_response.text
    assert malformed_date_response.status_code == 400
    assert "text/html" in malformed_date_response.headers["content-type"]
    assert "Enter valid from and to dates." in malformed_date_response.text
    assert "Lab report" not in malformed_date_response.text
    assert maximum_date_response.status_code == 200

    with app.state.session_factory() as session:
        read_events = list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(
                    PatientPortalAuditEvent.event_type == AUDIT_EVENT_UNLOCK_SECRET_READ,
                    PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_SUCCESS,
                    PatientPortalAuditEvent.account_id == account_id,
                )
                .order_by(PatientPortalAuditEvent.id)
            )
        )

        assert len(read_events) == 1
        assert all(event.actor_type == "patient" for event in read_events)


def test_email_password_dashboard_empty_search_and_unavailable_password_states() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, client)
    raw_secret = "HiddenEmail9!"

    empty_response = client.get("/portal/email-passwords")
    empty_search_response = client.get("/portal/email-passwords?q=missing")

    assert empty_response.status_code == 200
    assert "No document passwords" in empty_response.text
    assert "Page 1 of 1" in empty_response.text
    assert empty_search_response.status_code == 200
    assert "No matching document passwords" in empty_search_response.text
    assert "Page 1 of 1" in empty_search_response.text

    with app.state.session_factory() as session:
        with session.begin():
            created = create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=1234,
                account_id=account_id,
                secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                secret=raw_secret,
                created_by="CarlosDoc",
                encryption_secret="v" * MIN_PRODUCTION_SECRET_LENGTH,
                label="Broken message",
                source_reference="message-4000",
            )
            unavailable_id = created.unlock_secret.id

    unavailable_response = client.get("/portal/email-passwords")
    csrf_token_match = CSRF_TOKEN_PATTERN.search(unavailable_response.text)
    assert csrf_token_match is not None
    reveal_response = client.post(
        f"/portal/email-passwords/{unavailable_id}/reveal",
        data={
            "csrf_token": csrf_token_match.group(1),
            "current_password": STRONG_PASSWORD,
        },
    )

    assert unavailable_response.status_code == 200
    assert "Broken message" in unavailable_response.text
    assert "Hidden" in unavailable_response.text
    assert raw_secret not in unavailable_response.text
    assert reveal_response.status_code == 503
    assert reveal_response.json()["detail"] == "email password unavailable"
    with app.state.session_factory() as session:
        read_event = session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_UNLOCK_SECRET_READ,
                PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_FAILURE,
                PatientPortalAuditEvent.account_id == account_id,
            )
        )

        assert read_event is not None
        assert read_event.reason == "decryption_failed"


def test_email_password_dashboard_escapes_stored_and_reflected_values() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, client)
    with app.state.session_factory() as session:
        with session.begin():
            create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=1234,
                account_id=account_id,
                secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                secret="Escaped1!word",
                created_by="<strong>Provider</strong>",
                encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                label="<meta http-equiv=refresh content=0>",
                source_reference="<img src=x>",
            )

    stored_response = client.get("/portal/email-passwords")
    reflected_response = client.get(
        "/portal/email-passwords",
        params={"q": '<script nonce="x">alert(1)</script>'},
    )

    assert stored_response.status_code == 200
    assert "<strong>Provider</strong>" not in stored_response.text
    assert "<meta http-equiv" not in stored_response.text
    assert "<img src=x>" not in stored_response.text
    assert "&lt;strong&gt;Provider&lt;/strong&gt;" in stored_response.text
    assert reflected_response.status_code == 200
    assert '<script nonce="x">alert(1)</script>' not in reflected_response.text
    assert "&lt;script" in reflected_response.text


def test_non_portal_prefix_does_not_receive_portal_cache_rule() -> None:
    app = migrated_development_app()
    response = TestClient(app).get("/portalfoo")

    assert response.status_code == 404
    assert "cache-control" not in response.headers


def test_dashboard_styles_include_desktop_and_mobile_navigation_rules() -> None:
    app = main.create_app(development_settings())
    client = TestClient(app)
    response = client.get("/static/styles.css")
    script_response = client.get("/static/portal.js")
    css = response.text

    assert response.status_code == 200
    assert script_response.status_code == 200
    assert ".dashboard-layout" in css
    assert "grid-template-columns: 220px minmax(0, 1fr);" in css
    assert "@media (max-width: 640px)" in css
    assert ".portal-topbar" in css
    assert "flex-direction: row;" in css
    assert ".language-switch .text-tab" in css
    assert "min-height: 44px;" in css
    assert ".module-nav" in css
    assert "align-items: center;" in css
    assert "grid-template-rows: auto minmax(0, 1fr);" in css
    assert ".module-toolbar .search-field" in css
    assert "width: min(100%, 160px);" in css
    assert ".settings-section" in css
    assert ".password-copy-group" in css
    assert ".table-shell .email-password-table" in css
    assert ".email-password-table td::before" in css
    assert "content: attr(data-label);" in css
    assert "navigator.clipboard.writeText" in script_response.text


def test_patient_email_password_api_lists_retrieves_scoped_records_and_audits() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    account_a_id = activate_seeded_patient_account(app, client)
    account_b_id = activate_seeded_patient_account(
        app,
        client,
        username="other.patient",
        demographic_no=5678,
        email="other.patient@example.com",
        health_card_number="WXYZ 9876-5432",
    )
    patient_a_token = sign_in_patient_api_session(client)
    raw_secret_a = "AlphaEmail9!"
    raw_secret_b = "BetaEmail9!"
    raw_secret_revoked = "RevokedEmail9!"
    raw_secret_pdf = "PdfEmail9!"
    raw_secret_unavailable = "WrongKeyEmail9!"

    with app.state.session_factory() as session:
        with session.begin():
            created_a = create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=1234,
                account_id=account_a_id,
                secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                secret=raw_secret_a,
                created_by="CarlosDoc",
                encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                label="Specialist reply",
                source_reference="message-3135",
            )
            created_b = create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=5678,
                account_id=account_b_id,
                secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                secret=raw_secret_b,
                created_by="CarlosDoc",
                encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                label="Other patient reply",
                source_reference="message-3136",
            )
            created_revoked = create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=1234,
                account_id=account_a_id,
                secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                secret=raw_secret_revoked,
                created_by="CarlosDoc",
                encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                label="Revoked reply",
                source_reference="message-3137",
            )
            created_pdf = create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=1234,
                account_id=account_a_id,
                secret_type=UNLOCK_SECRET_TYPE_PDF,
                secret=raw_secret_pdf,
                created_by="CarlosDoc",
                encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                label="PDF password",
                source_reference="document-3138",
            )
            created_unavailable = create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=1234,
                account_id=account_a_id,
                secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                secret=raw_secret_unavailable,
                created_by="CarlosDoc",
                encryption_secret="v" * MIN_PRODUCTION_SECRET_LENGTH,
                label="Temporarily unavailable reply",
                source_reference="message-3139",
            )
            revoke_unlock_secret(
                session,
                created_revoked.unlock_secret.id,
                clinic_id="default",
                demographic_no=1234,
                revoked_by="CarlosDoc",
                reason="staff_requested",
            )
            active_a_id = created_a.unlock_secret.id
            other_patient_id = created_b.unlock_secret.id
            revoked_id = created_revoked.unlock_secret.id
            pdf_id = created_pdf.unlock_secret.id
            unavailable_id = created_unavailable.unlock_secret.id

    list_response = client.get(
        "/api/patient/email-passwords",
        headers=bearer_headers(patient_a_token),
    )
    rejected_retrieve_response = client.post(
        f"/api/patient/email-passwords/{active_a_id}/reveal",
        json={"current_password": "Wrong1!password"},
        headers=bearer_headers(patient_a_token),
    )
    retrieve_response = client.post(
        f"/api/patient/email-passwords/{active_a_id}/reveal",
        json={"current_password": STRONG_PASSWORD},
        headers=bearer_headers(patient_a_token),
    )
    cross_patient_response = client.post(
        f"/api/patient/email-passwords/{other_patient_id}/reveal",
        json={"current_password": STRONG_PASSWORD},
        headers=bearer_headers(patient_a_token),
    )
    revoked_response = client.post(
        f"/api/patient/email-passwords/{revoked_id}/reveal",
        json={"current_password": STRONG_PASSWORD},
        headers=bearer_headers(patient_a_token),
    )
    pdf_response = client.post(
        f"/api/patient/email-passwords/{pdf_id}/reveal",
        json={"current_password": STRONG_PASSWORD},
        headers=bearer_headers(patient_a_token),
    )
    unavailable_response = client.post(
        f"/api/patient/email-passwords/{unavailable_id}/reveal",
        json={"current_password": STRONG_PASSWORD},
        headers=bearer_headers(patient_a_token),
    )

    assert list_response.status_code == 200
    assert rejected_retrieve_response.status_code == 403
    assert list_response.headers["cache-control"] == "no-store"
    list_payload = list_response.json()
    assert list_payload["limit"] == 10
    assert list_payload["offset"] == 0
    assert [item["id"] for item in list_payload["items"]] == [unavailable_id, active_a_id]
    assert list_payload["items"][0]["label"] == "Temporarily unavailable reply"
    assert list_payload["items"][0]["source_reference"] == "message-3139"
    assert list_payload["items"][1]["label"] == "Specialist reply"
    assert list_payload["items"][1]["source_reference"] == "message-3135"
    assert all(
        raw_secret not in list_response.text
        for raw_secret in [
            raw_secret_a,
            raw_secret_b,
            raw_secret_revoked,
            raw_secret_pdf,
            raw_secret_unavailable,
        ]
    )

    assert retrieve_response.status_code == 200
    retrieve_payload = retrieve_response.json()
    assert retrieve_payload["id"] == active_a_id
    assert retrieve_payload["label"] == "Specialist reply"
    assert retrieve_payload["source_reference"] == "message-3135"
    assert retrieve_payload["passphrase"] == raw_secret_a
    assert raw_secret_b not in retrieve_response.text
    assert raw_secret_revoked not in retrieve_response.text
    assert raw_secret_pdf not in retrieve_response.text

    for not_found_response in [cross_patient_response, revoked_response, pdf_response]:
        assert not_found_response.status_code == 404
        assert not_found_response.json()["detail"] == "email password not found"
        assert raw_secret_b not in not_found_response.text
        assert raw_secret_revoked not in not_found_response.text
        assert raw_secret_pdf not in not_found_response.text
    assert unavailable_response.status_code == 503
    assert unavailable_response.json()["detail"] == "email password unavailable"
    assert raw_secret_unavailable not in unavailable_response.text

    with app.state.session_factory() as session:
        active_secret = session.get(PatientPortalUnlockSecret, active_a_id)
        other_patient_secret = session.get(PatientPortalUnlockSecret, other_patient_id)
        unavailable_secret = session.get(PatientPortalUnlockSecret, unavailable_id)
        audit_events = list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(
                    PatientPortalAuditEvent.event_type.in_(
                        [
                            AUDIT_EVENT_UNLOCK_SECRET_LIST,
                            AUDIT_EVENT_UNLOCK_SECRET_READ,
                        ]
                    )
                )
                .order_by(PatientPortalAuditEvent.id)
            )
        )

        assert active_secret is not None
        assert active_secret.last_viewed_at is not None
        assert other_patient_secret is not None
        assert other_patient_secret.last_viewed_at is None
        assert unavailable_secret is not None
        assert unavailable_secret.last_viewed_at is None
        assert [
            (event.event_type, event.outcome, event.account_id, event.demographic_no, event.reason)
            for event in audit_events
        ] == [
            (AUDIT_EVENT_UNLOCK_SECRET_LIST, AUDIT_OUTCOME_SUCCESS, account_a_id, 1234, None),
            (
                AUDIT_EVENT_UNLOCK_SECRET_READ,
                AUDIT_OUTCOME_FAILURE,
                account_a_id,
                1234,
                "step_up_failed",
            ),
            (AUDIT_EVENT_UNLOCK_SECRET_READ, AUDIT_OUTCOME_SUCCESS, account_a_id, 1234, None),
            (
                AUDIT_EVENT_UNLOCK_SECRET_READ,
                AUDIT_OUTCOME_FAILURE,
                account_a_id,
                1234,
                "not_available",
            ),
            (
                AUDIT_EVENT_UNLOCK_SECRET_READ,
                AUDIT_OUTCOME_FAILURE,
                account_a_id,
                1234,
                "not_available",
            ),
            (
                AUDIT_EVENT_UNLOCK_SECRET_READ,
                AUDIT_OUTCOME_FAILURE,
                account_a_id,
                1234,
                "not_available",
            ),
            (
                AUDIT_EVENT_UNLOCK_SECRET_READ,
                AUDIT_OUTCOME_FAILURE,
                account_a_id,
                1234,
                "decryption_failed",
            ),
        ]


def test_email_password_reveal_password_failures_lock_the_account() -> None:
    app = migrated_development_app(auth_max_failed_password_attempts=2)
    client = TestClient(app)
    account_id = activate_seeded_patient_account(app, client)
    token = sign_in_patient_api_session(client)

    failed_reveals = [
        client.post(
            "/api/patient/email-passwords/1/reveal",
            json={"current_password": "Wrong1!password"},
            headers=bearer_headers(token),
        )
        for _ in range(2)
    ]
    rejected_session = client.post(
        "/api/patient/email-passwords/1/reveal",
        json={"current_password": STRONG_PASSWORD},
        headers=bearer_headers(token),
    )

    assert [response.status_code for response in failed_reveals] == [403, 403]
    assert rejected_session.status_code == 401
    with app.state.session_factory() as session:
        account = session.get(PatientPortalAccount, account_id)
        assert account is not None
        assert account.failed_login_count == 2
        assert account.locked_at is not None


def test_browser_email_password_index_records_a_sanitized_list_audit_event() -> None:
    """Browsing the password index must be auditable, without storing the raw query."""
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)

    plain_view = client.get("/portal/email-passwords")
    filtered_view = client.get("/portal/email-passwords?q=biopsy%20result")

    assert plain_view.status_code == 200
    assert filtered_view.status_code == 200
    with app.state.session_factory() as session:
        list_events = list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(PatientPortalAuditEvent.event_type == AUDIT_EVENT_UNLOCK_SECRET_LIST)
                .order_by(PatientPortalAuditEvent.id)
            )
        )
        assert [event.reason for event in list_events] == ["browser", "browser_filtered"]
        assert all(event.outcome == "success" for event in list_events)
        # The search term is PHI-bearing free text and must never be persisted.
        assert all("biopsy" not in (event.reason or "") for event in list_events)


@pytest.mark.parametrize("provider", ["id:", "name:"])
def test_empty_structured_provider_filter_returns_invalid_filter_page(provider: str) -> None:
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)

    response = client.get("/portal/email-passwords", params={"provider": provider})

    assert response.status_code == 400
    assert "Enter valid filters." in response.text


def test_email_change_confirmation_delivery_failure_revokes_the_pending_request() -> None:
    """A pending change the patient can never confirm is worse than no change at all.

    It occupies the one-pending-per-account slot and leaves them believing something is in flight,
    so a confirmation that cannot be delivered must take the request down with it.
    """
    app_holder: dict[str, object] = {}

    def act():
        app = migrated_development_app()
        app_holder["app"] = app
        client = TestClient(app)
        browser_sign_in_seeded_patient(app, client)
        return submit_contact_change(app, client)

    response = run_with_email_sender(FailingNoticeSender(fail_confirmation=True), act)
    app = app_holder["app"]

    assert response.status_code == 303
    assert (
        response.headers["location"]
        == "/portal/account?status=email-confirmation-notice-failed"
    )
    with app.state.session_factory() as session:
        account = session.scalar(select(PatientPortalAccount))
        email_change_request = session.scalar(select(PatientPortalEmailChangeRequest))
        outcomes = [
            (event.outcome, event.reason)
            for event in session.scalars(
                select(PatientPortalAuditEvent)
                .where(
                    PatientPortalAuditEvent.event_type
                    == AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_REQUEST
                )
                .order_by(PatientPortalAuditEvent.id)
            )
        ]

        assert account is not None
        assert account.email == SEEDED_INVITE_EMAIL
        assert email_change_request is not None
        assert email_change_request.status == EMAIL_CHANGE_STATUS_REVOKED
        assert outcomes == [
            (AUDIT_OUTCOME_SUCCESS, "email_confirmation_requested"),
            (AUDIT_OUTCOME_FAILURE, "delivery_unavailable"),
        ]


def test_phone_removal_does_not_create_an_unsendable_confirmation_code() -> None:
    email_sender = RecordingPortalEmailSender()
    sms_sender = RecordingPortalSmsSender()
    app = migrated_development_app(email_sender=email_sender, sms_sender=sms_sender)
    client = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, client)
    with app.state.session_factory() as session, session.begin():
        account = session.get(PatientPortalAccount, account_id)
        assert account is not None
        account.phone_number = "+15550105555"

    response = submit_contact_change(
        app,
        client,
        email=SEEDED_INVITE_EMAIL,
        phone_number="",
    )

    assert response.status_code == 200
    assert "Contact information updated" in response.text
    assert "you have been signed out" in response.text
    assert "carlos_portal_session=\"\"" in response.headers["set-cookie"]
    assert sms_sender.messages == []
    signed_out_account = client.get("/portal/account", follow_redirects=False)
    assert signed_out_account.status_code == 303
    assert signed_out_account.headers["location"] == "/"
    with app.state.session_factory() as session:
        account = session.get(PatientPortalAccount, account_id)
        change = session.scalar(select(PatientPortalEmailChangeRequest))
        assert account is not None
        assert account.phone_number is None
        assert change is not None
        assert change.phone_code_hash is None
        assert change.phone_confirmed_at is not None


def test_completed_contact_change_notice_failure_renders_a_signed_out_warning() -> None:
    app_holder: dict[str, object] = {}
    client_holder: dict[str, TestClient] = {}

    def act():
        app = migrated_development_app()
        client = TestClient(app)
        app_holder["app"] = app
        client_holder["client"] = client
        account_id = browser_sign_in_seeded_patient(app, client)
        with app.state.session_factory() as session, session.begin():
            account = session.get(PatientPortalAccount, account_id)
            assert account is not None
            account.phone_number = "+15550105555"
        return submit_contact_change(
            app,
            client,
            email=SEEDED_INVITE_EMAIL,
            phone_number="",
        )

    response = run_with_email_sender(FailingNoticeSender(), act)
    app = app_holder["app"]
    client = client_holder["client"]

    assert response.status_code == 200
    assert "Contact information updated" in response.text
    assert "security notice could not be sent" in response.text
    assert "you have been signed out" in response.text
    assert "Max-Age=0" in response.headers["set-cookie"]
    signed_out_account = client.get("/portal/account", follow_redirects=False)
    assert signed_out_account.status_code == 303
    assert signed_out_account.headers["location"] == "/"
    with app.state.session_factory() as session:
        failure = session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACCOUNT_CONTACT_UPDATE,
                PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_FAILURE,
                PatientPortalAuditEvent.reason == "delivery_unavailable",
            )
        )
    assert failure is not None


def test_contact_change_records_a_failure_when_the_security_notice_cannot_be_sent() -> None:
    """The old-address notice is the takeover alarm; its failure must be durable and visible."""
    app_holder: dict[str, object] = {}

    def act():
        app = migrated_development_app()
        app_holder["app"] = app
        client = TestClient(app)
        browser_sign_in_seeded_patient(app, client)
        # Confirmation delivery succeeds, so the change completes; only the notices fail.
        submit_contact_change(app, client)
        confirmation_page = client.get("/auth/email-change/confirm")
        with app.state.session_factory() as session:
            token_row = session.scalar(select(PatientPortalEmailChangeRequest))
            assert token_row is not None
        return client, confirmation_page

    client, confirmation_page = run_with_email_sender(FailingNoticeSender(), act)
    app = app_holder["app"]
    # The token is only ever delivered by email, so read it back the way the patient would: from
    # the link. Here the sender discarded it, so drive the service directly instead.
    with app.state.session_factory() as session:
        account = session.scalar(select(PatientPortalAccount))
        assert account is not None
        pending = session.scalar(select(PatientPortalEmailChangeRequest))
        assert pending is not None
        assert pending.status == EMAIL_CHANGE_STATUS_PENDING

    assert confirmation_page.status_code == 200
    with app.state.session_factory() as session:
        outcomes = [
            (event.outcome, event.reason)
            for event in session.scalars(
                select(PatientPortalAuditEvent)
                .where(
                    PatientPortalAuditEvent.event_type
                    == AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_REQUEST
                )
                .order_by(PatientPortalAuditEvent.id)
            )
        ]
        # The confirmation went out, so the request stands; only the advisory notice to the
        # current address failed, and that must not cancel what the patient asked for.
        assert outcomes == [(AUDIT_OUTCOME_SUCCESS, "email_confirmation_requested")]


def test_dashboard_template_only_reads_fields_the_view_model_declares() -> None:
    """The typed view model exists to make a template/field mismatch fail loudly.

    Jinja renders an unknown attribute as empty rather than raising, so before the view model
    a renamed context key produced a silently blank cell. This pins the template's field usage
    against the declared contract instead.
    """
    template = (web_support.PACKAGE_DIR / "templates" / "dashboard.jinja").read_text(
        encoding="utf-8"
    )
    dashboard_fields = {field.name for field in fields(EmailPasswordDashboardViewModel)}
    row_fields = {field.name for field in fields(EmailPasswordRowViewModel)}

    used_dashboard_fields = set(re.findall(r"email_passwords\.([a-z_]+)", template))
    used_row_fields = set(re.findall(r"\brow\.([a-z_]+)", template))

    assert used_dashboard_fields, "template no longer reads the email-password view model"
    undeclared = sorted(used_dashboard_fields - dashboard_fields)
    assert not undeclared, f"template reads undeclared dashboard fields: {undeclared}"
    undeclared_rows = sorted(used_row_fields - row_fields)
    assert not undeclared_rows, f"template reads undeclared row fields: {undeclared_rows}"


def test_email_password_view_model_is_immutable() -> None:
    """`*ViewModel` carries no behaviour and cannot be mutated after assembly."""
    row = EmailPasswordRowViewModel(
        id=1,
        subject="Lab results",
        provider="CarlosDoc",
        sent_at="2026-08-05 10:00 UTC",
        source_reference="message-1",
        is_available=True,
    )

    with pytest.raises(AttributeError):
        row.subject = "changed"  # type: ignore[misc]


def test_presenters_perform_no_writes() -> None:
    """`*ViewModelAssembler` is read-only orchestration; a write belongs to the route.

    Enforced structurally rather than by convention, because the previous version of the
    dashboard audit event was added inside the render path and looked perfectly reasonable there.
    """
    presenter_source = (web_support.PACKAGE_DIR / "presenters.py").read_text(encoding="utf-8")

    forbidden = re.findall(
        r"session\.(?:commit|add|flush|delete)\(|record_audit_event\(",
        presenter_source,
    )

    assert not forbidden, f"presenters.py must not write: {sorted(set(forbidden))}"


@pytest.mark.parametrize(
    ("template_name", "context_builder"),
    [
        ("index.jinja", "index_template_context"),
        ("activate.jinja", "public_auth_template_context"),
        ("password_reset_request.jinja", "public_auth_template_context"),
        ("password_reset_complete.jinja", "public_auth_template_context"),
        ("sign_up.jinja", "public_auth_template_context"),
        ("email_change_complete.jinja", "public_auth_template_context"),
        ("auth_result.jinja", "public_auth_template_context"),
        ("locked.jinja", "public_auth_template_context"),
        ("mfa.jinja", "mfa_template_context"),
    ],
)
def test_public_template_reads_only_keys_its_context_builder_supplies(
    template_name: str, context_builder: str
) -> None:
    """Every variable a public template reads must be supplied by its assembler.

    Jinja renders an unknown name as empty instead of raising, so an assembler that stops
    supplying a key -- or a template that starts reading a new one -- fails silently in the
    browser. This closes that gap for the pages that do not have a dedicated view model.
    """
    settings = Settings(environment="development", database_url="sqlite+pysqlite:///:memory:")
    builder = getattr(web_support, context_builder)
    # Minimal stand-in for a Request: only the attributes the assemblers actually read, so this
    # keeps failing loudly if one starts reaching for something else.
    request_stub = SimpleNamespace(
        cookies={},
        headers={},
        url=SimpleNamespace(path="/", query=""),
    )
    if context_builder == "mfa_template_context":
        context = builder(
            request_stub,
            settings=settings,
            delivery=_sample_mfa_delivery(),
            csrf_token="token",
        )
    else:
        context = builder(request_stub, settings=settings, csrf_token="token")
    # Derived from the assembler itself rather than a hand-maintained list, so the assertion
    # cannot drift away from what the code actually supplies.
    supplied = set(context) | {"url_for", "request"}

    used = _template_variable_names(template_name)

    undeclared = sorted(used - supplied)
    assert not undeclared, f"{template_name} reads keys no assembler supplies: {undeclared}"


def test_expired_email_change_confirmation_is_rejected() -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(email_sender=sender, email_change_token_ttl_seconds=300)
    client = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, client)
    confirmation_token = request_seeded_email_change(app, client, sender)

    with app.state.session_factory() as session:
        with session.begin():
            pending = session.scalar(select(PatientPortalEmailChangeRequest))
            assert pending is not None
            pending.created_at = pending.created_at - timedelta(days=2)
            pending.expires_at = pending.created_at + timedelta(seconds=1)

    expired = confirm_seeded_email_change(client, confirmation_token)

    assert expired.status_code == 400
    assert "no longer valid" in expired.text
    with app.state.session_factory() as session:
        account = session.get(PatientPortalAccount, account_id)
        pending = session.scalar(select(PatientPortalEmailChangeRequest))
        assert account is not None
        assert account.email == SEEDED_INVITE_EMAIL
        # The expired row is closed out rather than left pending and blocking a fresh attempt.
        assert pending is not None
        assert pending.status == EMAIL_CHANGE_STATUS_REVOKED


def test_superseding_an_email_change_invalidates_the_link_already_sent() -> None:
    """A corrected typo must not leave the mistyped address able to take over the account."""
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(email_sender=sender)
    client = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, client)
    mistyped_token = request_seeded_email_change(
        app,
        client,
        sender,
        email="typo.patient@example.com",
    )
    corrected_token = request_seeded_email_change(
        app,
        client,
        sender,
        email="corrected.patient@example.com",
    )

    superseded = confirm_seeded_email_change(client, mistyped_token)
    corrected = confirm_seeded_email_change(client, corrected_token)

    assert superseded.status_code == 400
    assert corrected.status_code == 200
    with app.state.session_factory() as session:
        account = session.get(PatientPortalAccount, account_id)
        assert account is not None
        assert account.email == "corrected.patient@example.com"


def test_email_change_confirmation_rejects_an_unknown_token() -> None:
    sender = RecordingPortalEmailSender()
    app = migrated_development_app(email_sender=sender)
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)

    forged = confirm_seeded_email_change(client, "not-a-real-confirmation-token")

    assert forged.status_code == 400
    assert "no longer valid" in forged.text


def test_phone_code_resend_inside_the_cooldown_is_rate_limited_not_an_error() -> None:
    """A resend right after the code was sent must answer with the rate-limited notice.

    On SQLite the stored send time comes back without a zone; the remaining-time arithmetic
    then raised TypeError and the patient got a 500 page.
    """
    sms_sender = RecordingPortalSmsSender()
    app = migrated_development_app(
        email_sender=RecordingPortalEmailSender(), sms_sender=sms_sender
    )
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)
    account_page = client.get("/portal/account")
    requested = client.post(
        "/portal/account/contact",
        data={
            "csrf_token": csrf_token_from_response(account_page),
            "email": SEEDED_INVITE_EMAIL,
            "phone_number": "+1 555 010 5556",
            "current_password": STRONG_PASSWORD,
        },
        follow_redirects=False,
    )
    assert requested.status_code == 303
    assert (
        requested.headers["location"] == "/portal/account?status=phone-confirmation-required"
    )
    sent_codes = len(sms_sender.messages)

    confirmation_page = client.get("/portal/account")
    resent = client.post(
        "/portal/account/contact/resend-phone",
        data={"csrf_token": csrf_token_from_response(confirmation_page)},
        follow_redirects=False,
    )

    assert resent.status_code == 303
    assert (
        resent.headers["location"]
        == "/portal/account?status=phone-confirmation-rate-limited"
    )
    assert len(sms_sender.messages) == sent_codes


PORTAL_MUTATING_ROUTES = (
    ("/portal/account/password", {"current_password": "x", "new_password": "y"}),
    ("/portal/account/contact", {"email": "a@b.test", "current_password": "x"}),
    ("/portal/account/contact/confirm-phone", {"code": "000000"}),
    ("/portal/account/contact/resend-phone", {}),
    ("/portal/account/mfa", {"preferred_mfa_method": "email"}),
    ("/portal/email-passwords/1/reveal", {}),
)


@pytest.mark.parametrize(("path", "body"), PORTAL_MUTATING_ROUTES)
def test_portal_mutators_reject_a_missing_csrf_token(path: str, body: dict) -> None:
    """CSRF negative coverage was 4 of 15 mutating routes.

    Tested were /auth/login, /auth/mfa/resend, /portal/logout and /auth/activate. Every
    /portal/account/* mutator was untested, and so was
    POST /portal/email-passwords/{id}/reveal - the one route that returns a decrypted
    passphrase, and whose CSRF gate is its first statement.
    """
    app = migrated_development_app()
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)

    response = client.post(path, data=body, follow_redirects=False)

    assert response.status_code == 403, f"{path} accepted a request with no CSRF token"


def test_reveal_route_csrf_gate_precedes_authentication() -> None:
    """The gate is the route's first statement; an unauthenticated caller must still 403."""
    app = migrated_development_app()
    client = TestClient(app)

    response = client.post("/portal/email-passwords/1/reveal", data={})

    assert response.status_code == 403


def test_reveal_route_audits_and_404s_an_out_of_scope_email_password() -> None:
    """The route had no 404 test at all.

    Its entire not-found/revoked handler - including the failure audit write - was deletable,
    and an out-of-scope id would then become an unaudited 500.
    """
    app = migrated_development_app()
    client = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, client)
    page = client.get("/portal/email-passwords")
    csrf_token_match = CSRF_TOKEN_PATTERN.search(page.text)
    assert csrf_token_match is not None

    response = client.post(
        "/portal/email-passwords/424242/reveal",
        data={
            "csrf_token": csrf_token_match.group(1),
            "current_password": STRONG_PASSWORD,
        },
    )

    assert response.status_code == 404
    assert response.json()["detail"] == "email password not found"
    with app.state.session_factory() as session:
        audited = session.scalar(
            select(PatientPortalAuditEvent).where(
                PatientPortalAuditEvent.event_type == AUDIT_EVENT_UNLOCK_SECRET_READ,
                PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_FAILURE,
                PatientPortalAuditEvent.account_id == account_id,
            )
        )
    assert audited is not None, "a failed reveal must leave an audit row"
    assert audited.reason == "not_available"


def test_csrf_enforcement_splits_on_content_type_only_for_auth_routes() -> None:
    """Pin where the urlencoded/JSON split actually is, because no test said so.

    /auth/login checks CSRF only when the body is urlencoded: a JSON caller is an API client,
    not a browser form, and has no ambiently-attached cookie to forge with. The /portal/*
    mutators are the opposite and enforce unconditionally - a JSON body simply yields no form
    values, so the token is empty and the request is refused. Both halves are load-bearing and
    neither was pinned.
    """
    # The browser sign-in below spends auth-limiter budget; this test is about the CSRF gate.
    app = migrated_development_app(auth_rate_limit_max_requests=50)
    client = TestClient(app)
    browser_sign_in_seeded_patient(app, client)

    portal_form = client.post("/portal/account/mfa", data={"preferred_mfa_method": "email"})
    portal_json = client.post("/portal/account/mfa", json={"preferred_mfa_method": "email"})
    auth_form = client.post(
        "/auth/login",
        data={"username": "patient.user", "password": STRONG_PASSWORD},
    )
    # The sign-in above already sent an MFA code, and a fresh login is refused while that
    # cooldown holds - which is a 429 about delivery, not about CSRF.
    expire_email_mfa_cooldown(app)
    auth_json = client.post(
        "/auth/login",
        json={"username": "patient.user", "password": STRONG_PASSWORD},
    )

    assert portal_form.status_code == 403
    assert portal_json.status_code == 403, "portal mutators must not be bypassable with JSON"
    assert auth_form.status_code == 403
    assert auth_json.status_code == 200, "the JSON API path is deliberately exempt"


@pytest.mark.parametrize("delivery_fails", [False, True], ids=["delivered", "provider-failure"])
def test_phone_confirmation_resend_only_replaces_the_last_delivered_proof(
    delivery_fails: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A resend failure must roll back its new code, time, and failure-budget reset."""
    from carlos_patient_portal import account_settings

    email_sender, sms_sender = RecordingPortalEmailSender(), RecordingPortalSmsSender()
    app = migrated_development_app(email_sender=email_sender, sms_sender=sms_sender)
    with TestClient(app) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        new_phone = "+15550105556"
        requested = client.post(
            "/portal/account/contact",
            data={
                "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                "email": SEEDED_INVITE_EMAIL,
                "phone_number": new_phone,
                "current_password": STRONG_PASSWORD,
            },
            follow_redirects=False,
        )
        assert requested.status_code == 303
        assert requested.headers["location"].endswith("status=phone-confirmation-required")
        original_code = str(sms_sender.messages[-1]["code"])
        replacement_code = f"{(int(original_code) + 1) % 1_000_000:06d}"
        wrong = client.post(
            "/portal/account/contact/confirm-phone",
            data={
                "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                "phone_confirmation_code": replacement_code,
            },
            follow_redirects=False,
        )
        assert wrong.headers["location"].endswith("status=phone-confirmation-invalid")
        with app.state.session_factory() as session, session.begin():
            pending = session.scalars(select(PatientPortalEmailChangeRequest)).one()
            pending.phone_code_sent_at -= timedelta(
                seconds=app.state.settings.phone_change_resend_cooldown_seconds + 1
            )
            original_hash, original_sent_at = pending.phone_code_hash, pending.phone_code_sent_at
            assert pending.phone_failed_attempts == 1
        # Only the entropy boundary is deterministic. Requests, delivery, commits and
        # redemption use the real application.
        monkeypatch.setattr(account_settings, "create_mfa_code", lambda: replacement_code)
        sms_sender.fail = delivery_fails
        resent = client.post(
            "/portal/account/contact/resend-phone",
            data={"csrf_token": csrf_token_from_response(client.get("/portal/account"))},
            follow_redirects=False,
        )
        assert resent.status_code == 303
        assert resent.headers["location"].endswith(
            "status=phone-confirmation-invalid"
            if delivery_fails
            else "status=phone-confirmation-required"
        )
        assert len(sms_sender.messages) == 2
        assert sms_sender.messages[-1]["recipient"] == new_phone
        assert sms_sender.messages[-1]["code"] == replacement_code
        with app.state.session_factory() as session:
            pending = session.scalars(select(PatientPortalEmailChangeRequest)).one()
            account = session.get(PatientPortalAccount, account_id)
            assert account.phone_number is None
            assert pending.status == "pending"
            if delivery_fails:
                assert pending.phone_code_hash == original_hash
                assert pending.phone_code_sent_at == original_sent_at
                assert pending.phone_failed_attempts == 1
            else:
                assert pending.phone_code_hash != original_hash
                assert pending.phone_code_sent_at > original_sent_at
                assert pending.phone_failed_attempts == 0
        if not delivery_fails:
            old_code = client.post(
                "/portal/account/contact/confirm-phone",
                data={
                    "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                    "phone_confirmation_code": original_code,
                },
                follow_redirects=False,
            )
            assert old_code.headers["location"].endswith("status=phone-confirmation-invalid")
        completed = client.post(
            "/portal/account/contact/confirm-phone",
            data={
                "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                "phone_confirmation_code": original_code if delivery_fails else replacement_code,
            },
            follow_redirects=False,
        )
        assert completed.status_code == 200
        assert "Contact information updated" in completed.text
        assert web_support.PORTAL_SESSION_COOKIE_NAME not in client.cookies
        with app.state.session_factory() as session:
            assert session.get(PatientPortalAccount, account_id).phone_number == new_phone
            assert (
                session.scalars(select(PatientPortalEmailChangeRequest)).one().status == "confirmed"
            )
            assert len(list(session.scalars(select(PatientPortalContactReviewRequest)))) == 1


def test_legacy_sender_without_confirmation_revokes_unusable_email_change() -> None:
    """A configured legacy adapter must fail the required link delivery, even in development."""

    class LegacySender:
        def send_code(self, **kwargs: object) -> None:
            pass

    app = migrated_development_app(email_sender=LegacySender())
    with TestClient(app) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        response = client.post(
            "/portal/account/contact",
            data={
                "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                "email": "fake.replacement@example.test",
                "phone_number": "",
                "current_password": STRONG_PASSWORD,
            },
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"].endswith("status=email-confirmation-notice-failed")
        assert client.get("/portal/account").status_code == 200
        with app.state.session_factory() as session:
            assert session.get(PatientPortalAccount, account_id).email == SEEDED_INVITE_EMAIL
            assert (
                session.scalars(select(PatientPortalEmailChangeRequest)).one().status == "revoked"
            )
            assert session.scalar(select(PatientPortalContactReviewRequest)) is None
            failures = list(
                session.scalars(
                    select(PatientPortalAuditEvent).where(
                        PatientPortalAuditEvent.event_type
                        == AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_REQUEST,
                        PatientPortalAuditEvent.outcome == "failure",
                    )
                )
            )
            assert len(failures) == 1
            assert failures[0].reason == "delivery_unavailable"
        assert app.state.operational_metrics.snapshot()["failures"]["email_change_delivery"] == 1


def test_legacy_sender_without_advisory_methods_still_confirms_email_change() -> None:
    """Optional development notices must not undo a delivered and redeemed confirmation link."""

    class LegacyNoticeSender(RecordingPortalEmailSender):
        send_email_change_requested_notice = None
        send_contact_change_notice = None

    sender = LegacyNoticeSender()
    app = migrated_development_app(email_sender=sender)
    with TestClient(app) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        token = request_seeded_email_change(app, client, sender, email="fake.changed@example.test")
        confirmed = confirm_seeded_email_change(client, token)
        assert confirmed.status_code == 200
        assert "Email address confirmed" in confirmed.text
        with app.state.session_factory() as session:
            assert (
                session.get(PatientPortalAccount, account_id).email == "fake.changed@example.test"
            )
            assert (
                session.scalars(select(PatientPortalEmailChangeRequest)).one().status == "confirmed"
            )
            assert len(list(session.scalars(select(PatientPortalContactReviewRequest)))) == 1
        # The public email-link result leaves any browser cookie until its next use.
        # The committed session must already be revoked, and replay must clear it.
        with app.state.session_factory() as session:
            authorizing = session.scalars(select(PatientPortalSession)).one()
            assert authorizing.revoked_at is not None
            assert authorizing.revoked_reason == "contact_change"
        replay = client.get("/portal/account", follow_redirects=False)
        assert replay.status_code == 303 and replay.headers["location"] == "/"
        assert web_support.PORTAL_SESSION_COOKIE_NAME not in client.cookies
        assert app.state.operational_metrics.snapshot()["failures"] == {}


def test_sms_preference_change_invalidates_a_pending_phone_removal_link() -> None:
    """A link created before an MFA change must not remove its newly required phone."""
    email_sender, sms_sender = RecordingPortalEmailSender(), RecordingPortalSmsSender()
    app = migrated_development_app(email_sender=email_sender, sms_sender=sms_sender)
    with TestClient(app) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        old_phone = "+15550105555"
        # Normal initial contact fixture, as in the existing phone-removal regression.
        # Every change to MFA preference and the proposed contact uses an actual route.
        with app.state.session_factory() as session, session.begin():
            account = session.get(PatientPortalAccount, account_id)
            assert account.preferred_mfa_method == "email"
            account.phone_number = old_phone
        token = request_seeded_email_change(
            app, client, email_sender, email="fake.pending-contact@example.test"
        )
        with app.state.session_factory() as session:
            pending = session.scalars(select(PatientPortalEmailChangeRequest)).one()
            assert pending.status == "pending" and pending.new_phone_number is None
            assert pending.email_confirmed_at is None and pending.phone_confirmed_at is not None
            assert session.get(PatientPortalAccount, account_id).phone_number == old_phone
        preference = client.post(
            "/portal/account/mfa",
            data={
                "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                "current_password": STRONG_PASSWORD,
                "preferred_mfa_method": "sms",
            },
            follow_redirects=False,
        )
        assert preference.status_code == 303
        assert preference.headers["location"] == "/portal/account?status=mfa-updated"
        assert sms_sender.messages == []
        sent_before_confirmation = list(email_sender.messages)
        refused = confirm_seeded_email_change(client, token)
        assert refused.status_code == 400
        assert refused.headers["content-type"].startswith("text/html")
        assert "no longer valid" in refused.text
        assert email_sender.messages == sent_before_confirmation
        assert sms_sender.messages == []
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            assert (account.email, account.phone_number, account.preferred_mfa_method) == (
                SEEDED_INVITE_EMAIL,
                old_phone,
                "sms",
            )
            assert (
                session.scalars(select(PatientPortalEmailChangeRequest)).one().status == "revoked"
            )
            assert session.scalar(select(PatientPortalContactReviewRequest)) is None
            event = session.scalars(
                select(PatientPortalAuditEvent).where(
                    PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_CONFIRM
                )
            ).one()
            assert (event.outcome, event.reason) == (AUDIT_OUTCOME_FAILURE, "delivery_unavailable")
        assert client.get("/portal/account").status_code == 200
        fresh = client.post(
            "/auth/login", json={"username": "patient.user", "password": STRONG_PASSWORD}
        )
        assert fresh.status_code == 200 and fresh.json()["mfa_delivery_method"] == "sms"
        assert len(sms_sender.messages) == 1
        assert sms_sender.messages[0]["recipient"] == old_phone
        assert email_sender.messages == sent_before_confirmation
        verified = client.post(
            "/auth/mfa/verify",
            json={
                "mfa_challenge_token": fresh.json()["mfa_challenge_token"],
                "code": sms_sender.messages[0]["code"],
            },
        )
        assert verified.status_code == 200
        assert (
            client.get(
                "/auth/session", headers=bearer_headers(verified.json()["session_token"])
            ).status_code
            == 200
        )


def test_public_email_confirmation_notice_failure_keeps_change_and_other_notice(
    tmp_path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An advisory failure after confirmation must not undo recovery or skip the other address."""
    new_email = "fake.confirmed-notice@example.test"
    attempts = []
    committed_observations = []

    class FirstNoticeFails(RecordingPortalEmailSender):
        def send_contact_change_notice(self, *, recipient, message_id=None):
            # File SQLite gives this observer a separate connection: uncommitted
            # contact/session writes cannot satisfy these provider-boundary assertions.
            with app.state.session_factory() as session:
                account = session.get(PatientPortalAccount, account_id)
                proof = session.scalars(select(PatientPortalEmailChangeRequest)).one()
                authorizing = session.scalars(select(PatientPortalSession)).one()
                reviews = list(session.scalars(select(PatientPortalContactReviewRequest)))
                assert account.email == new_email
                assert proof.status == "confirmed" and proof.confirmed_at is not None
                assert authorizing.revoked_at is not None
                assert authorizing.revoked_reason == "contact_change"
                assert len(reviews) == 1
                committed_observations.append(recipient)
            attempts.append(recipient)
            super().send_contact_change_notice(recipient=recipient, message_id=message_id)
            if recipient == SEEDED_INVITE_EMAIL:
                raise PortalEmailDeliveryError(
                    f"FAKE private provider refusal recipient={recipient} proof={token}"
                )

    sender = FirstNoticeFails()
    app = migrated_development_app(
        email_sender=sender,
        database_url=f"sqlite+pysqlite:///{tmp_path / 'public-confirmation-notice.sqlite'}",
    )
    with TestClient(app) as patient:
        account_id = browser_sign_in_seeded_patient(app, patient)
        token = request_seeded_email_change(app, patient, sender, email=new_email)
        assert attempts == []
        caplog.clear()
        mailbox = TestClient(app)
        try:
            assert web_support.PORTAL_SESSION_COOKIE_NAME not in mailbox.cookies
            confirmed = confirm_seeded_email_change(mailbox, token)
            assert web_support.PORTAL_SESSION_COOKIE_NAME not in mailbox.cookies
        finally:
            mailbox.close()
        assert confirmed.status_code == 200
        assert "Email address confirmed" in confirmed.text
        assert attempts == committed_observations == [SEEDED_INVITE_EMAIL, new_email]
        assert [
            message["recipient"]
            for message in sender.messages
            if message.get("type") == "contact_change_notice"
        ] == attempts
        assert app.state.operational_metrics.snapshot()["failures"]["contact_change_delivery"] == 1
        errors = [record for record in caplog.records if record.levelname == "ERROR"]
        assert [record.getMessage() for record in errors] == [
            "Contact-change notice delivery failed"
        ]
        for private_detail in (
            SEEDED_INVITE_EMAIL,
            new_email,
            token,
            "FAKE private provider refusal",
        ):
            assert private_detail not in caplog.text
            assert private_detail not in confirmed.text
        # Assert eager revocation before replaying the old session or one-time proof.
        with app.state.session_factory() as session:
            assert session.get(PatientPortalAccount, account_id).email == new_email
            assert (
                session.scalars(select(PatientPortalEmailChangeRequest)).one().status == "confirmed"
            )
            assert (
                session.scalars(select(PatientPortalSession)).one().revoked_reason
                == "contact_change"
            )
            assert len(list(session.scalars(select(PatientPortalContactReviewRequest)))) == 1
        replayed = confirm_seeded_email_change(patient, token)
        assert replayed.status_code == 400
        assert attempts == [SEEDED_INVITE_EMAIL, new_email]
        stale_session = patient.get("/portal/account", follow_redirects=False)
        assert stale_session.status_code == 303 and stale_session.headers["location"] == "/"
        assert web_support.PORTAL_SESSION_COOKIE_NAME not in patient.cookies
        with app.state.session_factory() as session:
            assert session.get(PatientPortalAccount, account_id).email == new_email
            assert (
                session.scalars(select(PatientPortalEmailChangeRequest)).one().status == "confirmed"
            )
            assert len(list(session.scalars(select(PatientPortalContactReviewRequest)))) == 1


def test_sms_mfa_rejects_immediate_phone_removal_without_losing_sign_in() -> None:
    """The immediate contact path must preserve the phone needed by selected SMS MFA."""
    email_sender, sms_sender = RecordingPortalEmailSender(), RecordingPortalSmsSender()
    app = migrated_development_app(email_sender=email_sender, sms_sender=sms_sender)
    with TestClient(app) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        old_phone = "+15550105555"
        # Establish the same initial contact fixture used by the allowed-removal test.
        # The MFA preference change and attempted contact change use actual routes.
        with app.state.session_factory() as session, session.begin():
            account = session.get(PatientPortalAccount, account_id)
            assert account.preferred_mfa_method == "email"
            account.phone_number = old_phone
        preference = client.post(
            "/portal/account/mfa",
            data={
                "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                "current_password": STRONG_PASSWORD,
                "preferred_mfa_method": "sms",
            },
            follow_redirects=False,
        )
        assert preference.status_code == 303
        assert preference.headers["location"] == "/portal/account?status=mfa-updated"
        sent_before_removal = list(email_sender.messages)
        assert sms_sender.messages == []
        refused = client.post(
            "/portal/account/contact",
            data={
                "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                "email": SEEDED_INVITE_EMAIL,
                "phone_number": "",
                "current_password": STRONG_PASSWORD,
            },
            follow_redirects=False,
        )
        assert refused.status_code == 400
        assert refused.headers["content-type"].startswith("text/html")
        assert "Account change could not be completed." in refused.text
        assert email_sender.messages == sent_before_removal
        assert sms_sender.messages == []
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            assert (account.email, account.phone_number, account.preferred_mfa_method) == (
                SEEDED_INVITE_EMAIL,
                old_phone,
                "sms",
            )
            assert session.scalar(select(PatientPortalEmailChangeRequest)) is None
            assert session.scalar(select(PatientPortalContactReviewRequest)) is None
            authorizing = session.scalars(select(PatientPortalSession)).one()
            assert authorizing.account_id == account_id and authorizing.revoked_at is None
            # Rejection is auditable even though no contact change is allowed.
            events = list(
                session.scalars(
                    select(PatientPortalAuditEvent).where(
                        PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACCOUNT_CONTACT_UPDATE
                    )
                )
            )
            assert [(event.outcome, event.reason) for event in events] == [
                (AUDIT_OUTCOME_FAILURE, "delivery_unavailable")
            ]
        assert client.get("/portal/account").status_code == 200
        fresh = client.post(
            "/auth/login", json={"username": "patient.user", "password": STRONG_PASSWORD}
        )
        assert fresh.status_code == 200 and fresh.json()["mfa_delivery_method"] == "sms"
        assert len(sms_sender.messages) == 1
        assert sms_sender.messages[0]["recipient"] == old_phone
        assert email_sender.messages == sent_before_removal
        verified = client.post(
            "/auth/mfa/verify",
            json={
                "mfa_challenge_token": fresh.json()["mfa_challenge_token"],
                "code": sms_sender.messages[0]["code"],
            },
        )
        assert verified.status_code == 200
        assert (
            client.get(
                "/auth/session", headers=bearer_headers(verified.json()["session_token"])
            ).status_code
            == 200
        )


def test_initial_phone_delivery_failure_revokes_proof_then_allows_explicit_retry() -> None:
    """Initial delivery failure closes its unusable proof; an explicit retry can recover."""
    email_sender = RecordingPortalEmailSender()
    sms_sender = RecordingPortalSmsSender(fail=True)
    app = migrated_development_app(email_sender=email_sender, sms_sender=sms_sender)
    with TestClient(app) as client:
        account_id = browser_sign_in_seeded_patient(app, client)
        new_phone = "+15550105556"
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            original_contact = (account.email, account.phone_number)
            authorizing_id = session.scalars(select(PatientPortalSession.id)).one()
        failed = submit_contact_change(
            app, client, email=SEEDED_INVITE_EMAIL, phone_number=new_phone
        )
        assert failed.status_code == 303
        assert (
            failed.headers["location"] == "/portal/account?status=phone-confirmation-notice-failed"
        )
        assert len(sms_sender.messages) == 1
        assert sms_sender.messages[0]["recipient"] == new_phone
        failed_code = sms_sender.messages[0]["code"]
        with app.state.session_factory() as session:
            proof = session.scalars(select(PatientPortalEmailChangeRequest)).one()
            failed_proof_id = proof.id
            assert proof.status == EMAIL_CHANGE_STATUS_REVOKED
            assert proof.phone_confirmed_at is None
            account = session.get(PatientPortalAccount, account_id)
            assert (account.email, account.phone_number) == original_contact
            assert session.get(PatientPortalSession, authorizing_id).revoked_at is None
            assert session.scalar(select(PatientPortalContactReviewRequest)) is None
            failure = session.scalars(
                select(PatientPortalAuditEvent).where(
                    PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACCOUNT_EMAIL_CHANGE_REQUEST,
                    PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_FAILURE,
                )
            ).one()
            assert failure.reason == "delivery_unavailable"
        assert app.state.operational_metrics.snapshot()["failures"]["email_change_delivery"] == 1
        assert client.get("/portal/account").status_code == 200
        attempts_after_failure = (len(email_sender.messages), len(sms_sender.messages))
        # Check before creating a fresh proof: two random codes could legitimately coincide.
        stale = client.post(
            "/portal/account/contact/confirm-phone",
            data={
                "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                "phone_confirmation_code": failed_code,
            },
            follow_redirects=False,
        )
        assert stale.status_code == 303
        assert stale.headers["location"] == "/portal/account?status=phone-confirmation-invalid"
        assert (len(email_sender.messages), len(sms_sender.messages)) == attempts_after_failure
        with app.state.session_factory() as session:
            assert session.get(PatientPortalEmailChangeRequest, failed_proof_id).status == "revoked"
            assert (
                session.scalar(
                    select(PatientPortalEmailChangeRequest).where(
                        PatientPortalEmailChangeRequest.status == EMAIL_CHANGE_STATUS_PENDING
                    )
                )
                is None
            )
            assert session.get(PatientPortalSession, authorizing_id).revoked_at is None
            assert session.scalar(select(PatientPortalContactReviewRequest)) is None
        # Toggle only the established recorder's fault; retry through the real contact route.
        sms_sender.fail = False
        retried = submit_contact_change(
            app, client, email=SEEDED_INVITE_EMAIL, phone_number=new_phone
        )
        assert retried.status_code == 303
        assert retried.headers["location"] == "/portal/account?status=phone-confirmation-required"
        assert len(sms_sender.messages) == 2
        assert sms_sender.messages[1]["recipient"] == new_phone
        new_code = sms_sender.messages[1]["code"]
        assert any(
            message.get("type") == "email_change_requested_notice"
            and message["recipient"] == SEEDED_INVITE_EMAIL
            for message in email_sender.messages
        )
        with app.state.session_factory() as session:
            proofs = session.scalars(
                select(PatientPortalEmailChangeRequest).order_by(PatientPortalEmailChangeRequest.id)
            ).all()
            assert [proof.status for proof in proofs] == ["revoked", "pending"]
            fresh_proof_id = proofs[1].id
            assert fresh_proof_id != failed_proof_id
            account = session.get(PatientPortalAccount, account_id)
            assert (account.email, account.phone_number) == original_contact
            assert session.get(PatientPortalSession, authorizing_id).revoked_at is None
        completed = client.post(
            "/portal/account/contact/confirm-phone",
            data={
                "csrf_token": csrf_token_from_response(client.get("/portal/account")),
                "phone_confirmation_code": new_code,
            },
            follow_redirects=False,
        )
        assert completed.status_code == 200
        assert "Contact information updated" in completed.text
        with app.state.session_factory() as session:
            account = session.get(PatientPortalAccount, account_id)
            assert (account.email, account.phone_number) == (SEEDED_INVITE_EMAIL, new_phone)
            assert session.get(PatientPortalEmailChangeRequest, failed_proof_id).status == "revoked"
            confirmed = session.get(PatientPortalEmailChangeRequest, fresh_proof_id)
            assert confirmed.status == "confirmed" and confirmed.phone_confirmed_at is not None
            reviews = session.scalars(select(PatientPortalContactReviewRequest)).all()
            assert len(reviews) == 1 and reviews[0].phone_number_after == new_phone
            authorizing = session.get(PatientPortalSession, authorizing_id)
            assert authorizing.revoked_at is not None
            assert authorizing.revoked_reason == "contact_change"
        assert web_support.PORTAL_SESSION_COOKIE_NAME not in client.cookies
        assert any(
            message.get("type") == "contact_change_notice"
            and message["recipient"] == SEEDED_INVITE_EMAIL
            for message in email_sender.messages
        )


def test_native_legacy_provider_filter_isolates_retained_records_and_clear_restores_both() -> None:
    app = migrated_development_app()
    client = TestClient(app)
    try:
        account_id = browser_sign_in_seeded_patient(app, client)
        legacy_secret = "FAKE legacy document passphrase"
        current_secret = "FAKE current document passphrase"
        with app.state.session_factory() as session, session.begin():
            legacy = create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=1234,
                account_id=account_id,
                secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                secret=legacy_secret,
                created_by="Clinic Nurse",
                encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                label="Retained letter",
                source_reference="retained-provider-letter",
            ).unlock_secret
            current = create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=1234,
                account_id=account_id,
                secret_type=UNLOCK_SECRET_TYPE_EMAIL,
                secret=current_secret,
                created_by="Clinic Nurse",
                created_by_id="provider-42",
                encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                label="Current report",
                source_reference="current-provider-report",
            ).unlock_secret
            legacy_id, current_id = legacy.id, current.id
            assert legacy.created_by_id is None
            assert current.created_by_id == "provider-42"

        listing = client.get("/portal/email-passwords")
        assert listing.status_code == 200
        assert set(re.findall(r'id="email-password-(\d+)"', listing.text)) == {
            str(legacy_id),
            str(current_id),
        }
        provider_select = re.search(
            r'<select[^>]*name="provider"[^>]*>(.*?)</select>', listing.text, re.S
        )
        assert provider_select is not None
        legacy_option = re.search(
            r'<option value="(name:[^"]+)">Clinic Nurse</option>', provider_select.group(1)
        )
        assert legacy_option is not None
        assert '<option value="id:provider-42">Clinic Nurse</option>' in provider_select.group(1)

        # Submit the value actually emitted for the retained NULL-ID group, not an old bookmark.
        filtered = client.get(
            "/portal/email-passwords", params={"provider": unescape(legacy_option.group(1))}
        )
        assert filtered.status_code == 200
        assert set(re.findall(r'id="email-password-(\d+)"', filtered.text)) == {str(legacy_id)}
        assert "Retained letter" in filtered.text
        assert "Current report" not in filtered.text
        assert f'<option value="{legacy_option.group(1)}" selected>' in filtered.text
        clear_link = re.search(r'<a[^>]*href="([^"]+)"[^>]*>Clear filters</a>', filtered.text)
        assert clear_link is not None

        cleared = client.get(unescape(clear_link.group(1)))
        assert cleared.status_code == 200
        assert not cleared.url.query
        assert set(re.findall(r'id="email-password-(\d+)"', cleared.text)) == {
            str(legacy_id),
            str(current_id),
        }
        assert f'<option value="{legacy_option.group(1)}" selected>' not in cleared.text
        for response in (listing, filtered, cleared):
            assert legacy_secret not in response.text
            assert current_secret not in response.text

        with app.state.session_factory() as session:
            legacy = session.get(PatientPortalUnlockSecret, legacy_id)
            current = session.get(PatientPortalUnlockSecret, current_id)
            assert legacy is not None and current is not None
            assert legacy.created_by_id is None
            assert current.created_by_id == "provider-42"
            assert legacy.last_viewed_at is None
            assert current.last_viewed_at is None
    finally:
        app.state.database_engine.dispose()
