"""Self sign-up: the public request page, its uniform response, and encrypted, limited storage.

carlos-portal#15. Every detail below is FAKE: invented health card numbers, dates and addresses on
reserved example domains and documentation IP ranges.
"""

import asyncio
import logging
import re
from dataclasses import replace
from datetime import date, timedelta
from time import monotonic

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, func, inspect, select, text, update

from carlos_patient_portal import i18n
from carlos_patient_portal.config import Settings
from carlos_patient_portal.maintenance import cleanup_transient_auth_rows
from carlos_patient_portal.models import (
    AUDIT_EVENT_SIGNUP_REQUEST,
    AUDIT_OUTCOME_SUCCESS,
    AUDIT_OUTCOME_THROTTLED,
    PatientPortalAuditEvent,
    PatientPortalOutboundDelivery,
    PatientPortalSignupRequest,
    utc_now,
)
from carlos_patient_portal.routes.signup import hold_response_floor
from carlos_patient_portal.self_signup import (
    SIGNUP_HEALTH_CARD_RESOURCE_TYPE,
    SIGNUP_OUTCOME_RATE_LIMITED,
    SIGNUP_OUTCOME_STORED,
    SIGNUP_REASON_CLIENT_RATE_LIMITED,
    SIGNUP_REASON_HEALTH_CARD_RATE_LIMITED,
    SelfSignupPolicy,
    SignupQueueFullError,
    SignupRequestDetails,
    SignupRequestKeyUnavailableError,
    SignupRequestPayloadError,
    count_recent_signup_requests,
    decrypt_signup_request,
    encrypt_signup_details,
    hash_signup_client,
    hash_signup_health_card,
    health_card_rate_key,
    submit_signup_request,
    summarize_signup_backlog,
)
from tests.support import (
    AUDIT_HASH_SECRET,
    INTERNAL_HEALTH_TOKEN,
    OUTBOX_ENCRYPTION_SECRET,
    SEEDED_INVITE_DOB,
    SEEDED_INVITE_EMAIL,
    SEEDED_INVITE_HCN,
    RecordingPortalEmailSender,
    activate_seeded_patient_account,
    create_service_invite,
    csrf_token_from_response,
    get_csrf_token,
    migrated_development_app,
    seeded_identity_proof,
)

SIGN_UP_PATH = "/auth/sign-up"
FAKE_HCN = "9876 543 210 XY"
FAKE_HCN_NORMALIZED = "9876543210XY"
FAKE_DOB = "1975-03-14"
FAKE_EMAIL = "fake.patient@example.test"
FAKE_CLIENT_IP = "203.0.113.7"
SIGN_UP_KEYS = sorted(key for key in i18n.TEXT_CATALOG["en"] if key.startswith("sign_up_"))


def signup_app(**overrides: object):
    values: dict[str, object] = {
        "self_signup_enabled": True,
        "self_signup_response_floor_ms": 0,
        "outbox_encryption_secret": OUTBOX_ENCRYPTION_SECRET,
        **overrides,
    }
    return migrated_development_app(**values)


def client_at(app, address: str = FAKE_CLIENT_IP) -> TestClient:
    return TestClient(app, client=(address, 50000))


def date_boxes(iso_date: str) -> dict[str, str]:
    """An ISO date as the page's Day, Month and Year boxes would post it."""
    year, month, day = iso_date.split("-")
    return {
        "date_of_birth_day": str(int(day)),
        "date_of_birth_month": str(int(month)),
        "date_of_birth_year": year,
    }


def sign_up(client: TestClient, *, date_of_birth: str = FAKE_DOB, **fields: str):
    page = client.get(SIGN_UP_PATH)
    assert page.status_code == 200
    data = {
        "csrf_token": csrf_token_from_response(page),
        "health_card_number": FAKE_HCN,
        **date_boxes(date_of_birth),
        "email": FAKE_EMAIL,
        **fields,
    }
    return client.post(SIGN_UP_PATH, data=data)


def stored_requests(app) -> list[PatientPortalSignupRequest]:
    with app.state.session_factory() as session:
        return list(session.scalars(select(PatientPortalSignupRequest)))


def signup_events(app) -> list[PatientPortalAuditEvent]:
    with app.state.session_factory() as session:
        return list(
            session.scalars(
                select(PatientPortalAuditEvent)
                .where(PatientPortalAuditEvent.event_type == AUDIT_EVENT_SIGNUP_REQUEST)
                .order_by(PatientPortalAuditEvent.id)
            )
        )


def response_signature(response) -> tuple[object, ...]:
    """Everything a caller can observe, with the two values that are fresh on every response.

    The request id and the CSRF cookie's value are random per response by design; their presence
    and every cookie attribute must still match.
    """
    headers = []
    for name, value in response.headers.multi_items():
        if name == "x-request-id":
            value = "<request-id>"
        elif name == "set-cookie":
            value = re.sub(r"^carlos_portal_csrf=[^;]*", "carlos_portal_csrf=<token>", value)
        headers.append((name, value))
    return response.status_code, tuple(sorted(headers)), response.content


# --------------------------------------------------------------------------------------------
# Off by default
# --------------------------------------------------------------------------------------------


def test_self_signup_is_off_by_default_with_the_tickets_starting_values() -> None:
    settings = Settings(environment="development")

    assert settings.self_signup_enabled is False
    assert settings.self_signup_request_ttl_seconds == 24 * 60 * 60
    assert settings.self_signup_max_requests_per_client == 5
    assert settings.self_signup_client_window_seconds == 60 * 60
    assert settings.self_signup_max_requests_per_health_card == 3
    assert settings.self_signup_health_card_window_seconds == 24 * 60 * 60


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("self_signup_request_ttl_seconds", 60),
        ("self_signup_max_requests_per_client", 0),
        ("self_signup_max_requests_per_health_card", 0),
        ("self_signup_queue_max_pending", 1),
        ("self_signup_response_floor_ms", -1),
    ],
)
def test_self_signup_settings_are_bounded(setting: str, value: int) -> None:
    with pytest.raises(ValidationError):
        Settings(environment="development", **{setting: value})


def test_switched_off_the_page_is_an_unknown_page_and_nothing_is_stored() -> None:
    app = migrated_development_app(outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    client = client_at(app)

    page = client.get(SIGN_UP_PATH)
    unknown = client.get("/auth/no-such-page")
    submitted = client.post(
        SIGN_UP_PATH,
        data={
            "csrf_token": get_csrf_token(client),
            "health_card_number": FAKE_HCN,
            "date_of_birth": FAKE_DOB,
            "email": FAKE_EMAIL,
        },
    )

    assert page.status_code == unknown.status_code == submitted.status_code == 404
    # The pages differ only in the path the language links return to.
    assert page.text.replace(SIGN_UP_PATH, "<path>") == unknown.text.replace(
        "/auth/no-such-page", "<path>"
    )
    assert stored_requests(app) == []
    assert signup_events(app) == []
    assert SIGN_UP_PATH not in client.get("/").text


# --------------------------------------------------------------------------------------------
# The page
# --------------------------------------------------------------------------------------------


def test_sign_up_page_has_the_auth_page_headers_csrf_and_a_sign_in_link() -> None:
    app = signup_app()
    client = client_at(app)

    page = client.get(SIGN_UP_PATH)
    reset_page = client.get("/auth/password-reset")

    assert page.status_code == 200
    assert page.headers["cache-control"] == "no-store"
    assert page.headers["pragma"] == "no-cache"
    for header in (
        "cache-control",
        "pragma",
        "content-security-policy",
        "referrer-policy",
        "x-content-type-options",
        "x-frame-options",
    ):
        assert page.headers[header] == reset_page.headers[header]
    set_cookie = page.headers["set-cookie"]
    assert "carlos_portal_csrf=" in set_cookie
    assert "HttpOnly" in set_cookie
    assert "Path=/auth" in set_cookie
    assert "SameSite=strict" in set_cookie
    assert f'action="http://testserver{SIGN_UP_PATH}"' in page.text
    for field_name in (
        "health_card_number",
        "date_of_birth_day",
        "date_of_birth_month",
        "date_of_birth_year",
        "email",
        "csrf_token",
    ):
        assert f'name="{field_name}"' in page.text
    # The Day, Month and Year boxes activation uses, never a browser date field.
    assert 'type="date"' not in page.text
    assert i18n.TEXT_CATALOG["en"]["date_of_birth_hint"] in page.text
    assert i18n.TEXT_CATALOG["en"]["sign_up_email_hint"].replace("'", "&#39;") in page.text
    assert f'href="http://testserver{SIGN_UP_PATH}"' in client.get("/").text


def test_sign_up_page_is_translated() -> None:
    app = signup_app()
    client = client_at(app)
    client.cookies.set("portal_locale", "fr")

    page = client.get(SIGN_UP_PATH)
    result = sign_up(client)

    assert "Demander un compte du portail" in page.text
    # The shared date boxes come translated from activation (carlos-portal#30, #31).
    assert "Choisissez un mois" in page.text
    assert '<html lang="fr">' in page.text
    assert result.status_code == 202
    assert "Demande reçue" in result.text


@pytest.mark.parametrize("locale", ["fr", "es", "pl", "pt-BR"])
def test_every_sign_up_string_is_translated(locale: str) -> None:
    english = i18n.TEXT_CATALOG["en"]
    translated = i18n.TEXT_CATALOG[locale]

    assert len(SIGN_UP_KEYS) == 10
    for key in SIGN_UP_KEYS:
        assert translated.get(key), f"{locale} has no {key}"
        assert translated[key] != english[key], f"{locale} {key} is still English"


def test_the_result_message_is_the_tickets_wording() -> None:
    assert i18n.TEXT_CATALOG["en"]["sign_up_result"] == (
        "If your details match our records, we have emailed you a link to finish setting up "
        "your account. If nothing arrives, contact the clinic."
    )


# --------------------------------------------------------------------------------------------
# CSRF and request shape
# --------------------------------------------------------------------------------------------


def test_post_without_a_valid_csrf_token_is_refused_and_stores_nothing() -> None:
    app = signup_app()
    details = {
        "health_card_number": FAKE_HCN,
        **date_boxes(FAKE_DOB),
        "email": FAKE_EMAIL,
    }

    missing_token = client_at(app)
    missing_token.get(SIGN_UP_PATH)
    no_token = missing_token.post(SIGN_UP_PATH, data=details)

    page = client_at(app).get(SIGN_UP_PATH)
    no_cookie = client_at(app).post(
        SIGN_UP_PATH,
        data={"csrf_token": csrf_token_from_response(page), **details},
    )

    mismatched_client = client_at(app)
    mismatched_client.get(SIGN_UP_PATH)
    mismatched = mismatched_client.post(
        SIGN_UP_PATH,
        data={"csrf_token": csrf_token_from_response(page), **details},
    )

    assert no_token.status_code == no_cookie.status_code == mismatched.status_code == 403
    assert stored_requests(app) == []
    assert signup_events(app) == []


def test_json_is_not_accepted() -> None:
    app = signup_app()
    client = client_at(app)
    client.get(SIGN_UP_PATH)

    response = client.post(
        SIGN_UP_PATH,
        json={"health_card_number": FAKE_HCN, "date_of_birth": FAKE_DOB, "email": FAKE_EMAIL},
    )

    assert response.status_code == 415
    assert stored_requests(app) == []


@pytest.mark.parametrize(
    ("field_override", "message_key"),
    [
        # The date of birth alone: activation's own "Check the date of birth" message.
        ({"date_of_birth_day": "30"}, "activation_date_of_birth_invalid"),
        ({"date_of_birth_year": "75"}, "activation_date_of_birth_invalid"),
        ({"date_of_birth_day": ""}, "activation_date_of_birth_invalid"),
        ({"date_of_birth_year": "1890"}, "activation_date_of_birth_invalid"),
        ({"health_card_number": "12"}, "sign_up_details_invalid"),
        ({"health_card_number": "9876-543-210-ÉÉ"}, "sign_up_details_invalid"),
        ({"email": "not-an-email"}, "sign_up_details_invalid"),
        ({"email": ""}, "sign_up_details_invalid"),
        # More than the date: the message that names every detail.
        ({"date_of_birth_day": "31", "email": "not-an-email"}, "sign_up_details_invalid"),
    ],
)
def test_a_detail_in_the_wrong_format_is_named_kept_and_not_stored(
    field_override, message_key
) -> None:
    app = signup_app()
    client = client_at(app)

    response = sign_up(client, **{"date_of_birth_month": "2", **field_override})

    assert response.status_code == 400
    assert response.headers["cache-control"] == "no-store"
    assert i18n.TEXT_CATALOG["en"][message_key] in response.text
    kept = {
        "health_card_number": FAKE_HCN,
        **date_boxes(FAKE_DOB),
        "date_of_birth_month": "2",
        "email": FAKE_EMAIL,
        **field_override,
    }
    for field_name in ("health_card_number", "date_of_birth_day", "date_of_birth_year", "email"):
        if kept[field_name]:
            assert f'value="{kept[field_name]}"' in response.text
    assert '<option value="2" selected>' in response.text
    assert stored_requests(app) == []
    assert signup_events(app) == []


def test_a_single_iso_date_of_birth_is_still_read() -> None:
    """date_of_birth_from_form, shared with activation, reads a lone ISO date as before."""
    app = signup_app()
    client = client_at(app)
    page = client.get(SIGN_UP_PATH)

    response = client.post(
        SIGN_UP_PATH,
        data={
            "csrf_token": csrf_token_from_response(page),
            "health_card_number": FAKE_HCN,
            "date_of_birth": FAKE_DOB,
            "email": FAKE_EMAIL,
        },
    )

    assert response.status_code == 202
    (row,) = stored_requests(app)
    details = decrypt_signup_request(row, encryption_keys={"primary": OUTBOX_ENCRYPTION_SECRET})
    assert details.date_of_birth == date(1975, 3, 14)


# --------------------------------------------------------------------------------------------
# The uniform response
# --------------------------------------------------------------------------------------------


def test_every_accepted_request_gets_the_same_page_status_and_headers() -> None:
    """Existing account, pending invite, unknown card, mismatch, duplicate and both limits."""
    sender = RecordingPortalEmailSender()
    app = signup_app(email_sender=sender)
    # A patient with an account, and one with a pending staff invite. The portal never looks
    # either up; the point is that their presence changes nothing a caller can see.
    activate_seeded_patient_account(app, TestClient(app))
    with app.state.session_factory.begin() as session:
        create_service_invite(
            session,
            demographic_no=2345,
            clinic_id=app.state.settings.clinic_id,
            identity_proof=seeded_identity_proof(
                email="invited.patient@example.test",
                health_card_number="5555 666 777",
            ),
        )
    sender.messages.clear()

    responses = {
        "existing account": sign_up(
            client_at(app, "203.0.113.1"),
            health_card_number=SEEDED_INVITE_HCN,
            date_of_birth=SEEDED_INVITE_DOB,
            email=SEEDED_INVITE_EMAIL,
        ),
        "pending invite": sign_up(
            client_at(app, "203.0.113.2"),
            health_card_number="5555 666 777",
            date_of_birth=SEEDED_INVITE_DOB,
            email="invited.patient@example.test",
        ),
        "email does not match": sign_up(
            client_at(app, "203.0.113.3"),
            health_card_number=SEEDED_INVITE_HCN,
            date_of_birth=SEEDED_INVITE_DOB,
            email="someone.else@example.test",
        ),
        "unknown health card": sign_up(client_at(app, "203.0.113.4")),
        "duplicate": sign_up(client_at(app, "203.0.113.4")),
    }
    # The unknown card has had two requests; a third and a fourth from new addresses reach the
    # per-card limit.
    sign_up(client_at(app, "203.0.113.5"))
    responses["health card limit"] = sign_up(client_at(app, "203.0.113.6"))
    busy_client = client_at(app, "198.51.100.9")
    for index in range(5):
        sign_up(busy_client, health_card_number=f"7000 000 00{index}")
    responses["client limit"] = sign_up(busy_client, health_card_number="7000 000 099")

    reference = response_signature(responses["existing account"])
    assert reference[0] == 202
    assert i18n.TEXT_CATALOG["en"]["sign_up_result"] in responses["existing account"].text
    for case, response in responses.items():
        assert response_signature(response) == reference, case
        assert "retry-after" not in response.headers, case

    reasons = [(event.outcome, event.reason) for event in signup_events(app)]
    assert reasons.count((AUDIT_OUTCOME_THROTTLED, SIGNUP_REASON_HEALTH_CARD_RATE_LIMITED)) == 1
    assert reasons.count((AUDIT_OUTCOME_THROTTLED, SIGNUP_REASON_CLIENT_RATE_LIMITED)) == 1
    assert len(stored_requests(app)) == 11
    # Nothing typed is used as a destination: the portal sends nothing at all.
    assert sender.messages == []
    with app.state.session_factory() as session:
        assert session.scalar(select(func.count(PatientPortalOutboundDelivery.id))) == 0


def test_a_stored_and_a_refused_request_take_the_same_minimum_time() -> None:
    floor_ms = 300
    app = signup_app(
        self_signup_response_floor_ms=floor_ms,
        self_signup_max_requests_per_client=1,
    )
    client = client_at(app)

    durations = []
    for card in ("7100 000 001", "7100 000 002"):
        page = client.get(SIGN_UP_PATH)
        started = monotonic()
        response = client.post(
            SIGN_UP_PATH,
            data={
                "csrf_token": csrf_token_from_response(page),
                "health_card_number": card,
                **date_boxes(FAKE_DOB),
                "email": FAKE_EMAIL,
            },
        )
        durations.append(monotonic() - started)
        assert response.status_code == 202

    assert [event.outcome for event in signup_events(app)] == [
        AUDIT_OUTCOME_SUCCESS,
        AUDIT_OUTCOME_THROTTLED,
    ]
    assert min(durations) >= floor_ms / 1000


def test_the_floor_waits_only_for_what_is_left() -> None:
    async def measure(already_elapsed: float, floor: float) -> float:
        started = monotonic()
        await hold_response_floor(started - already_elapsed, floor)
        return monotonic() - started

    assert asyncio.run(measure(0.0, 0.1)) >= 0.09
    assert asyncio.run(measure(0.5, 0.1)) < 0.05


# --------------------------------------------------------------------------------------------
# Rate limits
# --------------------------------------------------------------------------------------------


def test_the_per_client_limit_refuses_the_sixth_request_in_an_hour() -> None:
    app = signup_app()
    client = client_at(app)

    statuses = [
        sign_up(client, health_card_number=f"7200 000 00{index}").status_code
        for index in range(6)
    ]

    assert statuses == [202] * 6
    assert len(stored_requests(app)) == 5
    last = signup_events(app)[-1]
    assert (last.outcome, last.reason) == (
        AUDIT_OUTCOME_THROTTLED,
        SIGNUP_REASON_CLIENT_RATE_LIMITED,
    )


def test_the_per_card_limit_refuses_the_fourth_request_in_a_day_whatever_the_version_code() -> (
    None
):
    app = signup_app()
    typed_forms = ["9876543210", "9876-543-210", "9876 543 210 XY", "9876543210AB"]

    for index, typed in enumerate(typed_forms):
        response = sign_up(client_at(app, f"203.0.113.{20 + index}"), health_card_number=typed)
        assert response.status_code == 202

    assert len(stored_requests(app)) == 3
    events = signup_events(app)
    assert {event.resource_id for event in events} == {
        hash_signup_health_card(AUDIT_HASH_SECRET, "9876543210")
    }
    assert (events[-1].outcome, events[-1].reason) == (
        AUDIT_OUTCOME_THROTTLED,
        SIGNUP_REASON_HEALTH_CARD_RATE_LIMITED,
    )


def test_only_stored_requests_count_and_the_window_slides() -> None:
    app = signup_app(self_signup_max_requests_per_health_card=1)
    sign_up(client_at(app, "203.0.113.30"))
    sign_up(client_at(app, "203.0.113.31"))
    assert len(stored_requests(app)) == 1

    # A day later the stored request has left the window. The refusal is still recent, but a
    # refusal never counts, so a flood cannot keep the patient out.
    with app.state.session_factory.begin() as session:
        session.execute(
            update(PatientPortalAuditEvent)
            .where(PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_SUCCESS)
            .values(created_at=utc_now() - timedelta(days=1, minutes=1))
        )
    sign_up(client_at(app, "203.0.113.32"))

    assert len(stored_requests(app)) == 2


def test_limits_are_counted_from_keyed_hashes() -> None:
    app = signup_app()
    sign_up(client_at(app))
    client_hash = hash_signup_client(AUDIT_HASH_SECRET, FAKE_CLIENT_IP)
    card_hash = hash_signup_health_card(AUDIT_HASH_SECRET, FAKE_HCN_NORMALIZED)

    with app.state.session_factory() as session:
        since = utc_now() - timedelta(hours=1)
        assert count_recent_signup_requests(
            session, since=since, client_reference_hash=client_hash
        ) == 1
        assert count_recent_signup_requests(session, since=since, health_card_hash=card_hash) == 1
        with pytest.raises(ValueError):
            count_recent_signup_requests(session, since=since)
    event = signup_events(app)[0]
    assert event.client_reference_hash == client_hash
    assert (event.resource_type, event.resource_id) == (SIGNUP_HEALTH_CARD_RESOURCE_TYPE, card_hash)


@pytest.mark.parametrize(
    ("normalized", "key"),
    [
        ("9876543210", "9876543210"),
        ("9876543210A", "9876543210"),
        ("9876543210XY", "9876543210"),
        ("ABCD12345678", "ABCD12345678"),
        ("N1234567", "N1234567"),
        ("123AB", "123AB"),
        ("ABCDEF", "ABCDEF"),
    ],
)
def test_the_per_card_key_drops_only_a_trailing_version_code(normalized: str, key: str) -> None:
    assert health_card_rate_key(normalized) == key


# --------------------------------------------------------------------------------------------
# Storage: encrypted at rest, TTL, backlog
# --------------------------------------------------------------------------------------------


def test_the_raw_row_and_the_audit_trail_hold_no_plaintext(caplog) -> None:
    app = signup_app()
    with caplog.at_level(logging.DEBUG):
        assert sign_up(client_at(app)).status_code == 202

    plaintexts = (
        FAKE_HCN_NORMALIZED,
        FAKE_HCN,
        "9876543210",
        FAKE_DOB,
        "19750314",
        FAKE_EMAIL,
        FAKE_CLIENT_IP,
    )
    with app.state.database_engine.connect() as connection:
        signup_rows = connection.execute(text("select * from patient_portal_signup_requests"))
        raw_rows = [tuple(row) for row in signup_rows]
        audit_rows = [
            tuple(row)
            for row in connection.execute(text("select * from patient_portal_audit_events"))
        ]
    assert len(raw_rows) == 1
    for row in raw_rows + audit_rows:
        for value in row:
            raw = value if isinstance(value, bytes) else str(value).encode()
            for plaintext in plaintexts:
                assert plaintext.encode() not in raw
    for record in caplog.records:
        for plaintext in plaintexts:
            assert plaintext not in record.getMessage()


def test_a_stored_request_decrypts_with_the_outbox_keyring_and_only_in_place() -> None:
    app = signup_app()
    sign_up(client_at(app), email="  Fake.Patient@Example.TEST ")
    sign_up(client_at(app, "203.0.113.40"), health_card_number="7300 000 001")
    first, second = stored_requests(app)

    details = decrypt_signup_request(first, encryption_keys={"primary": OUTBOX_ENCRYPTION_SECRET})

    assert details == SignupRequestDetails(
        health_card_number=FAKE_HCN_NORMALIZED,
        date_of_birth=date(1975, 3, 14),
        email=FAKE_EMAIL,
    )
    assert FAKE_EMAIL not in repr(details)
    assert first.encryption_key_id == "primary"
    assert first.expires_at - first.created_at == timedelta(hours=24)
    with pytest.raises(SignupRequestKeyUnavailableError):
        decrypt_signup_request(first, encryption_keys={"other": OUTBOX_ENCRYPTION_SECRET})
    # The ciphertext is bound to its card hash: copied onto another row, it does not open.
    second.encrypted_payload = first.encrypted_payload
    second.encryption_nonce = first.encryption_nonce
    with pytest.raises(SignupRequestPayloadError):
        decrypt_signup_request(second, encryption_keys={"primary": OUTBOX_ENCRYPTION_SECRET})


def test_a_request_stored_under_an_old_key_still_decrypts_after_rotation() -> None:
    old_key = "old-outbox-key-" + "o" * 32
    new_key = "new-outbox-key-" + "n" * 32
    app = signup_app(
        outbox_encryption_secret=None,
        outbox_encryption_keyring=f'{{"2026-09":"{old_key}"}}',
        outbox_active_key_id="2026-09",
    )
    sign_up(client_at(app))
    (row,) = stored_requests(app)

    details = decrypt_signup_request(row, encryption_keys={"2026-09": old_key, "2026-10": new_key})

    assert row.encryption_key_id == "2026-09"
    assert details.email == FAKE_EMAIL


def test_expired_requests_are_purged_by_cleanup_and_by_the_next_request() -> None:
    app = signup_app()
    policy = SelfSignupPolicy.from_settings(app.state.settings)
    details = SignupRequestDetails(
        health_card_number=FAKE_HCN_NORMALIZED,
        date_of_birth=date(1975, 3, 14),
        email=FAKE_EMAIL,
    )

    def store(now, card: str) -> None:
        with app.state.session_factory.begin() as session:
            outcome = submit_signup_request(
                session,
                details=details,
                clinic_id="default",
                client_reference_hash=hash_signup_client(AUDIT_HASH_SECRET, card),
                health_card_hash=hash_signup_health_card(AUDIT_HASH_SECRET, card),
                encryption_secret=OUTBOX_ENCRYPTION_SECRET,
                encryption_key_id="primary",
                policy=policy,
                now=now,
            )
            assert outcome == SIGNUP_OUTCOME_STORED

    long_ago = utc_now() - timedelta(days=2)
    # The fresh one first: storing purges what has expired by its own `now`.
    store(utc_now(), "7400000003")
    store(long_ago, "7400000001")
    store(long_ago, "7400000002")
    with app.state.session_factory() as session:
        assert summarize_signup_backlog(session).pending == 1

    with app.state.session_factory.begin() as session:
        dry_run = cleanup_transient_auth_rows(
            session, before=utc_now() - timedelta(days=30), dry_run=True
        )
    with app.state.session_factory.begin() as session:
        cleaned = cleanup_transient_auth_rows(
            session, before=utc_now() - timedelta(days=30), batch_size=1
        )
    assert dry_run.signup_requests == 2
    assert cleaned.signup_requests == 1
    assert cleaned.total >= 1
    assert len(stored_requests(app)) == 2

    # The next submission deletes what cleanup has not reached yet.
    sign_up(client_at(app))
    assert all(row.expires_at.replace(tzinfo=None) > utc_now().replace(tzinfo=None)
               for row in stored_requests(app))
    assert len(stored_requests(app)) == 2


def test_a_full_backlog_answers_one_global_503_and_stores_nothing() -> None:
    app = signup_app(self_signup_queue_max_pending=10)
    now = utc_now()
    with app.state.session_factory.begin() as session:
        for index in range(10):
            session.add(
                PatientPortalSignupRequest(
                    clinic_id="default",
                    health_card_hash=f"{index:064d}",
                    encrypted_payload=b"opaque",
                    encryption_nonce=b"n" * 12,
                    encryption_key_id="primary",
                    created_at=now - timedelta(hours=2),
                    expires_at=now + timedelta(hours=1),
                )
            )

    full = sign_up(client_at(app))

    assert full.status_code == 503
    assert full.headers["retry-after"] == "300"
    assert full.headers["cache-control"] == "no-store"
    assert i18n.TEXT_CATALOG["en"]["sign_up_unavailable"] in full.text
    assert len(stored_requests(app)) == 10
    assert signup_events(app) == []
    assert app.state.operational_metrics.snapshot()["failures"]["self_signup_queue_full"] == 1

    # An expired request no longer counts against the backlog, and is purged on the way in.
    with app.state.session_factory.begin() as session:
        session.execute(
            update(PatientPortalSignupRequest)
            .where(PatientPortalSignupRequest.health_card_hash == f"{0:064d}")
            .values(expires_at=now - timedelta(minutes=1))
        )
    assert sign_up(client_at(app)).status_code == 202
    assert len(stored_requests(app)) == 10


def test_queue_full_is_raised_before_anything_is_written() -> None:
    app = signup_app()
    policy = SelfSignupPolicy(
        request_ttl=timedelta(hours=24),
        client_window=timedelta(hours=1),
        max_requests_per_client=5,
        health_card_window=timedelta(hours=24),
        max_requests_per_health_card=3,
        max_pending=0,
    )
    details = SignupRequestDetails(
        health_card_number=FAKE_HCN_NORMALIZED,
        date_of_birth=date(1975, 3, 14),
        email=FAKE_EMAIL,
    )

    with app.state.session_factory() as session:
        with pytest.raises(SignupQueueFullError):
            submit_signup_request(
                session,
                details=details,
                clinic_id="default",
                client_reference_hash="c" * 64,
                health_card_hash="h" * 64,
                encryption_secret=OUTBOX_ENCRYPTION_SECRET,
                encryption_key_id="primary",
                policy=policy,
            )
        assert len(session.new) == 0


def test_readiness_shows_the_backlog_and_the_age_of_the_oldest_request() -> None:
    app = signup_app(internal_health_token=INTERNAL_HEALTH_TOKEN)
    client = client_at(app)
    headers = {"Authorization": f"Bearer {INTERNAL_HEALTH_TOKEN}"}

    empty = client.get("/internal/readiness", headers=headers)
    sign_up(client)
    with app.state.session_factory.begin() as session:
        session.execute(
            update(PatientPortalSignupRequest).values(
                created_at=utc_now() - timedelta(minutes=10)
            )
        )
    waiting = client.get("/internal/readiness", headers=headers)

    assert empty.status_code == waiting.status_code == 200
    assert empty.json()["self_signup"] == {
        "pending": 0,
        "max_pending": 1000,
        "oldest_pending_age_seconds": None,
    }
    backlog = waiting.json()["self_signup"]
    assert backlog["pending"] == 1
    assert 600 <= backlog["oldest_pending_age_seconds"] < 700

    switched_off = migrated_development_app(internal_health_token=INTERNAL_HEALTH_TOKEN)
    assert "self_signup" not in TestClient(switched_off).get(
        "/internal/readiness", headers=headers
    ).json()


def test_encryption_refuses_an_oversized_payload() -> None:
    details = SignupRequestDetails(
        health_card_number="X" * 2000,
        date_of_birth=date(1975, 3, 14),
        email=FAKE_EMAIL,
    )

    with pytest.raises(ValueError, match="too large"):
        encrypt_signup_details(
            details,
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            clinic_id="default",
            health_card_hash="h" * 64,
        )


def test_a_stored_and_a_refused_outcome_are_returned_to_the_route() -> None:
    app = signup_app()
    policy = replace(SelfSignupPolicy.from_settings(app.state.settings), max_requests_per_client=1)
    details = SignupRequestDetails(
        health_card_number=FAKE_HCN_NORMALIZED,
        date_of_birth=date(1975, 3, 14),
        email=FAKE_EMAIL,
    )
    outcomes = []
    for card in ("7500000001", "7500000002"):
        with app.state.session_factory.begin() as session:
            outcomes.append(
                submit_signup_request(
                    session,
                    details=details,
                    clinic_id="default",
                    client_reference_hash="c" * 64,
                    health_card_hash=hash_signup_health_card(AUDIT_HASH_SECRET, card),
                    encryption_secret=OUTBOX_ENCRYPTION_SECRET,
                    encryption_key_id="primary",
                    policy=policy,
                )
            )

    assert outcomes == [SIGNUP_OUTCOME_STORED, SIGNUP_OUTCOME_RATE_LIMITED]


# --------------------------------------------------------------------------------------------
# Migration
# --------------------------------------------------------------------------------------------


def test_signup_migration_downgrades_only_without_signup_audit_events(tmp_path) -> None:
    config = Config()
    config.set_main_option("script_location", "carlos_patient_portal:migrations")
    database_url = f"sqlite+pysqlite:///{tmp_path / 'signup.db'}"
    config.set_main_option("sqlalchemy.url", database_url)
    command.upgrade(config, "0016_self_signup_requests")
    engine = create_engine(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "insert into patient_portal_audit_events "
                    "(event_type, outcome, actor_type, created_at) "
                    "values ('signup.request', 'success', 'patient', :now)"
                ),
                {"now": utc_now()},
            )
        with pytest.raises(RuntimeError, match="sign-up audit events exist"):
            command.downgrade(config, "0015_booking_offered_slots")
        with engine.begin() as connection:
            connection.execute(text("delete from patient_portal_audit_events"))
        command.downgrade(config, "0015_booking_offered_slots")
        assert "patient_portal_signup_requests" not in inspect(engine).get_table_names()
        with pytest.raises(Exception, match="(?i)constraint"):
            with engine.begin() as connection:
                connection.execute(
                    text(
                        "insert into patient_portal_audit_events "
                        "(event_type, outcome, actor_type, created_at) "
                        "values ('signup.request', 'success', 'patient', :now)"
                    ),
                    {"now": utc_now()},
                )
        command.upgrade(config, "head")
        assert "patient_portal_signup_requests" in inspect(engine).get_table_names()
    finally:
        engine.dispose()
