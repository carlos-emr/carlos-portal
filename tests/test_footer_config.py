import json

import pytest
from sqlalchemy.exc import SQLAlchemyError

from carlos_patient_portal import preflight
from carlos_patient_portal.cli import _outbox_configuration_digest
from carlos_patient_portal.config import OutboxSettings, Settings
from tests.support import TEST_STAFF_ASSERTION_PUBLIC_KEYRING, non_development_settings_values


@pytest.mark.parametrize(
    "field",
    [
        "email_footer_url",
        "email_footer_read_token",
        "email_footer_audit_directory",
        "internal_staff_assertion_public_keyring",
    ],
)
def test_non_development_smtp_requires_trusted_footer_configuration(field):
    values = non_development_settings_values("staging")
    values[field] = None
    with pytest.raises(ValueError):
        Settings(**values)


@pytest.mark.parametrize(
    "url",
    [
        "http://carlos.example.test/ws/portal/email-footer",
        "https://user:password@carlos.example.test/ws/portal/email-footer",
        "https://carlos.example.test/ws/portal/email-footer?nonce=stale",
        "https://carlos.example.test/ws/portal/email-footer#fragment",
        "https://carlos.example.test/other",
        "https://carlos.example.test\n/ws/portal/email-footer",
    ],
)
def test_provider_url_refuses_wrong_transport_credentials_query_fragment_or_path(url):
    with pytest.raises(ValueError, match="PATIENT_PORTAL_EMAIL_FOOTER_URL"):
        Settings(environment="development", email_footer_url=url)


def test_derived_token_is_masked_and_full_service_token_rejected():
    settings = Settings(environment="development", email_footer_read_token="d" * 64)
    assert "d" * 64 not in repr(settings)
    settings.internal_api_token = settings.email_footer_read_token
    with pytest.raises(ValueError, match="full internal API credential"):
        settings.validate_email_footer_policy()


def worker_values():
    return dict(
        environment="staging",
        clinic_id="clinic-a",
        clinic_name="FAKE Clinic",
        session_secret="s" * 32,
        outbox_encryption_keyring=json.dumps({"initial": "o" * 32}),
        outbox_active_key_id="initial",
        public_base_url="https://portal.example.test",
        smtp_host="fake-smtp.internal",
        smtp_from_address="portal@example.test",
        smtp_starttls=True,
        email_footer_url="https://carlos.example.test/ws/portal/email-footer",
        email_footer_read_token="d" * 64,
        email_footer_audit_directory="/FAKE/footer-audit",
        internal_staff_assertion_public_keyring=TEST_STAFF_ASSERTION_PUBLIC_KEYRING,
    )


def test_worker_can_verify_footer_without_full_root_service_or_private_signing_credential():
    settings = OutboxSettings(**worker_values())
    assert settings.internal_api_token is None
    assert settings.internal_api_token_previous is None
    assert settings.email_footer_read_token is not None
    assert settings.resolved_internal_staff_assertion_public_keys
    with pytest.raises(ValueError, match="web-only credentials"):
        OutboxSettings(**worker_values(), internal_api_token="c" * 32)


@pytest.mark.parametrize(
    "change",
    [
        {"email_footer_url": "https://different.example.test/ws/portal/email-footer"},
        {"email_footer_read_token": "e" * 64},
        {"email_footer_audit_directory": "/FAKE/another-audit-volume"},
        {"email_footer_timeout_seconds": 3},
    ],
)
def test_worker_compatibility_digest_detects_footer_deployment_mismatch(change):
    values = worker_values()
    first = _outbox_configuration_digest(OutboxSettings(**values))
    second = _outbox_configuration_digest(OutboxSettings(**{**values, **change}))
    assert first != second


@pytest.mark.parametrize("mode,expected", [(0o700, "pass"), (0o755, "fail")])
def test_actual_preflight_probes_private_durable_footer_volume(
    monkeypatch, tmp_path, mode, expected
):
    tmp_path.chmod(mode)
    settings = Settings(
        environment="development",
        clinic_id="clinic-a",
        smtp_host="fake-smtp.internal",
        email_footer_url="https://carlos.example.test/ws/portal/email-footer",
        email_footer_read_token="d" * 64,
        email_footer_audit_directory=str(tmp_path),
        internal_staff_assertion_public_keyring=TEST_STAFF_ASSERTION_PUBLIC_KEYRING,
    )

    def unavailable_database(*args, **kwargs):
        raise SQLAlchemyError("FAKE database not connected by this storage probe")

    monkeypatch.setattr(preflight, "create_portal_engine", unavailable_database)
    checks = preflight.collect_production_preflight(settings)
    assert next(check.status for check in checks if check.name == "email_footer_audit") == expected
    assert list(tmp_path.iterdir()) == []
