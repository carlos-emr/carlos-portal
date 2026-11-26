# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""Settings the portal refuses to start with, beyond what `test_config*.py` pin (FAKE values only).

Each case changes ONE thing from a configuration that is accepted (shown first where it is not
obvious), so the refusal named is the only thing that can have caused it. The messages name the
environment variable, never its value.
"""

import json
from functools import partial

import pytest

from carlos_patient_portal.config import (
    DEFAULT_CLINIC_ID,
    DEFAULT_CLINIC_NAME,
    DEFAULT_PROBE_ALLOWED_HOSTS,
    MigrationDatabaseSettings,
    OutboxSettings,
    normalize_environment_value,
)
from tests.support import (
    OUTBOX_ENCRYPTION_SECRET,
    development_settings,
    non_development_settings_values,
    production_settings,
    staging_settings,
)


def refused(factory, match: str, **overrides: object) -> None:
    with pytest.raises(ValueError, match=match):
        factory(**overrides)


# --------------------------------------------------------------------------------------------
# The environment name, the hosts a probe may use, the public address
# --------------------------------------------------------------------------------------------


def test_the_environment_name_is_trimmed_lower_cased_aliased_and_a_non_string_left_alone() -> None:
    assert normalize_environment_value(" PROD ") == "production"
    assert normalize_environment_value("Dev") == "development"
    assert normalize_environment_value("staging") == "staging"
    sentinel = object()
    assert normalize_environment_value(sentinel) is sentinel
    assert normalize_environment_value(None) is None
    assert MigrationDatabaseSettings(environment=" DEV ").environment == "development"


def test_probe_hosts_that_are_only_blanks_are_the_same_as_none_given() -> None:
    for aliases in (" , ,", ""):
        settings = development_settings(probe_allowed_hosts=aliases)
        assert settings.probe_host_aliases == DEFAULT_PROBE_ALLOWED_HOSTS
        exclusive = development_settings(
            probe_allowed_hosts=aliases, probe_allowed_hosts_exclusive=True
        )
        assert exclusive.probe_host_aliases == ()
    assert development_settings(probe_allowed_hosts="10.0.0.5").probe_host_aliases == (
        "10.0.0.5",
        *DEFAULT_PROBE_ALLOWED_HOSTS,
    )


def test_a_public_address_with_no_host_gives_no_allowed_hosts_rather_than_a_guess() -> None:
    settings = development_settings(public_base_url="https://portal.example.test")
    assert settings.allowed_hosts[0] == "portal.example.test"
    hostless = settings.model_copy(update={"public_base_url": "https:///patient"})
    with pytest.raises(ValueError, match="PUBLIC_BASE_URL must contain a hostname"):
        _ = hostless.allowed_hosts


# --------------------------------------------------------------------------------------------
# One value at a time
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("field", ["database_schema_owner_role", "database_maintenance_role"])
def test_a_database_role_name_must_be_one_to_sixty_three_bytes(field) -> None:
    assert getattr(development_settings(**{field: "r" * 63}), field) == "r" * 63
    assert getattr(development_settings(**{field: " role "}), field) == "role"
    for bad in ("", "   ", "r" * 64, "é" * 32):  # the last is 64 bytes in 32 characters
        refused(development_settings, "between 1 and 63 UTF-8 bytes", **{field: bad})


def test_a_sender_address_must_be_a_plain_mailbox_with_a_dotted_domain() -> None:
    assert development_settings(
        smtp_host="mail.internal", smtp_from_address="portal@example.test"
    ).smtp_from_address
    for bad in ("portal@nodot", "portal@.example.test", "portal@example.test."):
        refused(
            development_settings,
            "valid mailbox address",
            smtp_host="mail.internal",
            smtp_from_address=bad,
        )
    refused(
        development_settings,
        "one mailbox address without a display name",
        smtp_host="mail.internal",
        smtp_from_address="portal@",
    )


@pytest.mark.parametrize(
    ("field", "name", "good"),
    [
        ("sms_webhook_url", "SMS_WEBHOOK_URL", "https://sms.example.test/messages"),
        ("source_code_url", "SOURCE_CODE_URL", "https://example.test/source"),
    ],
)
def test_a_configured_link_is_http_with_a_host_and_no_credentials_query_or_fragment(
    field, name, good
) -> None:
    # An SMS webhook address is only accepted with its token.
    token = {"sms_webhook_token": "t" * 32} if field == "sms_webhook_url" else {}
    build = partial(development_settings, **token)
    assert getattr(build(**{field: good}), field) == good
    refused(
        development_settings,
        f"{name} must contain a valid port",
        **{field: "https://example.test:99999999/x"},
    )
    for bad in (
        "javascript:alert(1)",
        "ftp://example.test/x",
        "https:///nohost",
        "https://user:pw@example.test/x",
        "https://example.test/x?q=1",
        "https://example.test/x#frag",
    ):
        refused(build, f"{name} must be an HTTP", **{field: bad})


def test_a_clinic_timezone_must_be_an_iana_name() -> None:
    assert (
        development_settings(clinic_timezone=" America/Toronto ").clinic_timezone
        == "America/Toronto"
    )
    refused(development_settings, "must be an IANA timezone", clinic_timezone="Not/AZone")


# --------------------------------------------------------------------------------------------
# The encryption keyrings
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "secret", "keyring", "active"),
    [
        (
            "UNLOCK_SECRET",
            "unlock_secret_encryption_secret",
            "unlock_secret_encryption_keyring",
            "unlock_secret_active_key_id",
        ),
        ("OUTBOX", "outbox_encryption_secret", "outbox_encryption_keyring", "outbox_active_key_id"),
    ],
)
def test_a_keyring_needs_its_active_key_and_is_not_combined_with_a_single_secret(
    label, secret, keyring, active
) -> None:
    ring = json.dumps({"2026-07": "k" * 32, "2026-08": "m" * 32})
    ok = {secret: None, keyring: ring, active: "2026-08"}
    assert staging_settings(**ok)
    # The active key is not in the ring.
    refused(
        staging_settings,
        f"{label}_ACTIVE_KEY_ID must exist in the keyring",
        **{**ok, active: "2027-01"},
    )
    # A single secret and a ring together.
    refused(staging_settings, "not both", **{**ok, secret: "z" * 32})
    # A named active key without any ring.
    refused(
        staging_settings,
        f"{label}_ACTIVE_KEY_ID must be primary",
        **{secret: "z" * 32, keyring: None, active: "2026-08"},
    )


# --------------------------------------------------------------------------------------------
# Outside development: what must be set, and how
# --------------------------------------------------------------------------------------------


def test_outside_development_mail_needs_starttls_and_an_https_public_address() -> None:
    assert staging_settings()
    refused(staging_settings, "SMTP_STARTTLS must be enabled", smtp_starttls=False)
    refused(staging_settings, "PUBLIC_BASE_URL is required when SMTP", public_base_url=None)
    refused(staging_settings, "must use HTTPS", public_base_url="http://portal.example.test")


def test_outside_development_the_sms_webhook_is_set_and_https() -> None:
    refused(
        staging_settings,
        "SMS_WEBHOOK_URL must be set outside development",
        sms_webhook_url=None,
        sms_webhook_token=None,
    )
    refused(
        staging_settings,
        "SMS_WEBHOOK_URL must use HTTPS",
        sms_webhook_url="http://sms.example.test/messages",
    )
    refused(staging_settings, "must be configured together", sms_webhook_token=None)


def test_the_source_link_must_be_https_outside_development_whatever_its_case() -> None:
    assert staging_settings(source_code_url="HTTPS://example.test/source")
    refused(
        staging_settings,
        "SOURCE_CODE_URL must use HTTPS",
        source_code_url="http://example.test/source",
    )


def test_a_trusted_proxy_list_is_set_with_its_header_and_holds_valid_cidrs() -> None:
    ok = {
        "trusted_client_ip_header": "X-Forwarded-For",
        "trusted_proxy_cidrs": "10.0.0.0/8, 192.0.2.0/24",
    }
    assert staging_settings(**ok)
    refused(
        staging_settings, "must be configured together", trusted_client_ip_header="X-Forwarded-For"
    )
    refused(staging_settings, "must be configured together", trusted_proxy_cidrs="10.0.0.0/8")
    refused(staging_settings, "at least one CIDR", **{**ok, "trusted_proxy_cidrs": " , "})
    refused(
        staging_settings,
        "valid comma-separated CIDRs",
        **{**ok, "trusted_proxy_cidrs": "10.0.0.0/8,not-a-network"},
    )


def test_a_deployment_must_name_its_clinic_and_set_each_required_secret() -> None:
    refused(
        staging_settings, "CLINIC_ID must be explicitly configured", clinic_id=DEFAULT_CLINIC_ID
    )
    refused(
        staging_settings,
        "CLINIC_NAME must be explicitly configured",
        clinic_name=DEFAULT_CLINIC_NAME,
    )
    for field, name in (
        ("internal_health_token", "INTERNAL_HEALTH_TOKEN"),
        ("identity_proof_secret", "IDENTITY_PROOF_SECRET"),
        ("audit_hash_secret", "AUDIT_HASH_SECRET"),
    ):
        refused(staging_settings, f"{name} must be set outside development", **{field: None})
    # The same omissions are allowed in development.
    assert development_settings(
        internal_health_token=None, identity_proof_secret=None, audit_hash_secret=None
    )


def test_production_roles_for_the_runtime_the_schema_owner_and_maintenance_must_differ() -> None:
    url = "postgresql+psycopg://{role}@localhost/carlos_portal"
    ok = {"database_url": url.format(role="portal_runtime")}
    assert production_settings(**ok)
    refused(
        production_settings,
        "roles must differ",
        database_url=url.format(role="portal_schema_owner"),
    )
    refused(
        production_settings,
        "roles must differ",
        database_url=url.format(role="portal_audit_maintenance"),
    )
    refused(
        production_settings,
        "roles must differ",
        **ok,
        database_maintenance_role="portal_schema_owner",
    )
    refused(
        production_settings,
        "MAINTENANCE_DATABASE_URL must use",
        **ok,
        maintenance_database_url=url.format(role="someone_else"),
    )
    refused(
        production_settings,
        "valid SQLAlchemy database URL",
        database_url="postgresql+psycopg://portal@localhost:not-a-port/x",
    )


# --------------------------------------------------------------------------------------------
# myCarlos approval, and the outbox worker's smaller bundle
# --------------------------------------------------------------------------------------------


def test_myCarlos_approval_needs_delivery_and_the_mailbox_and_a_valid_public_address() -> None:
    on = {
        "mycarlos_approval_enabled": True,
        "mycarlos_delivery_enabled": True,
        "mycarlos_mailbox_enabled": True,
    }
    base = "https://portal.example.test"
    assert development_settings(**on, public_base_url=base)
    refused(
        development_settings,
        "requires delivery and mailbox",
        **{**on, "mycarlos_delivery_enabled": False},
        public_base_url=base,
    )
    refused(
        development_settings,
        "requires delivery and mailbox",
        **{**on, "mycarlos_mailbox_enabled": False},
        public_base_url=base,
    )
    refused(
        development_settings,
        "myCarlos public portal base is invalid",
        **on,
        public_base_url=" " + base,
    )


def test_the_outbox_settings_refuse_each_web_only_credential_outside_development() -> None:
    assert OutboxSettings(environment="development").is_development
    full = non_development_settings_values("staging")
    web_only = {
        "identity_proof_secret": "IDENTITY_PROOF_SECRET",
        "audit_hash_secret": "AUDIT_HASH_SECRET",
        "unlock_secret_encryption_secret": "UNLOCK_SECRET_ENCRYPTION_SECRET",
        "internal_health_token": "INTERNAL_HEALTH_TOKEN",
        "internal_api_token": "INTERNAL_API_TOKEN",
        "sms_webhook_url": "SMS_WEBHOOK_URL",
        "sms_webhook_token": "SMS_WEBHOOK_TOKEN",
    }
    # Only what the worker needs is accepted; each web-only value added back alone is refused.
    worker = {
        **full,
        **dict.fromkeys(web_only),
        "internal_staff_assertion_public_keyring": None,
    }
    assert (
        OutboxSettings(**worker).secret_value("outbox_encryption_secret")
        == OUTBOX_ENCRYPTION_SECRET
    )
    for field, name in web_only.items():
        with pytest.raises(ValueError, match=f"web-only credentials: .*{name}"):
            OutboxSettings(**{**worker, field: full[field]})
    # And without an outbox key it does not start.
    with pytest.raises(ValueError, match="OUTBOX_ENCRYPTION_SECRET or"):
        OutboxSettings(**{**worker, "outbox_encryption_secret": None})


# --------------------------------------------------------------------------------------------
# A refusal never echoes what it was given
# --------------------------------------------------------------------------------------------


def test_a_settings_error_never_contains_the_values_it_refused() -> None:
    """`hide_input_in_errors=True` keeps secrets out of a start-up traceback and the log.

    Without it pydantic prints `input_value=...` with the whole input, for a field error and for
    a model-level error alike, and these values include the session secret and database password.
    """
    secret = "FAKE-SECRET-MUST-NOT-APPEAR"
    cases = [
        # A field error: the bad value is the secret itself.
        (development_settings, {"smtp_host": "mail.internal", "smtp_from_address": secret}),
        # A model-level error: the secret is a different field's (and too short) value.
        (production_settings, {"session_secret": secret}),
        (
            production_settings,
            {"database_url": f"invalid://portal:{secret}@localhost/portal"},
        ),
    ]
    for build, overrides in cases:
        with pytest.raises(ValueError) as refused:
            build(**overrides)
        text = str(refused.value)
        assert "validation error" in text, overrides  # it is a pydantic refusal, with its reason
        assert secret not in text and "input_value" not in text, overrides
    # The migration job's smaller settings object holds the same rule.
    with pytest.raises(ValueError) as refused:
        MigrationDatabaseSettings(
            environment="production", database_url=f"invalid://portal:{secret}@localhost/portal"
        )
    assert "validation error" in str(refused.value)
    assert secret not in str(refused.value) and "input_value" not in str(refused.value)
