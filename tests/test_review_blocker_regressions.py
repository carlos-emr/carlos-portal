"""Regression cover for the blocking defects found in the PR #3220 review.

Each test here pins a control that was either absent or defeated, and would fail again if the
corresponding fix were reverted. Grouped in one module deliberately: they share no theme beyond
being the security regressions that review turned up, and keeping them together makes it obvious
which behaviour is load-bearing for that review.
"""

import ast
import logging
from datetime import timedelta
from pathlib import Path

import pytest
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, text
from sqlalchemy.pool import StaticPool

from carlos_patient_portal import auth
from carlos_patient_portal.auth import (
    AUTH_LOCKED_BY_AUTOMATION,
    MfaChallengeDelivery,
    PasswordResetRequestResult,
    hash_auth_token,
    hash_mfa_code,
)
from carlos_patient_portal.config import DEFAULT_PROBE_ALLOWED_HOSTS
from carlos_patient_portal.database import Base
from carlos_patient_portal.delivery_outbox import (
    enqueue_contact_change_delivery,
    process_one_delivery,
)
from carlos_patient_portal.email_delivery import PortalEmailDeliveryError
from carlos_patient_portal.models import (
    AUDIT_EVENT_ACCOUNT_CONTACT_UPDATE,
    AUDIT_EVENT_ACCOUNT_UNLOCK,
    AUDIT_OUTCOME_FAILURE,
    OUTBOX_KIND_CONTACT_CHANGE,
    OUTBOX_STATUS_FAILED,
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalOutboundDelivery,
    PatientPortalPasswordResetToken,
    PatientPortalSession,
    utc_now,
)
from carlos_patient_portal.token_keys import PortalTokenKeys
from carlos_patient_portal.web_support import is_rate_limited_path
from tests.support import (
    INTERNAL_API_TOKEN,
    OUTBOX_ENCRYPTION_SECRET,
    SEEDED_INVITE_EMAIL,
    STRONG_PASSWORD,
    activate_seeded_patient_account,
    alembic_config_for_tests,
    browser_sign_in_seeded_patient,
    migrated_development_app,
    upgrade_to_head,
)

SECRET = "regression-secret-value-32-characters"
SEEDED_USERNAME = "patient.user"
# Alembic creates alembic_version.version_num as VARCHAR(32) and never widens it.
ALEMBIC_VERSION_NUM_LENGTH = 32


# --------------------------------------------------------------------------------------
# Schema drift - the migrations are the only source of schema, and they must match the models
# --------------------------------------------------------------------------------------


def test_migrated_schema_matches_the_models_exactly() -> None:
    """Fail the build when a migration and `models.py` drift apart.

    The suite used to build its schema with `create_all` and then *stamp* the Alembic head, so no
    test ever executed migrations 0003+ and a migration that forgot a column would pass pytest,
    pass `alembic upgrade head`, and pass the readiness probe. The harness now migrates, and this
    asserts the end state is what the models describe.
    """
    engine = create_engine("sqlite+pysqlite:///:memory:", poolclass=StaticPool)
    try:
        upgrade_to_head(engine)
        with engine.connect() as connection:
            differences = compare_metadata(MigrationContext.configure(connection), Base.metadata)
    finally:
        engine.dispose()

    assert differences == [], f"migrations and models.py disagree: {differences}"


# --------------------------------------------------------------------------------------
# Revision identifiers - a revision id that overflows alembic_version strands every PostgreSQL
# --------------------------------------------------------------------------------------


def test_every_revision_id_fits_the_alembic_version_column() -> None:
    """Fail the build when a revision id cannot be written to `alembic_version`.

    Alembic creates `alembic_version.version_num` as VARCHAR(32). SQLite ignores a declared width,
    so an over-long id migrates cleanly there and raises StringDataRightTruncation only on
    PostgreSQL -- leaving pytest, the SQLite round trip, and the whole 3.11 matrix leg green while
    no PostgreSQL database could reach head at all. Measuring the ids puts that on every leg.
    """
    script_directory = ScriptDirectory.from_config(alembic_config_for_tests())
    over_limit = {
        script.revision: len(script.revision)
        for script in script_directory.walk_revisions()
        if len(script.revision) > ALEMBIC_VERSION_NUM_LENGTH
    }

    assert over_limit == {}, f"revision ids exceed alembic_version.version_num: {over_limit}"


def test_populated_v7_database_upgrades_without_reactivating_sessions(tmp_path: Path) -> None:
    """Historical contact proofs must migrate while incomplete revocations fail closed."""
    database_path = tmp_path / "populated-v7.db"
    config = alembic_config_for_tests()
    config.set_main_option("sqlalchemy.url", f"sqlite+pysqlite:///{database_path}")
    command.upgrade(config, "0007_durable_outbound_delivery")

    engine = create_engine(f"sqlite+pysqlite:///{database_path}")
    now = utc_now()
    with engine.begin() as connection:
        connection.execute(
            text(
                "insert into patient_portal_accounts ("
                "id, clinic_id, demographic_no, username, email, preferred_mfa_method, "
                "password_hash, status, failed_login_count, force_password_reset, created_at, "
                "updated_at, password_updated_at, failed_mfa_count"
                ") values ("
                "1, 'default', 1234, 'patient.user', 'patient@example.test', 'email', "
                "'stored-hash', 'active', 0, false, :now, :now, :now, 0"
                ")"
            ),
            {"now": now},
        )
        connection.execute(
            text(
                "insert into patient_portal_email_change_requests ("
                "id, account_id, token_hash, status, new_email, created_at, expires_at, "
                "confirmed_at"
                ") values (1, 1, :token_hash, 'confirmed', 'new@example.test', "
                ":created_at, :expires_at, :confirmed_at)"
            ),
            {
                "token_hash": "e" * 64,
                "created_at": now - timedelta(days=2),
                "expires_at": now - timedelta(days=1),
                "confirmed_at": now - timedelta(days=1, hours=12),
            },
        )
        connection.execute(
            text(
                "insert into patient_portal_sessions ("
                "id, account_id, token_hash, created_at, expires_at, revoked_reason"
                ") values (1, 1, :token_hash, :created_at, :expires_at, 'logout')"
            ),
            {
                "token_hash": "s" * 64,
                "created_at": now - timedelta(hours=1),
                "expires_at": now + timedelta(hours=1),
            },
        )
    engine.dispose()

    command.upgrade(config, "head")

    engine = create_engine(f"sqlite+pysqlite:///{database_path}")
    try:
        with engine.connect() as connection:
            proof_row = connection.execute(
                text(
                    "select confirmed_at, email_confirmed_at, phone_confirmed_at "
                    "from patient_portal_email_change_requests where id = 1"
                )
            ).one()
            revoked_row = connection.execute(
                text(
                    "select revoked_at, revoked_reason from patient_portal_sessions where id = 1"
                )
            ).one()
    finally:
        engine.dispose()

    assert proof_row.email_confirmed_at == proof_row.confirmed_at
    assert proof_row.phone_confirmed_at == proof_row.confirmed_at
    assert revoked_row.revoked_at is not None
    assert revoked_row.revoked_reason == "logout"


def test_async_routes_do_not_call_sync_session_io_directly() -> None:
    """A future async route must not put blocking driver calls back on the event loop."""
    package_root = Path(__file__).parents[1] / "carlos_patient_portal"
    route_files = (
        package_root / "routes" / "activation.py",
        package_root / "routes" / "auth.py",
        package_root / "routes" / "portal.py",
    )
    blocking_methods = {"commit", "rollback", "execute", "scalar", "scalars", "flush", "get"}
    violations: list[str] = []

    for route_file in route_files:
        tree = ast.parse(route_file.read_text(encoding="utf-8"), filename=str(route_file))

        class AsyncSessionCallVisitor(ast.NodeVisitor):
            def __init__(self, file_name: str) -> None:
                self.in_async_function = 0
                self.file_name = file_name

            def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
                self.in_async_function += 1
                self.generic_visit(node)
                self.in_async_function -= 1

            def visit_Call(self, node: ast.Call) -> None:
                if (
                    self.in_async_function
                    and isinstance(node.func, ast.Attribute)
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "session"
                    and node.func.attr in blocking_methods
                ):
                    violations.append(
                        f"{self.file_name}:{node.lineno} session.{node.func.attr}"
                    )
                self.generic_visit(node)

        AsyncSessionCallVisitor(route_file.name).visit(tree)

    assert violations == []


def test_unhandled_exception_log_omits_exception_details_and_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Unexpected database-style failures must not copy bound patient values into logs."""
    app = migrated_development_app()
    secret_patient_value = "patient.email@example.test"

    @app.get("/test/unhandled-error")
    async def raise_unhandled_error() -> None:
        raise RuntimeError(secret_patient_value)

    caplog.set_level(logging.ERROR, logger="carlos_patient_portal.main")
    response = TestClient(app, raise_server_exceptions=False).get("/test/unhandled-error")

    assert response.status_code == 500
    records = [
        record for record in caplog.records if record.name == "carlos_patient_portal.main"
    ]
    assert records
    assert all(record.exc_info is None for record in records)
    assert all(secret_patient_value not in record.getMessage() for record in records)


# --------------------------------------------------------------------------------------
# Probe hosts - IPv6 literals cannot be allowlisted, so we must not claim they can
# --------------------------------------------------------------------------------------


def test_ipv6_literal_host_is_rejected_and_no_longer_advertised_as_a_default() -> None:
    """Pin the IPv6 limitation instead of shipping a default that silently never matches.

    TrustedHostMiddleware derives the host as `headers["host"].split(":")[0]`, which yields "[" for
    a bracketed literal and "" for a bare one. `[::1]` therefore sat in the defaults implying IPv6
    probes worked when they always got 400 -- which on a dual-stack cluster reads as an unhealthy
    pod. The only pattern that would match is "[", which would accept every IPv6 host.
    """
    assert "[::1]" not in DEFAULT_PROBE_ALLOWED_HOSTS
    assert "::1" not in DEFAULT_PROBE_ALLOWED_HOSTS

    app = migrated_development_app()
    client = TestClient(app)

    assert client.get("/health", headers={"Host": "127.0.0.1:8000"}).status_code == 200
    assert client.get("/health", headers={"Host": "[::1]:8000"}).status_code == 400


# --------------------------------------------------------------------------------------
# Secret material must never reach a log line through a default dataclass repr
# --------------------------------------------------------------------------------------


def test_secret_bearing_dataclasses_keep_their_material_out_of_repr() -> None:
    """One `logger.warning("... %s", delivery)` should not write a live MFA code to the log."""
    delivery = MfaChallengeDelivery(
        challenge_id=1,
        challenge_token="CHALLENGE-TOKEN-SECRET",
        code="123456",
        delivery_method="email",
        destination="patient@example.test",
        available_delivery_methods=("email",),
        expires_at=utc_now(),
        expected_code_hash="EXPECTED-HASH-SECRET",
    )
    rendered = repr(delivery)
    for secret in ("CHALLENGE-TOKEN-SECRET", "123456", "EXPECTED-HASH-SECRET"):
        assert secret not in rendered
    # Fields that are useful for diagnosis are deliberately still shown.
    assert "email" in rendered

    keys = PortalTokenKeys(
        csrf="CSRF-KEY", session="SESSION-KEY", mfa="MFA-KEY",
        password_reset="RESET-KEY", email_change="CHANGE-KEY",
    )
    assert not any(
        key in repr(keys)
        for key in ("CSRF-KEY", "SESSION-KEY", "MFA-KEY", "RESET-KEY", "CHANGE-KEY")
    )

    assert "RESET-TOKEN-SECRET" not in repr(
        PasswordResetRequestResult(reset_token="RESET-TOKEN-SECRET", recipient="p@example.test")
    )


# --------------------------------------------------------------------------------------
# Blocker 4 - MFA challenge-token normalization asymmetry
# --------------------------------------------------------------------------------------


def test_mfa_code_hash_normalizes_the_challenge_token_like_the_lookup_hash() -> None:
    """A padded challenge token must not produce a code hash the clean token can never match.

    hash_auth_token strips before hashing, so a padded token still resolved to a real challenge. If
    hash_mfa_code does not strip identically, that challenge's code_hash is keyed on the padded form
    and the correct code can never verify -- while every rejected attempt spends the MFA failure
    budget toward a lockout.
    """
    padded = " abc123\n"
    clean = "abc123"

    assert hash_auth_token(SECRET, "mfa_challenge", padded) == hash_auth_token(
        SECRET, "mfa_challenge", clean
    )
    assert hash_mfa_code(SECRET, padded, "123456") == hash_mfa_code(SECRET, clean, "123456")


def test_mfa_code_hash_rejects_a_blank_challenge_token() -> None:
    with pytest.raises(ValueError):
        hash_mfa_code(SECRET, "   ", "123456")


# --------------------------------------------------------------------------------------
# Blocker 2 - unauthenticated write amplification against the internal API
# --------------------------------------------------------------------------------------


def test_internal_carlos_prefix_is_rate_limited_but_probe_endpoints_are_not() -> None:
    """Every failed /internal/carlos/** request writes an audit row, so it must be throttled.

    The probe endpoints must stay unthrottled: an orchestrator polls them on a fixed interval and a
    429 there turns a healthy service into a failing liveness check.
    """
    assert is_rate_limited_path("/internal/carlos/patients/1/unlock-secrets")
    assert is_rate_limited_path("/internal/carlos/contact-reviews")

    assert not is_rate_limited_path("/internal/health/db")
    assert not is_rate_limited_path("/internal/readiness")
    assert not is_rate_limited_path("/internal/metrics")

    # The patient-facing surface is unchanged.
    assert is_rate_limited_path("/auth/login")
    assert is_rate_limited_path("/portal/account")


def test_unauthenticated_internal_failures_are_attributable_to_a_client() -> None:
    """Without a client reference every unauthenticated failure row is identical.

    A flood then cannot be told apart from one misconfigured caller, which is precisely the signal
    the middleware exists to preserve.
    """
    # The internal router is only mounted when a service token is configured.
    app = migrated_development_app(internal_api_token=INTERNAL_API_TOKEN)
    client = TestClient(app)

    # Asserted so this cannot pass vacuously against an unmounted router: the audit middleware keys
    # off the path prefix, so a genuinely missing route would still produce a row.
    assert "/internal/carlos/contact-reviews" in {
        getattr(route, "path", "") for route in app.routes
    }

    response = client.get("/internal/carlos/contact-reviews")
    # 404, not 401: service-auth failure deliberately fails closed without confirming the endpoint
    # exists to an unauthenticated caller.
    assert response.status_code == 404

    with app.state.session_factory() as session:
        events = list(
            session.scalars(
                select(PatientPortalAuditEvent).where(
                    PatientPortalAuditEvent.resource_type == "internal_api"
                )
            )
        )

    assert events, "a failed internal request must leave an audit row"
    assert all(event.client_reference_hash is not None for event in events)


# --------------------------------------------------------------------------------------
# Blocker 3 - permanent, remotely triggerable account lockout
# --------------------------------------------------------------------------------------


def drive_account_into_lockout(client: TestClient, attempts: int) -> None:
    for _ in range(attempts):
        client.post(
            "/auth/login",
            json={"username": SEEDED_USERNAME, "password": "Wrong1!password"},
        )


def test_automated_lockout_expires_and_restores_self_service_sign_in(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An automated lockout is time-boxed, so a remote attacker cannot permanently deny access.

    Ten wrong passwords against a known username used to set locked_at with nothing in the system
    able to clear it except clinic staff.
    """
    app = migrated_development_app(auth_max_failed_password_attempts=2)
    client = TestClient(app)
    account_id = activate_seeded_patient_account(app, client)

    drive_account_into_lockout(client, attempts=2)
    locked_response = client.post(
        "/auth/login",
        json={"username": SEEDED_USERNAME, "password": STRONG_PASSWORD},
    )
    assert locked_response.status_code == 423

    started_at = utc_now()
    monkeypatch.setattr(auth, "utc_now", lambda: started_at + timedelta(seconds=901))
    recovered_response = client.post(
        "/auth/login",
        json={"username": SEEDED_USERNAME, "password": STRONG_PASSWORD},
    )

    # A password-only attacker can impose the configured cooling-off period, but cannot force the
    # victim through account recovery. After expiry the correct password resumes the normal flow.
    assert recovered_response.status_code == 200
    assert recovered_response.json()["status"] == "mfa_required"

    with app.state.session_factory() as session:
        stored = session.get(PatientPortalAccount, account_id)
        assert stored is not None
        assert stored.locked_at is None
        assert stored.failed_login_count == 0
        assert stored.force_password_reset is False
        unlock_events = list(
            session.scalars(
                select(PatientPortalAuditEvent).where(
                    PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACCOUNT_UNLOCK
                )
            )
        )
    assert unlock_events, "an expired lockout must leave an audit record of the release"


def test_unauthenticated_password_failures_do_not_revoke_an_active_session() -> None:
    app = migrated_development_app(auth_max_failed_password_attempts=2)
    victim = TestClient(app)
    account_id = browser_sign_in_seeded_patient(app, victim)
    attacker = TestClient(app)

    drive_account_into_lockout(attacker, attempts=2)

    assert victim.get("/portal").status_code == 200
    with app.state.session_factory() as session:
        account = session.get(PatientPortalAccount, account_id)
        active_sessions = list(
            session.scalars(
                select(PatientPortalSession).where(
                    PatientPortalSession.account_id == account_id,
                    PatientPortalSession.revoked_at.is_(None),
                )
            )
        )
        assert account is not None
        assert account.locked_at is not None
        assert account.force_password_reset is False
        assert active_sessions


def test_staff_initiated_lock_is_never_released_by_the_expiry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Only automation-stamped locks are time-boxed; a deliberate staff lock must survive."""
    app = migrated_development_app(auth_max_failed_password_attempts=2)
    client = TestClient(app)
    account_id = activate_seeded_patient_account(app, client)

    with app.state.session_factory() as session:
        with session.begin():
            stored = session.get(PatientPortalAccount, account_id)
            assert stored is not None
            stored.locked_at = utc_now() - timedelta(days=30)
            stored.locked_by = "provider-42"
            stored.locked_by_id = "provider-42"

    response = client.post(
        "/auth/login",
        json={"username": SEEDED_USERNAME, "password": STRONG_PASSWORD},
    )

    assert response.status_code == 423
    with app.state.session_factory() as session:
        stored = session.get(PatientPortalAccount, account_id)
        assert stored is not None
        assert stored.locked_at is not None


def test_locked_out_account_can_still_request_a_password_reset() -> None:
    """The reset path is the patient's only self-service route back in.

    Eligibility previously required locked_at to be null, so the endpoint answered 202 "reset link
    sent" and sent nothing at all.
    """
    app = migrated_development_app(auth_max_failed_password_attempts=2)
    client = TestClient(app)
    account_id = activate_seeded_patient_account(app, client)

    drive_account_into_lockout(client, attempts=2)
    response = client.post(
        "/auth/password-reset/request",
        json={"username": SEEDED_USERNAME, "email": SEEDED_INVITE_EMAIL},
    )

    assert response.status_code == 202
    with app.state.session_factory() as session:
        stored = session.get(PatientPortalAccount, account_id)
        assert stored is not None
        assert stored.locked_by == AUTH_LOCKED_BY_AUTOMATION
        issued = list(
            session.scalars(
                select(PatientPortalPasswordResetToken).where(
                    PatientPortalPasswordResetToken.account_id == account_id
                )
            )
        )
    assert issued, "a locked-out patient must still be issued a reset token"


# --------------------------------------------------------------------------------------
# Blocker 5 - contact-change delivery failure left no audit evidence
# --------------------------------------------------------------------------------------


class AlwaysFailingEmailSender:
    """Stands in for an SMTP outage across every send the outbox can attempt."""

    def send_password_reset(self, *args: object, **kwargs: object) -> None:
        raise PortalEmailDeliveryError("smtp unavailable")

    def send_contact_change_notice(self, *args: object, **kwargs: object) -> None:
        raise PortalEmailDeliveryError("smtp unavailable")


def test_exhausted_contact_change_notice_records_a_failure_audit_event() -> None:
    """The notice to the address a change moved away from is the only out-of-band alarm a patient
    gets. Exhausting the retry budget previously produced a `failed` row and nothing else, so a
    breach review could not enumerate the patients who were never warned.
    """
    app = migrated_development_app()
    client = TestClient(app)
    account_id = activate_seeded_patient_account(app, client)

    with app.state.session_factory() as session:
        with session.begin():
            delivery = enqueue_contact_change_delivery(
                session,
                account_id=account_id,
                recipient="previous@example.test",
                encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            )
            session.flush()
            delivery_id = delivery.id

    for _ in range(8):
        process_one_delivery(
            app.state.session_factory,
            email_sender=AlwaysFailingEmailSender(),
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            max_attempts=8,
            lease_seconds=30,
            delivery_id=delivery_id,
        )
        # Each failure pushes available_at out by the retry backoff, and a row is only claimable
        # once it is due. Pull it back rather than sleeping so the test exercises the full retry
        # budget without wall-clock delay.
        with app.state.session_factory() as session:
            with session.begin():
                queued = session.get(PatientPortalOutboundDelivery, delivery_id)
                if queued is not None:
                    queued.available_at = utc_now() - timedelta(seconds=1)

    with app.state.session_factory() as session:
        stored = session.get(PatientPortalOutboundDelivery, delivery_id)
        assert stored is not None
        assert stored.status == OUTBOX_STATUS_FAILED
        assert stored.kind == OUTBOX_KIND_CONTACT_CHANGE

        failures = list(
            session.scalars(
                select(PatientPortalAuditEvent).where(
                    PatientPortalAuditEvent.event_type == AUDIT_EVENT_ACCOUNT_CONTACT_UPDATE,
                    PatientPortalAuditEvent.outcome == AUDIT_OUTCOME_FAILURE,
                )
            )
        )

    assert failures, "a terminally failed contact-change notice must leave a failure audit row"
    assert failures[0].account_id == account_id
