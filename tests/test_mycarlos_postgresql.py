# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

"""Migrate and check myCarlos linking on PostgreSQL (carlos-portal#41, M2-a/M2-c).

The limits hold because checking a code locks the account row and then the link row: one code
links one device however many requests race, and concurrent wrong codes never count past 5 per
link or 10 per account. Each test runs real migrations in its own disposable schema, including
the database constraints, audit event vocabulary and downgrade guards.
"""

from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import timedelta
from hashlib import sha256
from itertools import count
from threading import Barrier, Event
from time import monotonic, sleep
from uuid import uuid4

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, delete, func, inspect, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateSchema, DropSchema

from carlos_patient_portal import main, web_support
from carlos_patient_portal.auth import AuthenticatedPortalSession, create_patient_session
from carlos_patient_portal.device_identity import LinkRequest
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalMfaChallenge,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosLinkCode,
    PatientPortalMyCarlosLinkFailure,
    PatientPortalMyCarlosRecipient,
    PatientPortalSession,
    utc_now,
)
from carlos_patient_portal.mycarlos_links import create_link_code, link_device
from carlos_patient_portal.mycarlos_devices import ClinicKeyPublishError, ClinicKeySpec, publish_clinic_keys
from carlos_patient_portal.runtime import auth_policy_from_settings
from carlos_patient_portal.token_keys import PortalTokenKeys
from tests import delivery_contract_reference as ref
from tests.support import (
    RecordingPortalSmsSender,
    alembic_config_for_tests,
    migrated_development_app,
    upgrade_to_head,
)
from tests.test_postgresql_integration import POSTGRES_URL
from tests.test_link_lifecycle_routes import native_portal, signed_assertion, RECOVERY, NOW_AT
from carlos_patient_portal.routes import mycarlos as mycarlos_routes

pytestmark = pytest.mark.skipif(
    POSTGRES_URL is None,
    reason="PORTAL_TEST_POSTGRES_URL is required for PostgreSQL integration tests",
)


def test_first_clinic_publish_has_a_stable_mutex_before_complete_inventory_validation(
    migrated_postgresql_engine,
):
    """Different first key rows cannot evade one clinic's complete-inventory transaction."""
    engine = migrated_postgresql_engine
    factory = sessionmaker(bind=engine)
    first_key = ref.ClinicKey("FAKE PostgreSQL first publisher A", "clinic-a")
    second_key = ref.ClinicKey("FAKE PostgreSQL first publisher B", "clinic-a")
    first_published = Event()
    release_first = Event()
    second_connected = Event()
    second_pid = []

    def first_publish():
        with factory.begin() as session:
            publish_clinic_keys(
                session, clinic_id="clinic-a",
                specs=[ClinicKeySpec(first_key.kid, first_key.spki, "active")],
            )
            first_published.set()
            assert release_first.wait(5)

    def second_publish():
        try:
            with factory.begin() as session:
                second_pid.append(session.scalar(text("select pg_backend_pid()")))
                second_connected.set()
                publish_clinic_keys(
                    session, clinic_id="clinic-a",
                    specs=[ClinicKeySpec(second_key.kid, second_key.spki, "active")],
                )
        except ClinicKeyPublishError as exc:
            return exc.code
        return "published"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(first_publish)
        try:
            assert first_published.wait(5)
            second = pool.submit(second_publish)
            assert second_connected.wait(5)
            waiting = False
            deadline = monotonic() + 5
            while monotonic() < deadline:
                with engine.connect() as observer:
                    waiting = observer.scalar(text(
                        "select exists(select 1 from pg_locks where pid=:pid "
                        "and locktype='advisory' and not granted)"
                    ), {"pid": second_pid[0]})
                if waiting or second.done():
                    break
                sleep(0.02)
            assert waiting, "second publisher must wait even when the first key row is uncommitted"
        finally:
            release_first.set()
        first.result(timeout=5)
        assert second.result(timeout=5) == "key_missing"
    with factory() as session:
        assert list(session.scalars(select(PatientPortalClinicKey.kid))) == [first_key.kid]


def test_recovery_rechecks_removal_after_waiting_on_the_account_lock(
    migrated_postgresql_engine, monkeypatch,
):
    engine = migrated_postgresql_engine
    with engine.connect() as connection:
        assert connection.scalar(text("select current_schema()")).startswith("mycarlos_test_")
    monkeypatch.setattr(main, "create_portal_engine", lambda *_args, **_kwargs: engine)
    app, client, _proxy, account_id = native_portal(database_url=POSTGRES_URL)
    snapshot = Event()
    original_find = mycarlos_routes.find_device_record

    def snapshot_device(session, kid):
        result = original_find(session, kid)
        if result is not None:
            snapshot.set()
        return result

    monkeypatch.setattr(mycarlos_routes, "find_device_record", snapshot_device)
    assertion = signed_assertion(RECOVERY)
    with ThreadPoolExecutor(max_workers=1) as pool:
        with app.state.session_factory() as holder, holder.begin():
            holder.scalar(select(PatientPortalAccount).where(
                PatientPortalAccount.id == account_id
            ).with_for_update())
            request = pool.submit(
                client.get, RECOVERY, headers={"X-MyCarlos-Device-Assertion": assertion}
            )
            assert snapshot.wait(5)
            device = holder.scalar(select(PatientPortalMyCarlosDevice).where(
                PatientPortalMyCarlosDevice.account_id == account_id
            ).with_for_update())
            device.status = "removed"
            device.removed_at = NOW_AT
            device.removed_by = "patient"
        response = request.result(timeout=5)
    assert response.status_code == 403
    assert response.json() == {"code": "device_removed"}
    with app.state.session_factory() as session:
        assert session.scalar(select(PatientPortalMyCarlosDevice.status)) == "removed"
        assert session.scalar(select(func.count()).select_from(PatientPortalMyCarlosLinkCode)) == 0

LINK_KEY = PortalTokenKeys.derive("p" * 32).mycarlos_link
IDLE = timedelta(minutes=10)
SESSION_NUMBERS = count(1)


@pytest.fixture
def migrated_postgresql_engine() -> Iterator[Engine]:
    """Migrate only a fresh, owned schema; never truncate the shared database."""
    assert POSTGRES_URL is not None
    schema = f"mycarlos_test_{uuid4().hex}"
    admin_engine = create_engine(POSTGRES_URL)
    engine = create_engine(POSTGRES_URL, connect_args={"options": f"-csearch_path={schema}"})
    created = False
    try:
        with admin_engine.begin() as connection:
            connection.execute(CreateSchema(schema))
        created = True
        upgrade_to_head(engine)
        yield engine
    finally:
        engine.dispose()
        try:
            if created:
                with admin_engine.begin() as connection:
                    connection.execute(DropSchema(schema, cascade=True))
        finally:
            admin_engine.dispose()


def downgrade_linking(engine: Engine) -> None:
    with engine.begin() as connection:
        config = alembic_config_for_tests()
        config.attributes["connection"] = connection
        command.downgrade(config, "0016_job_assertion_audit")


def account_with_session(
    session_factory: sessionmaker, demographic_no: int = 6001
) -> tuple[int, int]:
    now = utc_now()
    with session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id="postgres-clinic",
            demographic_no=demographic_no,
            username=f"fake.postgres.link{demographic_no}",
            email=f"postgres.link{demographic_no}@example.test",
            password_hash="FAKE-not-a-real-hash",
            status="active",
        )
        session.add(account)
        session.flush()
        portal_session = PatientPortalSession(
            account_id=account.id,
            token_hash=sha256(f"FAKE session {next(SESSION_NUMBERS)}".encode()).hexdigest(),
            created_at=now,
            expires_at=now + timedelta(hours=1),
            last_seen_at=now,
        )
        session.add(portal_session)
        session.flush()
        return account.id, portal_session.id


def new_code(session_factory: sessionmaker, account_id: int, session_id: int):
    with session_factory() as session, session.begin():
        return create_link_code(
            session,
            account_id=account_id,
            session_id=session_id,
            key=LINK_KEY,
            idle_timeout=IDLE,
        )


def request_for(link_id: str, code: str, label: str) -> LinkRequest:
    device = ref.DeviceKeys(f"postgres {label}")
    return LinkRequest(
        link_id=link_id,
        code=code,
        device_name="myCarlos on Linux",
        x25519_public_key=device.x25519_public,
        ed25519_public_key=device.ed25519_public,
        device_key_id=device.device_key_id,
        assertion_id="not-used-here",
        assertion_expires_at=0,
    )


def wrong(code: str) -> str:
    return ("0" if code[0] != "0" else "1") + code[1:]


def race(session_factory: sessionmaker, requests: list[LinkRequest]) -> list[str]:
    barrier = Barrier(len(requests))

    def attempt(request: LinkRequest) -> str:
        barrier.wait(timeout=10)
        with session_factory() as session, session.begin():
            return link_device(session, request, key=LINK_KEY, idle_timeout=IDLE).code

    with ThreadPoolExecutor(max_workers=len(requests)) as executor:
        return sorted(executor.map(attempt, requests))


def test_postgresql_one_code_links_one_device_when_two_requests_race(
    migrated_postgresql_engine: Engine,
) -> None:
    engine = migrated_postgresql_engine
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        account_id, session_id = account_with_session(session_factory)
        issued = new_code(session_factory, account_id, session_id)
        results = race(
            session_factory,
            [request_for(issued.link_id, issued.code, label) for label in ("first", "second")],
        )
        with session_factory() as session:
            devices = session.scalar(select(func.count()).select_from(PatientPortalMyCarlosDevice))
            link = session.scalar(select(PatientPortalMyCarlosLinkCode))
        assert results == ["link_code_invalid", "linked"]
        assert devices == 1
        assert link.status == "used"
    finally:
        engine.dispose()


def test_postgresql_concurrent_wrong_codes_stop_at_five_for_a_link(
    migrated_postgresql_engine: Engine,
) -> None:
    engine = migrated_postgresql_engine
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        account_id, session_id = account_with_session(session_factory)
        issued = new_code(session_factory, account_id, session_id)
        results = race(
            session_factory,
            [request_for(issued.link_id, wrong(issued.code), f"wrong {n}") for n in range(8)],
        )
        with session_factory() as session:
            failures = session.scalar(
                select(func.count()).select_from(PatientPortalMyCarlosLinkFailure)
            )
            link = session.scalar(select(PatientPortalMyCarlosLinkCode))
        assert results == ["link_code_invalid"] * 8
        assert (failures, link.wrong_codes) == (5, 5)
    finally:
        engine.dispose()


def test_postgresql_concurrent_wrong_codes_stop_at_ten_for_an_account(
    migrated_postgresql_engine: Engine,
) -> None:
    engine = migrated_postgresql_engine
    session_factory = sessionmaker(bind=engine, expire_on_commit=False)
    try:
        account_id, session_id = account_with_session(session_factory)
        codes = [new_code(session_factory, account_id, session_id) for _ in range(3)]
        requests = [
            request_for(issued.link_id, wrong(issued.code), f"account {issued.link_id} {n}")
            for issued in codes
            for n in range(5)
        ]
        results = race(session_factory, requests)
        with session_factory() as session:
            failures = session.scalar(
                select(func.count()).select_from(PatientPortalMyCarlosLinkFailure)
            )
        assert results == ["link_code_invalid"] * 15
        assert failures == 10
    finally:
        engine.dispose()


def stored_device(
    owner_account_id: int, label: str, **changes: object
) -> PatientPortalMyCarlosDevice:
    keys = ref.DeviceKeys(label)
    values: dict[str, object] = {
        "account_id": owner_account_id,
        "device_key_id": keys.device_key_id,
        "x25519_public_key": keys.x25519_public,
        "ed25519_public_key": keys.ed25519_public,
        "device_name": "FAKE PostgreSQL device",
        "status": "active",
        "linked_at": utc_now(),
    }
    values.update(changes)
    return PatientPortalMyCarlosDevice(**values)


@pytest.mark.parametrize(
    ("changes", "sqlstate"),
    [
        ({"x25519_public_key": b"x" * 31}, "23514"),
        ({"ed25519_public_key": b"e" * 33}, "23514"),
        ({"status": "removed"}, "23514"),
        ({"account_id": 2_147_483_647}, "23503"),
    ],
)
def test_postgresql_migration_enforces_device_checks_and_account_foreign_key(
    migrated_postgresql_engine: Engine, changes: dict[str, object], sqlstate: str
) -> None:
    session_factory = sessionmaker(bind=migrated_postgresql_engine)
    account_id, _session_id = account_with_session(session_factory)
    with pytest.raises(IntegrityError) as refused:
        with session_factory.begin() as session:
            session.add(stored_device(account_id, "postgres invalid device", **changes))
    assert refused.value.orig.sqlstate == sqlstate


def test_postgresql_device_keys_and_recipients_are_unique_across_accounts(
    migrated_postgresql_engine: Engine,
) -> None:
    session_factory = sessionmaker(bind=migrated_postgresql_engine)
    first, _first_session = account_with_session(session_factory, 6001)
    second, _second_session = account_with_session(session_factory, 6002)
    with session_factory.begin() as session:
        session.add(stored_device(first, "postgres same device"))
        session.add(
            PatientPortalMyCarlosRecipient(
                account_id=first, recipient_id="rcp-FAKE-postgres-unique", created_at=utc_now()
            )
        )
    with pytest.raises(IntegrityError) as duplicate_device:
        with session_factory.begin() as session:
            session.add(stored_device(second, "postgres same device"))
    assert duplicate_device.value.orig.sqlstate == "23505"
    with pytest.raises(IntegrityError) as duplicate_recipient:
        with session_factory.begin() as session:
            session.add(
                PatientPortalMyCarlosRecipient(
                    account_id=second, recipient_id="rcp-FAKE-postgres-unique", created_at=utc_now()
                )
            )
    assert duplicate_recipient.value.orig.sqlstate == "23505"


def test_postgresql_audit_constraint_keeps_existing_and_mycarlos_events(
    migrated_postgresql_engine: Engine,
) -> None:
    session_factory = sessionmaker(bind=migrated_postgresql_engine)
    with session_factory.begin() as session:
        for event_type in (
            "job.auth_refused",
            "mycarlos.clinic_keys_publish",
            "mycarlos.device_list",
            "mycarlos.device_remove",
            "mycarlos.link",
            "mycarlos.link_code_create",
        ):
            session.add(
                PatientPortalAuditEvent(
                    event_type=event_type,
                    outcome="success",
                    actor_type="system",
                    created_at=utc_now(),
                )
            )
    with pytest.raises(IntegrityError) as unknown_event:
        with session_factory.begin() as session:
            session.add(
                PatientPortalAuditEvent(
                    event_type="mycarlos.made_up",
                    outcome="success",
                    actor_type="system",
                    created_at=utc_now(),
                )
            )
    assert unknown_event.value.orig.sqlstate == "23514"
    with pytest.raises(RuntimeError, match="myCarlos audit events exist"):
        downgrade_linking(migrated_postgresql_engine)


def test_postgresql_linking_migration_round_trip_and_populated_downgrade_guard(
    migrated_postgresql_engine: Engine,
) -> None:
    engine = migrated_postgresql_engine
    tables = {
        "patient_portal_clinic_keys",
        "patient_portal_mycarlos_devices",
        "patient_portal_mycarlos_link_codes",
        "patient_portal_mycarlos_link_failures",
        "patient_portal_mycarlos_recipients",
    }
    assert tables <= set(inspect(engine).get_table_names())
    indexes = inspect(engine).get_indexes("patient_portal_mycarlos_link_codes")
    assert any(index["column_names"] == ["session_id"] for index in indexes)
    downgrade_linking(engine)
    assert tables.isdisjoint(inspect(engine).get_table_names())
    upgrade_to_head(engine)
    assert tables <= set(inspect(engine).get_table_names())
    session_factory = sessionmaker(bind=engine)
    account_id, _session_id = account_with_session(session_factory)
    with session_factory.begin() as session:
        session.add(stored_device(account_id, "postgres retained device"))
    with pytest.raises(RuntimeError, match="myCarlos devices are linked"):
        downgrade_linking(engine)
    assert tables <= set(inspect(engine).get_table_names())


def step_up_app(monkeypatch, engine: Engine, initial_snapshot):
    """Exercise real HTTP handlers against only the fixture's migrated, owned PostgreSQL schema."""
    with engine.connect() as connection:
        assert connection.scalar(text("select current_schema()")).startswith("mycarlos_test_")
    monkeypatch.setattr(main, "create_portal_engine", lambda *_args, **_kwargs: engine)
    original_builder = main.build_route_dependencies

    def synchronized_dependencies(runtime):
        dependencies = original_builder(runtime)
        authenticate = dependencies.get_portal_cookie_session_or_redirect

        def synchronized_authentication(request, session):
            result = authenticate(request, session)
            if (
                isinstance(result, AuthenticatedPortalSession)
                and request.url.path == "/portal/mycarlos/mfa"
                and not getattr(request.state, "mfa_test_snapshot", False)
            ):
                request.state.mfa_test_snapshot = True
                initial_snapshot()
            return result

        return replace(
            dependencies, get_portal_cookie_session_or_redirect=synchronized_authentication
        )

    monkeypatch.setattr(main, "build_route_dependencies", synchronized_dependencies)
    sms = RecordingPortalSmsSender()
    app = migrated_development_app(
        database_url=POSTGRES_URL,
        session_secret="FAKE PostgreSQL MFA session root" * 2,
        require_mfa=False,
        session_idle_timeout_seconds=1800,
        mycarlos_delivery_enabled=True,
        sms_sender=sms,
    )
    return app, sms


def step_up_sessions(app, *, count: int = 2, stale: bool = False):
    settings = app.state.settings
    assert settings.session_secret is not None
    keys = PortalTokenKeys.derive(settings.session_secret.get_secret_value())
    policy = auth_policy_from_settings(settings)
    now = utc_now()
    with app.state.session_factory() as session, session.begin():
        account = PatientPortalAccount(
            clinic_id=settings.clinic_id,
            demographic_no=7101,
            username="fake.postgres.mfa",
            email="mfa@example.test",
            phone_number="+15555550123",
            preferred_mfa_method="sms",
            password_hash="FAKE-cookie-session-already-authenticated",
            status="active",
            created_at=now - timedelta(hours=1),
        )
        session.add(account)
        session.flush()
        tokens = [
            create_patient_session(
                session,
                account,
                policy=policy,
                session_token_secret=keys.session,
                now=now - timedelta(minutes=6) if stale else now,
            )
            for _ in range(count)
        ]
        session_ids = list(session.scalars(select(PatientPortalSession.id)))
        account_id = account.id
    return account_id, tokens, session_ids, keys


def step_up_client(app, token: str, keys: PortalTokenKeys):
    client = TestClient(app)
    csrf = web_support.create_csrf_token(keys.csrf)
    client.cookies.set(web_support.PORTAL_SESSION_COOKIE_NAME, token, path="/portal")
    client.cookies.set(web_support.CSRF_COOKIE_NAME, csrf)
    return client, csrf


def test_postgresql_two_authenticated_sessions_cannot_bypass_sms_cooldown(
    migrated_postgresql_engine: Engine, monkeypatch
) -> None:
    snapshots = Barrier(2)
    app, sms = step_up_app(
        monkeypatch, migrated_postgresql_engine, lambda: snapshots.wait(timeout=10)
    )
    _account_id, tokens, _session_ids, keys = step_up_sessions(app)
    clients = [step_up_client(app, token, keys) for token in tokens]
    try:

        def request_step_up(client_and_csrf):
            client, csrf = client_and_csrf
            return client.post("/portal/mycarlos/mfa", data={"csrf_token": csrf}).status_code

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = sorted(executor.map(request_step_up, clients))
        assert results == [200, 429]
        assert len(sms.messages) == 1
        with app.state.session_factory() as session:
            assert session.scalar(select(func.count()).select_from(PatientPortalMfaChallenge)) == 1
    finally:
        for client, _csrf in clients:
            client.close()


@pytest.mark.parametrize("change", ["revoked", "deleted"])
def test_postgresql_session_invalidated_while_waiting_never_starts_mfa(
    migrated_postgresql_engine: Engine, monkeypatch, change: str
) -> None:
    authenticated = Event()
    app, sms = step_up_app(monkeypatch, migrated_postgresql_engine, authenticated.set)
    account_id, tokens, session_ids, keys = step_up_sessions(app, count=1, stale=True)
    client, csrf = step_up_client(app, tokens[0], keys)
    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            with app.state.session_factory() as holder, holder.begin():
                holder.scalar(
                    select(PatientPortalAccount)
                    .where(PatientPortalAccount.id == account_id)
                    .with_for_update()
                )
                pending = executor.submit(
                    client.post,
                    "/portal/mycarlos/mfa",
                    data={"csrf_token": csrf},
                    follow_redirects=False,
                )
                assert authenticated.wait(timeout=10)
                if change == "deleted":
                    holder.execute(
                        delete(PatientPortalSession).where(
                            PatientPortalSession.id == session_ids[0]
                        )
                    )
                else:
                    holder.execute(
                        update(PatientPortalSession)
                        .where(PatientPortalSession.id == session_ids[0])
                        .values(revoked_at=utc_now(), revoked_reason="FAKE concurrent removal")
                    )
            response = pending.result(timeout=10)
        assert response.status_code == 303
        assert not sms.messages
        with app.state.session_factory() as session:
            assert session.scalar(select(func.count()).select_from(PatientPortalMfaChallenge)) == 0
    finally:
        client.close()
