# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The operator CLI's remaining paths: the outbox worker's loop (idle poll, a fault on one pass, an
interrupt), its argument errors, the outbox status listing, the deployment artifact hash and the
PostgreSQL identity the audit-pruning and deployment probes compare. FAKE data only.

The PostgreSQL identity query itself needs a PostgreSQL server (it reads `pg_control_system()`);
`tests/test_*postgresql*.py` run it there. What is checked here is what is done with its answer,
with a stand-in connection that returns one fixed row.
"""

import logging
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy.exc import SQLAlchemyError

from carlos_patient_portal import cli
from tests.support import OUTBOX_ENCRYPTION_SECRET, development_settings


@pytest.fixture
def worker(monkeypatch, tmp_path):
    """The worker with its settings, sender and clock replaced; returns what it did."""
    settings = development_settings(
        database_url=f"sqlite+pysqlite:///{tmp_path / 'worker.db'}",
        outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET,
    )
    record = SimpleNamespace(sleeps=[], disposed=[], settings=settings)
    monkeypatch.setattr(cli, "get_outbox_settings", lambda: settings)
    monkeypatch.setattr(cli, "build_portal_email_sender", lambda _settings: object())
    monkeypatch.setattr(cli, "sleep", record.sleeps.append)
    real_engine = cli.create_portal_engine

    def engine(*args, **kwargs):
        made = real_engine(*args, **kwargs)
        original = made.dispose
        made.dispose = lambda *a, **k: (record.disposed.append(True), original(*a, **k))[1]
        return made

    monkeypatch.setattr(cli, "create_portal_engine", engine)
    return record


# --------------------------------------------------------------------------------------------
# The worker loop
# --------------------------------------------------------------------------------------------


def test_an_idle_queue_is_polled_again_after_the_poll_interval(monkeypatch, worker) -> None:
    answers = iter([None, None, object()])  # two idle passes, then one delivery ends the run
    monkeypatch.setattr(cli, "process_one_delivery", lambda *a, **k: next(answers))

    cli.outbox_worker(["--max-deliveries", "1"])

    assert worker.sleeps == [worker.settings.outbox_poll_seconds] * 2
    assert worker.disposed == [True]


def test_an_idle_queue_ends_a_run_that_asked_to_drain_once_without_waiting(
    monkeypatch, worker
) -> None:
    calls = []
    monkeypatch.setattr(cli, "process_one_delivery", lambda *a, **k: calls.append(1))

    cli.outbox_worker(["--once"])

    assert (len(calls), worker.sleeps, worker.disposed) == (1, [], [True])


def test_a_database_fault_ends_a_run_that_asked_for_one_pass_and_is_logged_without_the_error(
    monkeypatch, worker, caplog
) -> None:
    caplog.set_level(logging.ERROR, logger="carlos_patient_portal.cli")

    def fault(*args, **kwargs):
        raise SQLAlchemyError("host=db.internal user=portal password=FAKE-secret")

    monkeypatch.setattr(cli, "process_one_delivery", fault)

    cli.outbox_worker(["--once"])

    assert worker.sleeps == []  # a one-pass run does not wait and retry
    [record] = [r for r in caplog.records if "iteration failed" in r.message]
    assert "SQLAlchemyError" in record.message
    assert "FAKE-secret" not in caplog.text and "db.internal" not in caplog.text
    assert worker.disposed == [True]


def test_an_interrupt_stops_the_worker_quietly_and_still_closes_the_database(
    monkeypatch, worker
) -> None:
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "process_one_delivery", interrupted)

    cli.outbox_worker([])  # no limit: only the interrupt can end it

    assert worker.disposed == [True]
    assert worker.sleeps == []


def test_the_worker_refuses_a_negative_limit_and_a_missing_keyring(monkeypatch, capsys) -> None:
    with pytest.raises(SystemExit) as refused:
        cli.outbox_worker(["--max-deliveries", "-1"])
    assert refused.value.code == 2
    assert "--max-deliveries must not be negative" in capsys.readouterr().err

    monkeypatch.setattr(
        cli, "get_outbox_settings", lambda: SimpleNamespace(resolved_outbox_keyring={})
    )
    with pytest.raises(SystemExit) as refused:
        cli.outbox_worker(["--once"])
    assert refused.value.code == 2
    error = capsys.readouterr().err
    assert "PATIENT_PORTAL_OUTBOX_ENCRYPTION_SECRET" in error and "KEYRING" in error


# --------------------------------------------------------------------------------------------
# The outbox status listing and the artifact hash
# --------------------------------------------------------------------------------------------


def test_the_outbox_status_prints_one_compact_sorted_json_line_per_row(
    monkeypatch, capsys, tmp_path
) -> None:
    from carlos_patient_portal.database import create_portal_engine
    from tests.support import upgrade_to_head

    url = f"sqlite+pysqlite:///{tmp_path / 'status.db'}"
    engine = create_portal_engine(url)
    upgrade_to_head(engine)
    engine.dispose()
    monkeypatch.setattr(cli, "get_outbox_settings", lambda: development_settings(database_url=url))
    monkeypatch.setattr(
        cli,
        "summarize_outbox",
        lambda session: [{"status": "pending", "count": 2}, {"count": 1, "status": "done"}],
    )

    cli.maintenance(["outbox-status"])

    assert capsys.readouterr().out.splitlines() == [
        '{"count":2,"status":"pending"}',
        '{"count":1,"status":"done"}',
    ]


def test_the_database_artifacts_hash_is_the_two_sql_files_sha256_in_order(capsys) -> None:
    deploy = Path(cli.__file__).resolve().parent / "deploy"
    expected = "|".join(
        sha256((deploy / name).read_bytes()).hexdigest()
        for name in ("postgresql-audit-roles.sql", "postgresql-database-identity.sql")
    )

    cli.deployment_probe(["database-artifacts-sha256"])

    assert capsys.readouterr().out.strip() == expected
    first, second = expected.split("|")
    assert len(first) == len(second) == 64 and first != second


# --------------------------------------------------------------------------------------------
# The PostgreSQL identity (what is done with the answer)
# --------------------------------------------------------------------------------------------


class Row(dict):
    def mappings(self):
        return self

    def one(self):
        return self


def stand_in_engine(row: dict, *, tls: bool = True, driver: bool = True):
    pgconn = SimpleNamespace(ssl_in_use=tls)
    driver_connection = SimpleNamespace(pgconn=pgconn) if driver else SimpleNamespace()

    class Connection:
        connection = SimpleNamespace(driver_connection=driver_connection)

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return None

        def execute(self, statement):
            assert "pg_control_system" in str(statement)
            return Row(row)

    return SimpleNamespace(connect=lambda: Connection())


ROW = {
    "system_identifier": "7000000000000000001",
    "database_oid": "16384",
    "database_name": "portal",
    "session_role": "portal_app",
    "current_role": "portal_app",
    "search_path": "pg_catalog,public",
    "lock_timeout_bounded": True,
    "statement_timeout_bounded": True,
}


def identity(row=None, **options):
    return cli._postgresql_connection_identity(
        stand_in_engine(ROW if row is None else row, **options),
        configured_username="portal_app",
        expected_search_path="pg_catalog,public",
    )


def test_the_identity_is_the_server_the_database_the_role_tls_and_whether_the_session_is_safe() -> (
    None
):
    assert identity() == ("7000000000000000001", "16384", "portal", "portal_app", True, True)
    assert identity(tls=False)[4] is False
    assert identity(driver=False)[4] is False  # a driver that cannot say is not TLS


@pytest.mark.parametrize(
    "change",
    [
        {"search_path": "public"},
        {"lock_timeout_bounded": False},
        {"statement_timeout_bounded": False},
        {"lock_timeout_bounded": None},
    ],
)
def test_a_session_without_the_expected_search_path_or_bounded_timeouts_is_not_safe(change) -> None:
    assert identity({**ROW, **change})[5] is False


@pytest.mark.parametrize(
    "change", [{"session_role": "someone_else"}, {"current_role": "someone_else"}]
)
def test_a_session_that_is_not_the_url_login_role_is_refused_not_described(change) -> None:
    with pytest.raises(SystemExit, match="direct session using the URL's login role"):
        identity({**ROW, **change})
    with pytest.raises(SystemExit, match="direct session using the URL's login role"):
        cli._postgresql_connection_identity(
            stand_in_engine(ROW),
            configured_username=None,
            expected_search_path="pg_catalog,public",
        )


def test_the_deployment_identity_hex_encodes_the_target_and_hashes_the_role() -> None:
    text = cli._database_deployment_identity(
        stand_in_engine(ROW),
        configured_username="portal_app",
        expected_search_path="pg_catalog,public",
    )
    server, database, name, role_hash, tls, safe = text.split("|")
    assert bytes.fromhex(server) == b"7000000000000000001"
    assert bytes.fromhex(database) == b"16384"
    assert bytes.fromhex(name) == b"portal"
    assert role_hash == sha256(b"portal_app").hexdigest()
    assert (tls, safe) == ("tls", "safe")
    assert "portal_app" not in text  # the role is only its hash
    plain = cli._database_deployment_identity(
        stand_in_engine({**ROW, "search_path": "public"}, tls=False),
        configured_username="portal_app",
        expected_search_path="pg_catalog,public",
    )
    assert plain.split("|")[-2:] == ["plaintext", "unsafe"]
