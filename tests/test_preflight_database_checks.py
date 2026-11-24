"""The operator's database checks, run against a stand-in engine so no PostgreSQL is needed.

Each case says which checks the operator is shown, and that a schema that is not current stops the
privilege checks from being trusted.
"""

from types import SimpleNamespace

import pytest
from sqlalchemy.exc import OperationalError

from carlos_patient_portal import preflight
from carlos_patient_portal.database import DatabaseSchemaMismatchError


class FakeSession:
    def __init__(self, engine):
        self.engine = engine

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None


def engine(dialect="postgresql"):
    return SimpleNamespace(dialect=SimpleNamespace(name=dialect))


@pytest.fixture
def stand_in(monkeypatch):
    """Patch the session and every query; each returns a passing check unless a case changes it."""
    calls = []
    monkeypatch.setattr(preflight, "Session", FakeSession)
    monkeypatch.setattr(preflight, "check_database", lambda session: calls.append("connect"))
    monkeypatch.setattr(preflight, "check_database_schema_current", lambda session: None)
    for name in (
        "query_database_tls",
        "query_runtime_role_policy",
        "query_declared_database_roles",
        "query_runtime_database_allowlist",
    ):
        monkeypatch.setattr(
            preflight,
            name,
            lambda session, *, _name=name, **kwargs: (
                calls.append(_name) or preflight.PreflightCheck(_name, "pass", "ok")
            ),
        )
    return calls


def summary(checks):
    return [(check.name, check.status) for check in checks]


def test_a_database_that_is_not_postgresql_stops_after_the_backend_check(stand_in):
    checks = preflight.database_preflight_checks(engine("sqlite"))
    assert summary(checks) == [("database_backend", "fail")]
    assert stand_in == []


def test_a_current_schema_shows_every_check_including_the_privilege_checks(stand_in):
    checks = preflight.database_preflight_checks(engine())
    assert summary(checks) == [
        ("database_backend", "pass"),
        ("database_connectivity", "pass"),
        ("database_schema", "pass"),
        ("query_database_tls", "pass"),
        ("query_runtime_role_policy", "pass"),
        ("query_declared_database_roles", "pass"),
        ("query_runtime_database_allowlist", "pass"),
    ]


def test_a_schema_that_is_not_current_says_the_privileges_cannot_be_verified(stand_in, monkeypatch):
    def mismatch(session):
        raise DatabaseSchemaMismatchError("FAKE revision detail")

    monkeypatch.setattr(preflight, "check_database_schema_current", mismatch)
    checks = preflight.database_preflight_checks(engine())
    assert summary(checks) == [
        ("database_backend", "pass"),
        ("database_connectivity", "pass"),
        ("database_schema", "fail"),
        ("query_database_tls", "pass"),
        ("runtime_database_role", "fail"),
        ("declared_database_roles", "fail"),
        ("runtime_database_allowlist", "fail"),
    ]
    details = " ".join(check.detail for check in checks)
    assert "until the schema is current" in details
    # The revision text from the exception is not shown to the operator.
    assert "FAKE revision detail" not in details
    assert "query_runtime_role_policy" not in stand_in


def test_a_database_that_cannot_be_reached_is_named_by_its_error_type_only(stand_in, monkeypatch):
    def refuse(session):
        raise OperationalError("FAKE-private-statement", {"x": "FAKE-private-parameter"}, None)

    monkeypatch.setattr(preflight, "check_database", refuse)
    checks = preflight.database_preflight_checks(engine())
    assert summary(checks) == [("database_backend", "pass"), ("database_connectivity", "fail")]
    assert checks[-1].detail == "database check failed (OperationalError)"


def test_a_query_that_fails_after_connecting_is_a_query_failure_not_a_connection_failure(
    stand_in, monkeypatch
):
    def refuse(session, **kwargs):
        raise OperationalError("FAKE-private-statement", {}, None)

    monkeypatch.setattr(preflight, "query_runtime_role_policy", refuse)
    checks = preflight.database_preflight_checks(engine())
    assert summary(checks)[-1] == ("database_preflight_queries", "fail")
    assert ("database_connectivity", "pass") in summary(checks)
    assert "FAKE-private" not in checks[-1].detail


@pytest.mark.parametrize(
    "pgconn,expected",
    [
        (SimpleNamespace(ssl_in_use=True), "pass"),
        (SimpleNamespace(ssl_in_use=False), "fail"),
        (SimpleNamespace(), "fail"),
        (None, "fail"),
    ],
)
def test_the_tls_check_reads_the_connection_this_process_uses(pgconn, expected):
    driver = SimpleNamespace(pgconn=pgconn)
    session = SimpleNamespace(
        connection=lambda: SimpleNamespace(connection=SimpleNamespace(driver_connection=driver))
    )
    check = preflight.query_database_tls(session)
    assert (check.name, check.status) == ("database_tls", expected)
