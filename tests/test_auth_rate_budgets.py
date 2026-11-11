"""HTTP contracts for the per-process recovery and MFA request budgets."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select
from starlette.requests import Request

from carlos_patient_portal import main, runtime
from carlos_patient_portal.models import PatientPortalOutboundDelivery
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    development_settings,
    migrated_staging_app,
)
from tests.test_link_lifecycle_routes import PREFIX, StrippingProxy

AUTH_POST_PATHS = (
    "/auth/password-reset/request",
    "/auth/password-reset/complete",
    "/auth/mfa/verify",
    "/auth/mfa/resend",
)


def rate_limited_app(**overrides):
    return main.create_app(
        development_settings(
            **{
                "database_url": "sqlite+pysqlite:///:memory:",
                "auth_rate_limit_max_requests": 2,
                "global_rate_limit_max_requests": 100,
                "mycarlos_delivery_enabled": False,
                "mycarlos_mailbox_enabled": False,
                **overrides,
            }
        ),
        email_sender=RecordingPortalEmailSender(),
        sms_sender=RecordingPortalSmsSender(),
    )


@pytest.mark.parametrize("path", AUTH_POST_PATHS)
@pytest.mark.parametrize(
    ("content_type", "body", "expected_status"),
    [
        ("application/json", "{", 422),
        ("application/json", "{}", 422),
        ("application/x-www-form-urlencoded", "FAKE-without-an-equals-sign", 400),
        ("application/x-www-form-urlencoded", "", 403),
    ],
    ids=["malformed-json", "missing-json-fields", "invalid-form", "empty-form"],
)
def test_recovery_and_mfa_limit_runs_before_body_parsing(
    monkeypatch, path, content_type, body, expected_status
):
    app = rate_limited_app(auth_rate_limit_max_requests=1)
    parsed_bodies = []
    original_stream = Request.stream

    async def observed_stream(request):
        parsed_bodies.append(request.url.path)
        async for chunk in original_stream(request):
            yield chunk

    monkeypatch.setattr(Request, "stream", observed_stream)
    with TestClient(app) as client:
        first = client.post(path, content=body, headers={"Content-Type": content_type})
        assert first.status_code == expected_status
        assert parsed_bodies
        parsed_after_first = len(parsed_bodies)
        rejected = client.post(path, content=body, headers={"Content-Type": content_type})

    assert rejected.status_code == 429
    if content_type == "application/json":
        assert rejected.json() == {"detail": "too many requests"}
    else:
        assert rejected.headers["content-type"].startswith("text/html")
        assert "Too many requests" in rejected.text
    assert 1 <= int(rejected.headers["retry-after"]) <= 60
    assert rejected.headers["cache-control"] == "no-store"
    assert len(parsed_bodies) == parsed_after_first


@pytest.mark.parametrize("path", AUTH_POST_PATHS)
def test_mounted_and_repeated_prefix_aliases_share_the_canonical_budget(path):
    app = rate_limited_app(
        public_base_url="https://portal.example.test" + PREFIX,
    )
    proxy = StrippingProxy(app)
    with TestClient(proxy, base_url="https://portal.example.test") as client:
        canonical = client.post(PREFIX + path, json={})
        alias = client.post(PREFIX + PREFIX + path, json={})
        rejected = client.post(PREFIX + path, json={})

    assert canonical.status_code in {400, 422}
    assert alias.status_code == canonical.status_code
    assert rejected.status_code == 429


def test_each_flow_and_client_has_its_own_budget_charged_once_per_request():
    app = rate_limited_app(global_rate_limit_max_requests=1)
    paths = (*AUTH_POST_PATHS, "/auth/login", "/api/mycarlos/link")
    with TestClient(app, client=("192.0.2.10", 50000)) as first:
        # Exhausting the coarse budget must not consume any flow's strict budget.
        assert first.post("/auth/FAKE-unclassified", json={}).status_code == 404
        assert first.post("/auth/FAKE-unclassified", json={}).status_code == 429
        for path in paths:
            for _ in range(2):
                assert first.post(path, json={}).status_code != 429
            assert first.post(path, json={}).status_code == 429

    with TestClient(app, client=("192.0.2.11", 50001)) as second:
        for path in paths:
            for _ in range(2):
                assert second.post(path, json={}).status_code != 429
            assert second.post(path, json={}).status_code == 429
        # Strict requests select one limiter; they do not also spend the coarse budget.
        assert second.post("/auth/FAKE-unclassified", json={}).status_code == 404
        assert second.post("/auth/FAKE-unclassified", json={}).status_code == 429


@pytest.mark.parametrize("path", AUTH_POST_PATHS)
def test_recovery_and_mfa_honor_the_configured_auth_budget(path):
    app = rate_limited_app(auth_rate_limit_max_requests=10)
    with TestClient(app) as client:
        for _ in range(10):
            assert client.post(path, json={}).status_code in {400, 422}
        assert client.post(path, json={}).status_code == 429


@pytest.mark.parametrize("path", AUTH_POST_PATHS)
@pytest.mark.parametrize("method", ["GET", "HEAD", "PUT"])
def test_other_methods_keep_the_coarse_budget(path, method):
    app = rate_limited_app(auth_rate_limit_max_requests=1, global_rate_limit_max_requests=2)
    with TestClient(app) as client:
        for _ in range(2):
            assert client.request(method, path).status_code != 429
        assert client.request(method, path).status_code == 429
        # These requests have not consumed the POST flow's independent budget.
        assert client.post(path, json={}).status_code in {400, 422}
        assert client.post(path, json={}).status_code == 429


@pytest.mark.parametrize("path", ["/auth/login", "/api/mycarlos/link"])
def test_existing_login_and_link_keep_their_path_wide_strict_budget(path):
    app = rate_limited_app(auth_rate_limit_max_requests=1)
    with TestClient(app) as client:
        assert client.get(path).status_code != 429
        assert client.post(path, json={}).status_code == 429


@pytest.mark.parametrize(
    "path",
    ["/auth/language", "/auth/logout", "/auth/mfa/verify/FAKE-child"],
)
def test_other_auth_posts_keep_the_coarse_budget(path):
    app = rate_limited_app(auth_rate_limit_max_requests=1, global_rate_limit_max_requests=2)
    with TestClient(app) as client:
        for _ in range(2):
            assert client.post(path, json={}).status_code != 429
        assert client.post(path, json={}).status_code == 429


@pytest.mark.parametrize("path", AUTH_POST_PATHS)
def test_retry_after_uses_the_existing_fixed_window_without_extension(monkeypatch, path):
    now = [100.25]
    monkeypatch.setattr(runtime, "monotonic", lambda: now[0])
    app = rate_limited_app(auth_rate_limit_max_requests=1, auth_rate_limit_window_seconds=10)
    with TestClient(app) as client:
        assert client.post(path, json={}).status_code in {400, 422}
        now[0] = 100.75
        assert client.post(path, json={}).headers["retry-after"] == "10"
        now[0] = 109.251
        assert client.post(path, json={}).headers["retry-after"] == "1"
        now[0] = 110.25
        assert client.post(path, json={}).status_code in {400, 422}
        assert client.post(path, json={}).headers["retry-after"] == "10"


@pytest.mark.parametrize("path", AUTH_POST_PATHS)
@pytest.mark.parametrize("trusted_peer", [True, False], ids=["trusted", "untrusted"])
def test_forwarded_clients_follow_existing_proxy_trust_rules(path, trusted_peer):
    app = rate_limited_app(
        auth_rate_limit_max_requests=1,
        trusted_client_ip_header="x-forwarded-for",
        trusted_proxy_cidrs="10.0.0.0/8",
    )
    peer = "10.1.1.1" if trusted_peer else "198.51.100.10"
    with TestClient(app, client=(peer, 50000)) as client:
        first_headers = {"X-Forwarded-For": "192.0.2.20, 10.2.2.2"}
        second_headers = {"X-Forwarded-For": "192.0.2.21, 10.2.2.2"}
        assert client.post(path, json={}, headers=first_headers).status_code in {400, 422}
        assert client.post(path, json={}, headers=first_headers).status_code == 429
        second = client.post(path, json={}, headers=second_headers)
        assert second.status_code in ({400, 422} if trusted_peer else {429})


def test_reset_budget_rejects_rotated_identities_before_enqueue():
    sender = RecordingPortalEmailSender()
    app = migrated_staging_app(
        email_sender=sender,
        sms_sender=RecordingPortalSmsSender(),
        auth_rate_limit_max_requests=2,
    )
    with TestClient(app, base_url="https://portal.example.test") as client:
        responses = [
            client.post(
                "/auth/password-reset/request",
                json={
                    "username": f"fake.missing.patient{index}",
                    "email": f"fake.missing.patient{index}@example.test",
                },
            )
            for index in range(3)
        ]
        assert [response.status_code for response in responses] == [202, 202, 429]
        assert responses[0].json() == responses[1].json()
        with app.state.session_factory() as session:
            commands = session.scalars(select(PatientPortalOutboundDelivery)).all()
            assert len(commands) == 2
            assert all(command.account_id is None for command in commands)
        assert sender.messages == []
