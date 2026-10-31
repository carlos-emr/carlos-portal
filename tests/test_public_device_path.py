"""Frozen URL policy and actual signed GET/POST through a Unicode-aware stripping proxy.

The expected external URI bytes come from the frozen native vectors, never the production
canonicalizer. These tests exercise the portal, not a running native client or camera decoder.
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import unquote
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from carlos_patient_portal.main import create_app
from carlos_patient_portal.models import PatientPortalMyCarlosDevice
from carlos_patient_portal.mycarlos_links import IssuedLinkCode
from carlos_patient_portal.mycarlos_qr import link_qr_payload
from carlos_patient_portal.public_device_path import (
    canonical_public_device_url,
    public_device_prefix,
)
from carlos_patient_portal.routes import mycarlos as routes
from carlos_patient_portal.web_support import deployment_cookie_path
from tests import delivery_contract_reference as ref
from tests.support import development_settings
from tests.test_link_lifecycle_routes import NOW, native_portal, signed_assertion
from tests.test_mycarlos_link_route import (
    NOW as LINK_NOW,
)
from tests.test_mycarlos_link_route import (
    PORTAL,
    link_app,
    seed_vector_state,
)

QR = json.loads((Path(__file__).parent / "fixtures/qr-link-v1.json").read_text())
CASES = [
    ("/café", "/caf%C3%A9"),
    ("/患者", "/%E6%82%A3%E8%80%85"),
    ("/cafe\u0301", "/cafe%CC%81"),
    ("/caf%C3%A9", "/caf%C3%A9"),
    ("/patients", "/patients"),
]


@pytest.mark.parametrize("vector", QR["vectors"], ids=lambda item: item["name"])
def test_all_frozen_qr_vectors_preserve_raw_payload_before_url_policy(vector):
    # Test-only raw producer comparison, not a new production QR consumer/parser. Comparing the
    # original bytes rejects duplicates, extra/missing fields and alternate JSON encodings.
    raw = bytes.fromhex(vector["payload_hex"])
    try:
        values = json.loads(raw.decode("utf-8"))
        issued = IssuedLinkCode(values["link_id"], values["code"], datetime.now(UTC))
        assert link_qr_payload(issued, values["portal_url"]) == raw
        canonical = canonical_public_device_url(values["portal_url"])
    except (ValueError, UnicodeError, KeyError, TypeError, AssertionError):
        assert not vector["expect_accept"]
    else:
        assert vector["expect_accept"]
        assert canonical == vector["normalized_portal_url"]
        assert canonical_public_device_url(canonical) == canonical
        assert len(canonical.encode("utf-8")) <= 1024


@pytest.mark.parametrize(
    "value,expected", [(None, b""), ("http://testserver/patients", b"/patients")]
)
def test_none_and_existing_server_development_http_remain_unchanged(value, expected):
    assert public_device_prefix(development_settings(public_base_url=value)) == expected


def test_invalid_https_never_falls_back_in_development_and_feature_off_starts():
    value = "https://portal.example.test/" + "é" * 200
    settings = development_settings(public_base_url=value, mycarlos_delivery_enabled=False)
    assert create_app(settings).root_path == settings.root_path
    with pytest.raises(ValueError, match="invalid public device address"):
        public_device_prefix(settings)
    with pytest.raises(ValueError, match="invalid public device address"):
        create_app(development_settings(public_base_url=value, mycarlos_delivery_enabled=True))


class SplitProxy:
    """Strip decoded routing and raw URI prefixes independently, like the external proxy."""

    def __init__(self, app, configured_prefix, wire_prefix):
        self.app = app
        self.decoded_prefix = unquote(configured_prefix)
        self.wire_prefix = wire_prefix.encode("ascii")
        self.observed = []

    async def __call__(self, scope, receive, send):
        forwarded = dict(scope)
        if scope["type"] == "http":
            assert scope["path"].startswith(self.decoded_prefix + "/")
            assert scope["raw_path"].startswith(self.wire_prefix + b"/")
            forwarded["path"] = scope["path"][len(self.decoded_prefix) :]
            forwarded["raw_path"] = scope["raw_path"][len(self.wire_prefix) :]
            self.observed.append((scope["raw_path"], dict(forwarded)))
        await self.app(forwarded, receive, send)


def capture_real_signed_path(monkeypatch):
    observed = []
    original = routes.signed_path

    def capture(runtime, request):
        value = original(runtime, request)
        observed.append((value, dict(request.scope), runtime.settings))
        return value

    monkeypatch.setattr(routes, "signed_path", capture)
    return observed


def assert_trace(proxy, captured, external_target, method, body=b"", query=b""):
    signed, scope, settings = captured[-1]
    external, forwarded = proxy.observed[-1]
    assert external == external_target.encode("ascii")
    assert signed == external
    assert (
        scope["path"]
        == forwarded["path"]
        == "/api/mycarlos/" + ("clinic-keys" if method == "GET" else "link")
    )
    assert scope["raw_path"] == forwarded["raw_path"] == scope["path"].encode("ascii")
    assert scope["query_string"] == query
    assert scope["root_path"] == settings.root_path == proxy.app.root_path
    wire_prefix = external_target.rsplit("/api/mycarlos/", 1)[0]
    assert deployment_cookie_path(settings, "/portal") == wire_prefix + "/portal"
    expected_hash = ref.request_hash(method, external_target.encode("ascii"), query, body)
    assert ref.request_hash(method, signed, query, body) == expected_hash
    return {
        "external_target_ascii": external_target,
        "method": method,
        "asgi_path": scope["path"],
        "asgi_raw_path_hex": scope["raw_path"].hex(),
        "root_path_preserved": scope["root_path"],
        "server_signed_path_hex": signed.hex(),
        "native_expected_path_hex": external_target.encode("ascii").hex(),
        "native_expected_request_hash": expected_hash,
        "query_hex": query.hex(),
        "body_hex": body.hex(),
        "configured_public_url_preserved": settings.public_base_url,
    }


@pytest.mark.parametrize("configured_prefix,wire_prefix", CASES)
def test_real_unicode_get_exact_external_bytes_replay_and_removed(
    configured_prefix, wire_prefix, monkeypatch, record_property
):
    captured = capture_real_signed_path(monkeypatch)
    app, client, proxy, _account = native_portal(
        public_base_url="https://portal.example.test" + configured_prefix,
        proxy_factory=lambda app: SplitProxy(app, configured_prefix, wire_prefix),
    )
    target = wire_prefix + "/api/mycarlos/clinic-keys"
    assertion = signed_assertion(target, recovery=False)
    headers = {"X-MyCarlos-Device-Assertion": assertion}
    assert client.get(target, headers=headers).status_code == 200
    record_property("wire_trace", json.dumps(assert_trace(proxy, captured, target, "GET")))
    assert client.get(target, headers=headers).status_code == 404
    old = configured_prefix + "/api/mycarlos/clinic-keys"
    if old != target:
        response = client.get(
            target, headers={"X-MyCarlos-Device-Assertion": signed_assertion(old, recovery=False)}
        )
        assert response.status_code == 404
    for method, path in [("POST", target), ("GET", "/api/mycarlos/clinic-keys")]:
        response = client.get(
            target,
            headers={
                "X-MyCarlos-Device-Assertion": signed_assertion(
                    target, recovery=False, signed_method=method, signed_path=path
                )
            },
        )
        assert response.status_code == 404
    with app.state.session_factory() as session, session.begin():
        device = session.scalar(select(PatientPortalMyCarlosDevice))
        device.status = "removed"
        device.removed_at = datetime.fromtimestamp(NOW, tz=UTC)
        device.removed_by = "patient"
    response = client.get(
        target, headers={"X-MyCarlos-Device-Assertion": signed_assertion(target, recovery=False)}
    )
    assert response.status_code == 403 and response.json() == {"code": "device_removed"}


@pytest.mark.parametrize("configured_prefix,wire_prefix", CASES)
def test_real_unicode_post_preserves_body_query_and_rejects_old_prefix(
    configured_prefix, wire_prefix, monkeypatch, record_property
):
    captured = capture_real_signed_path(monkeypatch)
    app = link_app(public_base_url="https://portal.example.test" + configured_prefix)
    seed_vector_state(app)
    proxy = SplitProxy(app, configured_prefix, wire_prefix)
    client = TestClient(proxy, base_url="https://portal.example.test")
    vector = next(value for value in PORTAL["link_requests"] if value["expect"] == "accept")
    body = vector["body"].encode()
    signer = ref.DeviceKeys("device 4")
    target = wire_prefix + "/api/mycarlos/link"
    query = b"probe=%C3%A9&repeat=1&repeat=2"

    def assertion(path, signed_body=body):
        return ref.compact_ed25519(
            signer.ed25519,
            {
                "aud": ref.LINK_AUDIENCE,
                "iss": "mycarlos",
                "kid": signer.device_key_id,
                "iat": LINK_NOW,
                "exp": LINK_NOW + 60,
                "jti": str(uuid4()),
                "request_hash": ref.request_hash("POST", path.encode(), query, signed_body),
            },
        )

    def post(signed, actual_body=body):
        return client.post(
            target + "?" + query.decode(),
            content=actual_body,
            headers={
                "Content-Type": "application/json",
                "X-MyCarlos-Device-Assertion": signed,
            },
        )

    old = configured_prefix + "/api/mycarlos/link"
    if old != target:
        assert post(assertion(old)).status_code == 404
    assert post(assertion(target), body + b" ").status_code == 404
    good = assertion(target)
    response = post(good)
    assert response.status_code == 200, response.text
    record_property(
        "wire_trace", json.dumps(assert_trace(proxy, captured, target, "POST", body, query))
    )
    assert post(good).status_code == 404


def test_idn_default_host_admission_is_separate_from_public_wire_path(monkeypatch, record_property):
    captured = capture_real_signed_path(monkeypatch)
    configured = "https://bücher.example/café"
    expected = "https://xn--bcher-kva.example/caf%C3%A9"
    assert canonical_public_device_url(configured) == expected
    app, _client, proxy, _account = native_portal(
        public_base_url=configured,
        proxy_factory=lambda app: SplitProxy(app, "/café", "/caf%C3%A9"),
        probe_allowed_hosts_exclusive=True,
    )
    client = TestClient(proxy, base_url="https://xn--bcher-kva.example")
    target = "/caf%C3%A9/api/mycarlos/clinic-keys"
    response = client.get(
        target, headers={"X-MyCarlos-Device-Assertion": signed_assertion(target, recovery=False)}
    )
    assert response.status_code == 400
    record_property("default_idn_host_status", response.status_code)
    assert not captured
    app, _client, proxy, _account = native_portal(
        public_base_url=configured,
        proxy_factory=lambda app: SplitProxy(app, "/café", "/caf%C3%A9"),
        probe_allowed_hosts_exclusive=True,
        probe_allowed_hosts="xn--bcher-kva.example",
    )
    response = TestClient(proxy, base_url="https://xn--bcher-kva.example").get(
        target, headers={"X-MyCarlos-Device-Assertion": signed_assertion(target, recovery=False)}
    )
    assert response.status_code == 200
    record_property(
        "explicit_punycode_alias_wire_trace",
        json.dumps(assert_trace(proxy, captured, target, "GET")),
    )
