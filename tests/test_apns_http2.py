# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The HTTP/2 client the iPhone push goes out through, against a real HTTP/2 server of the test's
own on the loopback address (TLS with ALPN ``h2``, a certificate the test makes). Nothing leaves
the machine; every value is FAKE."""

from __future__ import annotations

import logging
import socket
import ssl
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, StreamEnded

from carlos_patient_portal import apns_http2
from carlos_patient_portal.apns_http2 import Http2Client, require_http2
from carlos_patient_portal.apns_provider import ApnsKeyError
from carlos_patient_portal.notification_transports import HttpRequest, HttpResponse


@dataclass
class Seen:
    """What the test server saw."""

    requests: list[dict[str, object]] = field(default_factory=list)
    alpn: list[str | None] = field(default_factory=list)


def make_certificate(tmp_path: Path) -> tuple[Path, Path]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("localhost"), x509.IPAddress(ip_address("127.0.0.1"))]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "server.pem", tmp_path / "server.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


@contextmanager
def h2_server(
    tmp_path: Path,
    respond: Callable[[dict[str, object]], tuple[int, dict[str, str]]] = lambda _: (200, {}),
    *,
    alpn: tuple[str, ...] = ("h2",),
    silent: bool = False,
) -> Iterator[tuple[int, Seen, ssl.SSLContext]]:
    """A TLS server that speaks HTTP/2 to one client at a time. `silent` takes a request and
    never answers it. Yields (port, what it saw, a client TLS context that trusts it)."""
    cert_path, key_path = make_certificate(tmp_path)
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(cert_path, key_path)
    server_context.set_alpn_protocols(list(alpn))
    client_context = ssl.create_default_context(cafile=str(cert_path))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.2)
    seen = Seen()
    stop = threading.Event()

    def serve(connection: socket.socket) -> None:
        try:
            with server_context.wrap_socket(connection, server_side=True) as tls:
                seen.alpn.append(tls.selected_alpn_protocol())
                if tls.selected_alpn_protocol() != "h2":
                    return
                tls.settimeout(5)
                conn = H2Connection(config=H2Configuration(client_side=False))
                conn.initiate_connection()
                tls.sendall(conn.data_to_send())
                headers: dict[int, dict[str, str]] = {}
                bodies: dict[int, bytes] = {}
                while not stop.is_set():
                    data = tls.recv(65535)
                    if not data:
                        return
                    for event in conn.receive_data(data):
                        if isinstance(event, RequestReceived):
                            headers[event.stream_id] = {
                                k.decode(): v.decode() for k, v in event.headers
                            }
                            bodies[event.stream_id] = b""
                        elif isinstance(event, DataReceived):
                            bodies[event.stream_id] += event.data
                            conn.acknowledge_received_data(
                                event.flow_controlled_length, event.stream_id
                            )
                        elif isinstance(event, StreamEnded) and not silent:
                            request = {
                                "headers": headers[event.stream_id],
                                "body": bodies[event.stream_id],
                            }
                            seen.requests.append(request)
                            status, extra = respond(request)
                            conn.send_headers(
                                event.stream_id, [(":status", str(status)), *extra.items()]
                            )
                            conn.send_data(event.stream_id, b"FAKE apple reason", end_stream=True)
                        elif isinstance(event, StreamEnded):
                            seen.requests.append({"headers": headers[event.stream_id]})
                    tls.sendall(conn.data_to_send())
        except (OSError, ssl.SSLError):
            return

    def accept() -> None:
        while not stop.is_set():
            try:
                connection, _ = listener.accept()
            except (TimeoutError, OSError):
                continue
            threading.Thread(target=serve, args=(connection,), daemon=True).start()

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], seen, client_context
    finally:
        stop.set()
        listener.close()
        thread.join(timeout=2)


def push(port: int, **changes: object) -> HttpRequest:
    values: dict[str, object] = {
        "method": "POST",
        "url": f"https://127.0.0.1:{port}/3/device/" + "ab" * 32,
        "headers": {
            "authorization": "bearer FAKE-provider-token",
            "apns-topic": "ca.example.fake",
            "apns-push-type": "alert",
            "apns-priority": "10",
            "content-type": "application/json",
        },
        "body": b'{"aps":{"alert":{"loc-key":"native-notice-arrival"}},"n":"FAKE"}',
        **changes,
    }
    return HttpRequest(**values)  # type: ignore[arg-type]


def test_a_push_goes_out_over_http2_with_its_headers_and_body_and_only_the_status_comes_back(
    tmp_path: Path,
) -> None:
    with h2_server(tmp_path, lambda _: (200, {"apns-id": "FAKE-id"})) as (port, seen, context):
        client = Http2Client(verify=context)
        response = client.send(push(port), timeout=5)
        client.close()
    assert response == HttpResponse(200)
    # ALPN picked h2: the server would not have spoken to an HTTP/1.1 client.
    assert seen.alpn == ["h2"]
    [request] = seen.requests
    headers = request["headers"]
    assert headers[":method"] == "POST"
    assert headers[":path"] == "/3/device/" + "ab" * 32
    assert headers["apns-topic"] == "ca.example.fake"
    assert headers["apns-push-type"] == "alert"
    assert headers["authorization"] == "bearer FAKE-provider-token"
    assert request["body"] == push(port).body


@pytest.mark.parametrize("status", [200, 400, 403, 410, 429, 500, 503])
def test_every_status_comes_back_as_its_number_and_nothing_else(
    tmp_path: Path, status: int
) -> None:
    with h2_server(tmp_path, lambda _: (status, {})) as (port, _, context):
        client = Http2Client(verify=context)
        assert client.send(push(port), timeout=5) == HttpResponse(status)
        client.close()


def test_a_redirect_is_not_followed(tmp_path: Path) -> None:
    with h2_server(tmp_path, lambda _: (302, {"location": "https://127.0.0.1:1/elsewhere"})) as (
        port,
        seen,
        context,
    ):
        client = Http2Client(verify=context)
        assert client.send(push(port), timeout=5) == HttpResponse(302)
        client.close()
    assert len(seen.requests) == 1


def test_a_second_push_reuses_the_connection(tmp_path: Path) -> None:
    with h2_server(tmp_path) as (port, seen, context):
        client = Http2Client(verify=context)
        for _ in range(3):
            assert client.send(push(port), timeout=5) == HttpResponse(200)
        client.close()
    assert len(seen.requests) == 3
    assert seen.alpn == ["h2"], "one connection, not three"


def test_a_server_that_only_speaks_http1_is_refused_not_downgraded(tmp_path: Path) -> None:
    with h2_server(tmp_path, alpn=("http/1.1",)) as (port, seen, context):
        client = Http2Client(verify=context)
        with pytest.raises(ConnectionError, match="^provider_unreachable$"):
            client.send(push(port), timeout=5)
        client.close()
    assert seen.requests == []


def test_a_certificate_that_is_not_trusted_is_a_lost_connection(tmp_path: Path) -> None:
    with h2_server(tmp_path) as (port, seen, _):
        # The platform's own trust store does not know the test's authority.
        client = Http2Client()
        with pytest.raises(ConnectionError, match="^provider_unreachable$"):
            client.send(push(port), timeout=5)
        client.close()
    assert seen.requests == []


def test_a_refused_connection_is_a_lost_connection_and_names_nothing(tmp_path: Path) -> None:
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
    listener.close()
    client = Http2Client()
    with pytest.raises(ConnectionError) as raised:
        client.send(push(port), timeout=2)
    client.close()
    text = str(raised.value) + repr(raised.value)
    assert text.count("provider_unreachable") >= 1
    for secret in ("127.0.0.1", str(port), "ab" * 32, "FAKE-provider-token"):
        assert secret not in text


def test_a_server_that_never_answers_ends_at_the_timeout(tmp_path: Path) -> None:
    with h2_server(tmp_path, silent=True) as (port, _, context):
        client = Http2Client(verify=context)
        with pytest.raises(TimeoutError, match="^provider_timeout$"):
            client.send(push(port), timeout=0.5)
        client.close()


def test_the_client_never_reads_proxy_or_certificate_overrides_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "nope.pem"))
    with h2_server(tmp_path) as (port, _, context):
        client = Http2Client(verify=context)
        # Reaches the server directly, not through the (dead) proxy.
        assert client.send(push(port), timeout=5) == HttpResponse(200)
        client.close()


def test_the_client_prints_nothing_about_a_request() -> None:
    assert repr(Http2Client()) == "Http2Client[REDACTED]"


def test_a_portal_without_the_http2_packages_refuses_to_start_with_push_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    require_http2()  # installed here

    def missing(name: str) -> object:
        raise ImportError(name)

    monkeypatch.setattr(apns_http2, "import_module", missing)
    with pytest.raises(ApnsKeyError) as raised:
        require_http2()
    assert raised.value.code == "apns_http2_unavailable"
    with pytest.raises(ApnsKeyError):
        Http2Client()


# --- what the HTTP libraries would log ------------------------------------------------


@pytest.fixture
def loud_libraries() -> Iterator[None]:
    """The HTTP libraries' loggers as an application leaves them by default (open), put back."""
    names = ("httpx2", "httpcore2", "h2", "hpack")
    saved = [
        (
            logging.getLogger(n),
            logging.getLogger(n).level,
            logging.getLogger(n).propagate,
            list(logging.getLogger(n).handlers),
        )
        for n in names
    ]
    for logger, *_ in saved:
        logger.setLevel(logging.NOTSET)
        logger.propagate = True
        logger.handlers = []
    try:
        yield
    finally:
        for logger, level, propagate, handlers in saved:
            logger.setLevel(level)
            logger.propagate = propagate
            logger.handlers = handlers


def texts(caplog: pytest.LogCaptureFixture) -> str:
    return "\n".join(record.getMessage() for record in caplog.records)


def test_the_libraries_would_log_the_device_token_if_they_were_left_open(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, loud_libraries: None
) -> None:
    # The control: without the client's own silencing, httpx2 writes the URL, token and all.
    import httpx2

    with h2_server(tmp_path) as (port, _, context):
        caplog.set_level(logging.DEBUG)
        with httpx2.Client(http2=True, verify=context) as plain:
            plain.post(push(port).url, headers=dict(push(port).headers), content=b"x")
    assert "ab" * 32 in texts(caplog)


def test_the_client_keeps_the_device_token_and_the_provider_token_out_of_every_log(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, loud_libraries: None
) -> None:
    with h2_server(tmp_path) as (port, _, context):
        caplog.set_level(logging.DEBUG)
        # An application whose logging gives a library logger a level of its own.
        for name in (
            "httpx2",
            "httpcore2",
            "httpcore2.http2",
            "httpcore2.connection",
            "h2",
            "hpack",
        ):
            logging.getLogger(name).setLevel(logging.DEBUG)
        client = Http2Client(verify=context)
        # Silenced at the top: a child that an application opens still ends at its parent.
        logging.getLogger("httpcore2.http2").setLevel(logging.DEBUG)
        assert client.send(push(port), timeout=5) == HttpResponse(200)
        client.close()
    logged = texts(caplog)
    assert "ab" * 32 not in logged
    assert "FAKE-provider-token" not in logged
    assert "/3/device/" not in logged
    assert not any(
        record.name.split(".")[0] in {"httpx2", "httpcore2", "h2", "hpack"}
        for record in caplog.records
    )
