import copy
import http.client
import io
import json
import socket
import ssl
from pathlib import Path

import pytest

from carlos_patient_portal import clinic_footer
from carlos_patient_portal.clinic_footer import (
    ClinicFooterSnapshot,
    ClinicFooterUnavailableError,
    HttpsClinicFooterProvider,
    encode_base64url,
)
from carlos_patient_portal.config import Settings
from carlos_patient_portal.email_delivery import PortalEmailDeliveryError, SmtpPortalEmailSender
from carlos_patient_portal.footer_audit import FooterAuditStore
from tests.support import (
    TEST_STAFF_ASSERTION_KEY_ID,
    TEST_STAFF_ASSERTION_PRIVATE_KEY,
    TEST_STAFF_ASSERTION_PUBLIC_KEYRING,
)

VECTOR = Path(__file__).parent / "fixtures" / "clinic_footer_contract_v2.json"


def vector():
    return json.loads(VECTOR.read_text())


def provider(monkeypatch, *, public_keys=TEST_STAFF_ASSERTION_PUBLIC_KEYRING):
    monkeypatch.setattr(clinic_footer.secrets, "token_bytes", lambda n: bytes(range(n)))
    return HttpsClinicFooterProvider(
        Settings(
            environment="development",
            clinic_id="clinic-a",
            email_footer_url="https://carlos.example.test/carlos/ws/portal/email-footer",
            email_footer_read_token=vector()["derived_read_token"],
            internal_staff_assertion_public_keyring=public_keys,
        ),
        clock=lambda: 1700000001,
    )


def signed_response(payload):
    payload = copy.deepcopy(payload)
    payload["kid"] = TEST_STAFF_ASSERTION_KEY_ID
    raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
    assertion = (
        encode_base64url(raw) + "." + encode_base64url(TEST_STAFF_ASSERTION_PRIVATE_KEY.sign(raw))
    )
    return json.dumps({"assertion": assertion}).encode()


def test_product_verifies_exact_cross_language_fake_vector(monkeypatch):
    data = vector()
    client = provider(
        monkeypatch, public_keys=json.dumps({"fake-rfc8032": data["public_key_base64url"]})
    )
    monkeypatch.setattr(
        client, "_fetch", lambda nonce: json.dumps({"assertion": data["assertion"]}).encode()
    )
    snapshot = client.snapshot()
    assert snapshot.revision == data["payload"]["revision"]
    assert snapshot.plain == data["payload"]["footer_text"]
    assert snapshot.logo.sha256 == data["payload"]["logo"]["sha256"]


@pytest.mark.parametrize(
    "change",
    [
        {"nonce": "wrong"},
        {"clinic_id": "clinic-b"},
        {"aud": "carlos-patient-portal-internal-api"},
        {"iss": "other"},
        {"iat": True},
        {"iat": 1700000010},
        {"exp": 1700000000},
        {"exp": 1700000100},
        {"revision": "0" * 64},
        {"footer_text": ""},
        {"footer_html": "<script>FAKE</script>"},
        {"footer_html": "<b>\u200b</b>"},
        {"footer_html": '<a href="javascript:alert(1)">FAKE</a>'},
        {"footer_html": '<b onclick="x()">FAKE</b>'},
        {"extra": "unexpected"},
    ],
)
def test_invalid_even_correctly_signed_policy_is_refused(monkeypatch, change):
    client = provider(monkeypatch)
    payload = {**vector()["payload"], **change}
    monkeypatch.setattr(client, "_fetch", lambda nonce: signed_response(payload))
    with pytest.raises(ClinicFooterUnavailableError, match="^clinic email footer is unavailable$"):
        client.snapshot()


def test_authoritative_plaintext_is_not_recomputed_in_python(monkeypatch):
    client = provider(monkeypatch)
    payload = vector()["payload"]
    # Java's canonical result is signed in the vector and includes the link address.
    monkeypatch.setattr(client, "_fetch", lambda nonce: signed_response(payload))
    assert client.snapshot().plain.endswith("Website <https://clinic.example.test>")


@pytest.mark.parametrize(
    "content_id",
    ["logo\r\n@host", "<logo@host>", "logo/../@host", "logo host@test", "a" * 129 + "@host"],
)
def test_unsafe_cid_refused(monkeypatch, content_id):
    client = provider(monkeypatch)
    payload = vector()["payload"]
    payload["logo"]["content_id"] = content_id
    monkeypatch.setattr(client, "_fetch", lambda nonce: signed_response(payload))
    with pytest.raises(ClinicFooterUnavailableError):
        client.snapshot()


def test_wrong_signature_and_unknown_key_refused(monkeypatch):
    client = provider(monkeypatch)
    data = vector()
    monkeypatch.setattr(
        client, "_fetch", lambda nonce: json.dumps({"assertion": data["assertion"]}).encode()
    )
    with pytest.raises(ClinicFooterUnavailableError):
        client.snapshot()
    reply = json.loads(signed_response(data["payload"]))
    raw, _ = reply["assertion"].split(".")
    reply["assertion"] = raw + "." + encode_base64url(bytes(64))
    monkeypatch.setattr(client, "_fetch", lambda nonce: json.dumps(reply).encode())
    with pytest.raises(ClinicFooterUnavailableError):
        client.snapshot()


def test_duplicate_signed_json_fields_refused(monkeypatch):
    client = provider(monkeypatch)
    raw = json.dumps(vector()["payload"]).removesuffix("}") + ',"nonce":"other"}'
    encoded = raw.encode()
    reply = {
        "assertion": encode_base64url(encoded)
        + "."
        + encode_base64url(TEST_STAFF_ASSERTION_PRIVATE_KEY.sign(encoded))
    }
    monkeypatch.setattr(client, "_fetch", lambda nonce: json.dumps(reply).encode())
    with pytest.raises(ClinicFooterUnavailableError):
        client.snapshot()


def test_no_cached_footer_fallback_after_success(monkeypatch):
    client = provider(monkeypatch)
    monkeypatch.setattr(client, "_fetch", lambda nonce: signed_response(vector()["payload"]))
    client.snapshot()

    def unavailable(nonce):
        raise ClinicFooterUnavailableError("clinic email footer is unavailable")

    monkeypatch.setattr(client, "_fetch", unavailable)
    with pytest.raises(ClinicFooterUnavailableError):
        client.snapshot()


class FakeHttps:
    def __init__(self, response, **kwargs):
        self.response = response
        self.kwargs = kwargs
        self.sock = self
        self.closed = False
        self.requests = []

    def connect(self):
        pass

    def settimeout(self, value):
        assert 0 < value <= 5

    def request(self, method, path, *, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class FakeResponse:
    def __init__(self, body, status=200, **headers):
        self.body = body
        self.status = status
        self.headers = {"Content-Type": "application/json; charset=UTF-8", **headers}

    def getheader(self, key, default=None):
        return self.headers.get(key, default)

    def read1(self, maximum):
        chunk, self.body = self.body[:maximum], self.body[maximum:]
        return chunk

    def close(self):
        pass


def test_https_uses_exact_origin_derived_read_bearer_and_validated_tls(monkeypatch):
    client = provider(monkeypatch)
    transport = FakeHttps(FakeResponse(signed_response(vector()["payload"])))

    def connect(host, port, **kwargs):
        assert host == "carlos.example.test"
        assert kwargs["context"].verify_mode == ssl.CERT_REQUIRED
        assert kwargs["context"].check_hostname
        return transport

    monkeypatch.setattr(clinic_footer.http.client, "HTTPSConnection", connect)
    client.snapshot()
    method, path, headers = transport.requests[0]
    assert method == "GET"
    assert path == "/carlos/ws/portal/email-footer?nonce=" + vector()["payload"]["nonce"]
    assert headers["Authorization"] == "Bearer " + vector()["derived_read_token"]
    assert transport.closed


@pytest.mark.parametrize(
    "response",
    [
        FakeResponse(b"", status=302),
        FakeResponse(b"", status=503),
        FakeResponse(b"{}", **{"Content-Encoding": "gzip"}),
        FakeResponse(b"{}", **{"Content-Length": "9999999"}),
        FakeResponse(b"x" * (clinic_footer.MAX_FOOTER_RESPONSE_BYTES + 1)),
    ],
)
def test_http_refuses_redirects_failure_compression_and_unbounded_body(monkeypatch, response):
    client = provider(monkeypatch)
    transport = FakeHttps(response)
    monkeypatch.setattr(clinic_footer.http.client, "HTTPSConnection", lambda *a, **kw: transport)
    with pytest.raises(ClinicFooterUnavailableError):
        client.snapshot()
    assert transport.closed


def test_html_and_plain_limits_use_utf16_units():
    payload = vector()["payload"]
    fields = {
        k: payload[k] for k in ("clinic_id", "footer_html", "footer_text", "revision", "logo")
    }
    fields["footer_text"] = "😀" * 1001
    with pytest.raises(ClinicFooterUnavailableError):
        ClinicFooterSnapshot.from_dict(fields)


class TimedRaw(io.RawIOBase):
    def __init__(self, sock, prefix, slow, suffix):
        self.sock = sock
        self.prefix, self.slow, self.suffix = prefix, slow, suffix

    def readable(self):
        return True

    def readinto(self, buffer):
        if self.prefix:
            chunk, self.prefix = self.prefix[: len(buffer)], self.prefix[len(buffer) :]
        elif self.slow:
            # Each byte arrives well inside the original five-second inactivity timeout.
            # The real parser would keep resetting that timeout without the deadline reader.
            delay = 0.25
            if self.sock.timeout < delay:
                self.sock.clock[0] += self.sock.timeout
                raise TimeoutError("FAKE inactivity timeout")
            self.sock.clock[0] += delay
            chunk, self.slow = self.slow[:1], self.slow[1:]
        else:
            chunk, self.suffix = self.suffix[: len(buffer)], self.suffix[len(buffer) :]
        buffer[: len(chunk)] = chunk
        return len(chunk)


class TimedSocket:
    def __init__(self, clock, prefix, slow=b"", suffix=b""):
        self.clock = clock
        self.timeout = 5
        self.timeouts = []
        self.closed = False
        self.raw = TimedRaw(self, prefix, slow, suffix)

    def makefile(self, mode, buffering=-1):
        assert mode == "rb"
        return self.raw if buffering == 0 else io.BufferedReader(self.raw)

    def sendall(self, data):
        pass

    def settimeout(self, timeout):
        assert timeout > 0
        self.timeout = timeout
        self.timeouts.append(timeout)

    def close(self):
        self.closed = True


def install_real_http_parser(monkeypatch, sock):
    # Exercise real HTTPConnection.getresponse/HTTPResponse parsing and body framing;
    # only TLS connection establishment and the underlying socket are fake here.
    class ConnectedHttps(http.client.HTTPConnection):
        def connect(self):
            self.sock = sock

    monkeypatch.setattr(
        clinic_footer.http.client,
        "HTTPSConnection",
        lambda host, port, **kwargs: ConnectedHttps(host, port, timeout=kwargs["timeout"]),
    )


HTTP_HEADERS = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
CHUNKED_HEADERS = HTTP_HEADERS + b"Transfer-Encoding: chunked\r\n\r\n"


@pytest.mark.parametrize(
    "prefix,slow,suffix",
    [
        (b"HTTP/1.1 200 ", b"S" * 80, b"\r\nContent-Type: application/json\r\n\r\n{}"),
        (HTTP_HEADERS + b"X-Slow: ", b"S" * 80, b"\r\nContent-Length: 2\r\n\r\n{}"),
        (
            b"HTTP/1.1 100 Continue\r\n\r\n",
            b"HTTP/1.1 100 Continue\r\n\r\n" * 10,
            HTTP_HEADERS + b"\r\n{}",
        ),
        (CHUNKED_HEADERS + b"1;", b"S" * 80, b"\r\nx\r\n0\r\n\r\n"),
        (CHUNKED_HEADERS + b"1\r\nx\r\n0\r\nX-Slow: ", b"S" * 80, b"\r\n\r\n"),
        (HTTP_HEADERS + b"Content-Length: 80\r\n\r\n", b"S" * 80, b""),
    ],
    ids=["status", "headers", "interim-100", "chunk-size", "chunk-trailer", "body"],
)
def test_absolute_deadline_covers_real_http_framing_before_audit_and_smtp(
    monkeypatch, tmp_path, prefix, slow, suffix
):
    import smtplib

    client = provider(monkeypatch)
    clock = [0.0]
    monkeypatch.setattr(clinic_footer.time, "monotonic", lambda: clock[0])
    sock = TimedSocket(clock, prefix, slow, suffix)
    install_real_http_parser(monkeypatch, sock)
    smtp_connections = []

    def unexpected_smtp(**kwargs):
        smtp_connections.append(True)
        raise AssertionError("FAKE SMTP must not be reached")

    monkeypatch.setattr(smtplib, "SMTP", unexpected_smtp)
    sender = SmtpPortalEmailSender(
        Settings(environment="development", clinic_id="clinic-a", smtp_host="fake-smtp.internal"),
        footer_provider=client,
        footer_audit=FooterAuditStore(str(tmp_path), "clinic-a"),
    )
    with pytest.raises(PortalEmailDeliveryError, match="^portal email delivery failed$"):
        sender.send_code(recipient="fake.patient@example.test", code="FAKE", expires_in_seconds=60)
    assert clock[0] <= 5.0
    assert min(sock.timeouts) < max(sock.timeouts)
    assert sock.closed and sock.raw.closed
    assert smtp_connections == []
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("chunked", [False, True])
def test_deadline_reader_preserves_real_http_length_and_chunked_success(monkeypatch, chunked):
    client = provider(monkeypatch)
    payload = signed_response(vector()["payload"])
    if chunked:
        wire = CHUNKED_HEADERS + f"{len(payload):x}\r\n".encode() + payload + b"\r\n0\r\n\r\n"
    else:
        wire = HTTP_HEADERS + f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload
    clock = [0.0]
    monkeypatch.setattr(clinic_footer.time, "monotonic", lambda: clock[0])
    sock = TimedSocket(clock, wire)
    install_real_http_parser(monkeypatch, sock)
    assert client.snapshot().revision == vector()["payload"]["revision"]
    assert sock.closed and sock.raw.closed


@pytest.mark.parametrize(
    "framing", ["close-length", "close-chunked", "http10-length", "http10-eof"]
)
def test_valid_connection_close_responses_use_real_socket_file_lifetime(monkeypatch, framing):
    client = provider(monkeypatch)
    body = signed_response(vector()["payload"])
    if framing == "close-chunked":
        wire = (
            HTTP_HEADERS
            + b"Connection: close\r\nTransfer-Encoding: chunked\r\n\r\n"
            + f"{len(body):x}\r\n".encode()
            + body
            + b"\r\n0\r\n\r\n"
        )
    else:
        status = b"HTTP/1.0 200 OK\r\n" if framing.startswith("http10") else b"HTTP/1.1 200 OK\r\n"
        length = b"" if framing == "http10-eof" else f"Content-Length: {len(body)}\r\n".encode()
        wire = (
            status
            + b"Content-Type: application/json\r\nConnection: close\r\n"
            + length
            + b"\r\n"
            + body
        )
    # A real socketpair makes settimeout after the last makefile reference closes
    # fail with EBADF, which a fake close flag cannot reproduce. No TCP/TLS server.
    reader, writer = socket.socketpair()
    try:
        writer.sendall(wire)
        # Signal response EOF while retaining the peer reader for the client's GET.
        writer.shutdown(socket.SHUT_WR)

        class ConnectedHttps(http.client.HTTPConnection):
            def connect(self):
                self.sock = reader

        monkeypatch.setattr(
            clinic_footer.http.client,
            "HTTPSConnection",
            lambda host, port, **kwargs: ConnectedHttps(host, port, timeout=kwargs["timeout"]),
        )
        assert client.snapshot().revision == vector()["payload"]["revision"]
        assert reader.fileno() == -1
    finally:
        reader.close()
        writer.close()
