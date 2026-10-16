# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Read current, signed clinic branding from its sole administrator: CARLOS.

This client uses a narrowly derived read credential, never the internal API bearer.
The signed Java-produced plaintext is authoritative; Python does not emulate Jsoup.
"""

import base64
import hashlib
import http.client
import io
import json
import re
import secrets
import socket
import ssl
import time
import unicodedata
from collections.abc import Callable
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Protocol
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from carlos_patient_portal.config import Settings

MAX_FOOTER_PAYLOAD_BYTES = 256 * 1024
MAX_FOOTER_RESPONSE_BYTES = 512 * 1024
MAX_FOOTER_LOGO_BYTES = 100 * 1024
FOOTER_AUDIENCE = "carlos-patient-portal-email-footer"
CID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9.-]*")
HASH_PATTERN = re.compile(r"[0-9a-f]{64}")
_PAYLOAD_FIELDS = frozenset(
    {
        "iss",
        "aud",
        "iat",
        "exp",
        "nonce",
        "clinic_id",
        "kid",
        "footer_html",
        "footer_text",
        "revision",
        "logo",
    }
)


class ClinicFooterUnavailableError(Exception):
    """The current mandatory clinic footer could not be safely prepared."""


def _unavailable() -> ClinicFooterUnavailableError:
    return ClinicFooterUnavailableError("clinic email footer is unavailable")


def decode_base64url(value: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise _unavailable()
    if len(value) > 4 * ((maximum + 2) // 3):
        raise _unavailable()
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
    except ValueError:
        raise _unavailable() from None
    if len(decoded) > maximum or encode_base64url(decoded) != value:
        raise _unavailable()
    return decoded


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _unavailable()
        result[key] = value
    return result


def bounded_json(value: bytes, *, maximum: int) -> dict[str, object]:
    if len(value) > maximum:
        raise _unavailable()
    try:
        result = json.loads(value.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeError, ValueError, RecursionError):
        raise _unavailable() from None
    if not isinstance(result, dict):
        raise _unavailable()
    return result


def _visible(value: str) -> bool:
    return any(unicodedata.category(c)[0] not in {"C", "Z"} for c in value)


def _bounded_text(value: object, maximum: int) -> str:
    if not isinstance(value, str):
        raise _unavailable()
    try:
        length = len(value.encode("utf-16-le")) // 2
    except UnicodeError:
        raise _unavailable() from None
    if not 0 < length <= maximum or not _visible(value):
        raise _unavailable()
    return value


class _FooterHtmlValidator(HTMLParser):
    _allowed = frozenset({"b", "strong", "i", "em", "br", "p", "div", "a"})

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[str] = []
        self.visible = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag not in self._allowed or len(attrs) > 1:
            raise _unavailable()
        for name, value in attrs:
            if tag != "a" or name != "href" or value is None:
                raise _unavailable()
            if any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} or c == "\ufffd" for c in value):
                raise _unavailable()
            if urlsplit(value).scheme.lower() not in {"https", "mailto"}:
                raise _unavailable()
        if tag != "br":
            self.stack.append(tag)

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag != "br":
            self.handle_endtag(tag)

    def handle_endtag(self, tag: str) -> None:
        if not self.stack or self.stack.pop() != tag:
            raise _unavailable()

    def handle_data(self, data: str) -> None:
        self.visible |= _visible(data)

    def handle_comment(self, data: str) -> None:
        raise _unavailable()

    def handle_decl(self, decl: str) -> None:
        raise _unavailable()

    def handle_pi(self, data: str) -> None:
        raise _unavailable()


@dataclass(frozen=True)
class ClinicFooterLogo:
    content_id: str
    content_type: str
    data: bytes

    def __post_init__(self) -> None:
        if (
            not isinstance(self.content_id, str)
            or not 1 <= len(self.content_id) <= 128
            or CID_PATTERN.fullmatch(self.content_id) is None
            or self.content_type not in {"image/png", "image/jpeg"}
            or not isinstance(self.data, bytes)
            or not 0 < len(self.data) <= MAX_FOOTER_LOGO_BYTES
        ):
            raise _unavailable()

    @property
    def sha256(self) -> str:
        return hashlib.sha256(self.data).hexdigest()

    def to_dict(self) -> dict[str, str]:
        return {
            "content_id": self.content_id,
            "content_type": self.content_type,
            "bytes_base64": base64.b64encode(self.data).decode("ascii"),
            "sha256": self.sha256,
        }


def footer_revision(html: str, plain: str, logo: ClinicFooterLogo | None) -> str:
    digest = hashlib.sha256()
    for component in (
        html.encode("utf-8"),
        plain.encode("utf-8"),
        logo.content_id.encode("ascii") if logo else b"",
        logo.content_type.encode("ascii") if logo else b"",
        logo.data if logo else b"",
    ):
        digest.update(len(component).to_bytes(8, "big"))
        digest.update(component)
    return digest.hexdigest()


@dataclass(frozen=True)
class ClinicFooterSnapshot:
    clinic_id: str
    html: str
    plain: str
    revision: str
    logo: ClinicFooterLogo | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.clinic_id, str) or not re.fullmatch(
            r"[A-Za-z0-9._-]{1,64}", self.clinic_id
        ):
            raise _unavailable()
        _bounded_text(self.html, 10_000)
        _bounded_text(self.plain, 2_000)
        parser = _FooterHtmlValidator()
        try:
            parser.feed(self.html)
            parser.close()
        except ValueError:
            raise _unavailable() from None
        if (
            parser.stack
            or not parser.visible
            or self.revision != footer_revision(self.html, self.plain, self.logo)
        ):
            raise _unavailable()

    def to_dict(self) -> dict[str, object]:
        return {
            "clinic_id": self.clinic_id,
            "footer_html": self.html,
            "footer_text": self.plain,
            "revision": self.revision,
            "logo": self.logo.to_dict() if self.logo else None,
        }

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> "ClinicFooterSnapshot":
        if set(value) != {"clinic_id", "footer_html", "footer_text", "revision", "logo"}:
            raise _unavailable()
        logo = None
        if value["logo"] is not None:
            item = value["logo"]
            if not isinstance(item, dict) or set(item) != {
                "content_id",
                "content_type",
                "bytes_base64",
                "sha256",
            }:
                raise _unavailable()
            encoded = item["bytes_base64"]
            if not isinstance(encoded, str) or len(encoded) > 4 * (
                (MAX_FOOTER_LOGO_BYTES + 2) // 3
            ):
                raise _unavailable()
            try:
                raw = base64.b64decode(encoded, validate=True)
                logo = ClinicFooterLogo(item["content_id"], item["content_type"], raw)
            except (ValueError, TypeError):
                raise _unavailable() from None
            if base64.b64encode(raw).decode("ascii") != encoded or logo.sha256 != item["sha256"]:
                raise _unavailable()
        return cls(
            value["clinic_id"], value["footer_html"], value["footer_text"], value["revision"], logo
        )


class ClinicFooterProvider(Protocol):
    def snapshot(self) -> ClinicFooterSnapshot: ...


class _DeadlineReader(io.RawIOBase):
    """Bound every socket read, including http.client's buffered framing reads."""

    def __init__(self, raw: io.RawIOBase, sock: socket.socket, deadline: float) -> None:
        super().__init__()
        self._raw = raw
        self._socket = sock
        self._deadline = deadline

    def readable(self) -> bool:
        return True

    def _remaining(self) -> float:
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("clinic footer response deadline exceeded")
        return remaining

    def readinto(self, buffer: bytearray | memoryview) -> int | None:
        self._socket.settimeout(self._remaining())
        count = self._raw.readinto(buffer)
        self._remaining()
        return count

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


class _DeadlineSocket:
    def __init__(self, sock: socket.socket, deadline: float) -> None:
        self._socket = sock
        self._deadline = deadline

    def makefile(self, mode: str) -> io.BufferedReader:
        if mode != "rb":
            raise ValueError("clinic footer response reader requires binary mode")
        # Wrapping the unbuffered socket file ensures readline/read/read1 all reset
        # the remaining deadline at each actual receive, not each header/body chunk.
        raw = self._socket.makefile(mode, buffering=0)
        return io.BufferedReader(_DeadlineReader(raw, self._socket, self._deadline))


class HttpsClinicFooterProvider:
    def __init__(self, settings: Settings, *, clock: Callable[[], float] = time.time) -> None:
        self._url = urlsplit(settings.email_footer_url or "")
        self._credential = settings.secret_value("email_footer_read_token")
        self._clinic_id = settings.clinic_id
        self._timeout = settings.email_footer_timeout_seconds
        self._context = ssl.create_default_context(cafile=settings.email_footer_ca_file)
        self._keys = {
            kid: Ed25519PublicKey.from_public_bytes(decode_base64url(key, maximum=32))
            for kid, key in settings.resolved_internal_staff_assertion_public_keys.items()
        }
        self._clock = clock

    def _fetch(self, nonce: str) -> bytes:
        connection = http.client.HTTPSConnection(
            self._url.hostname,
            self._url.port,
            timeout=self._timeout,
            context=self._context,
        )
        response = None
        try:
            connection.connect()
            response_socket = connection.sock
            deadline = time.monotonic() + self._timeout
            connection.response_class = lambda sock, *args, **kwargs: http.client.HTTPResponse(
                _DeadlineSocket(sock, deadline), *args, **kwargs
            )
            connection.request(
                "GET",
                self._url.path + "?nonce=" + nonce,
                headers={
                    "Authorization": "Bearer " + self._credential,
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            )
            if response_socket is not None:
                response_socket.settimeout(max(0.001, deadline - time.monotonic()))
            response = connection.getresponse()
            if (
                response.status != 200
                or response.getheader("Content-Type", "").split(";")[0].strip()
                != "application/json"
                or response.getheader("Content-Encoding", "identity") != "identity"
            ):
                raise _unavailable()
            declared = response.getheader("Content-Length")
            if declared is not None and (
                not declared.isdecimal() or int(declared) > MAX_FOOTER_RESPONSE_BYTES
            ):
                raise _unavailable()
            chunks: list[bytes] = []
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise _unavailable()
                chunk = response.read1(min(8192, MAX_FOOTER_RESPONSE_BYTES - size + 1))
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_FOOTER_RESPONSE_BYTES:
                    raise _unavailable()
                chunks.append(chunk)
            return b"".join(chunks)
        except (OSError, ValueError, http.client.HTTPException):
            raise _unavailable() from None
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                connection.close()

    def snapshot(self) -> ClinicFooterSnapshot:
        if self._url.scheme != "https" or self._credential is None or not self._keys:
            raise _unavailable()
        nonce = encode_base64url(secrets.token_bytes(32))
        response = bounded_json(self._fetch(nonce), maximum=MAX_FOOTER_RESPONSE_BYTES)
        if set(response) != {"assertion"} or not isinstance(response["assertion"], str):
            raise _unavailable()
        parts = response["assertion"].split(".")
        if len(parts) != 2:
            raise _unavailable()
        encoded = decode_base64url(parts[0], maximum=MAX_FOOTER_PAYLOAD_BYTES)
        signature = decode_base64url(parts[1], maximum=64)
        payload = bounded_json(encoded, maximum=MAX_FOOTER_PAYLOAD_BYTES)
        if set(payload) != _PAYLOAD_FIELDS or not isinstance(payload["kid"], str):
            raise _unavailable()
        key = self._keys.get(payload["kid"])
        if key is None or len(signature) != 64:
            raise _unavailable()
        try:
            key.verify(signature, encoded)
        except InvalidSignature:
            raise _unavailable() from None
        now = self._clock()
        issued, expires = payload["iat"], payload["exp"]
        if (
            payload["iss"] != "carlos"
            or payload["aud"] != FOOTER_AUDIENCE
            or payload["clinic_id"] != self._clinic_id
            or payload["nonce"] != nonce
            or type(issued) is not int
            or type(expires) is not int
            or not 0 < expires - issued <= 60
            or issued > now + 5
            or expires <= now
        ):
            raise _unavailable()
        return ClinicFooterSnapshot.from_dict(
            {
                k: payload[k]
                for k in (
                    "clinic_id",
                    "footer_html",
                    "footer_text",
                    "revision",
                    "logo",
                )
            }
        )
