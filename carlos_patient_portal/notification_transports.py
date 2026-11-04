# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Provider adapters for the opaque "documents ready" hint (FCM v1, APNs, WNS).

Each adapter implements ``AvailabilityTransport.send`` and nothing else. The request carries only
the generic notice and the opaque, content-free hint (at most 256 bytes, no text, no document or
patient identifier), never the portal's own destination id. All HTTP goes through one injected
``HttpClient``; credentials come from injected sources; nothing here reads settings, the
environment or a file, opens a socket, or logs. Default off and not wired: no route, worker or
setting constructs these classes yet.

Outcome mapping (status code only; a response body, header or exception text is never read into
a decision):

* 2xx -> ``ACCEPTED`` (accepted by the provider, never "seen by the person");
* 429, 5xx, a client timeout or a lost connection -> ``TransportFailure`` (retryable);
* the provider saying the destination is gone (FCM 404, APNs 410, WNS 404/410) ->
  ``INVALID_DESTINATION``;
* any other 4xx (including 400, 401 and 403) -> ``PERMANENT_FAILURE`` (never retried);
* any other status -> ``PERMANENT_FAILURE`` as well.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit
from uuid import UUID
from xml.sax.saxutils import escape, quoteattr

from carlos_patient_portal.mycarlos_availability import (
    GenericNotice,
    ProviderResult,
    PushPlatform,
    TransportFailure,
)

HTTP_TIMEOUT_SECONDS = 10.0
FCM_ENDPOINT = "https://fcm.googleapis.com/v1/projects/{project_id}/messages:send"
APNS_PRODUCTION_HOST = "https://api.push.apple.com"
APNS_SANDBOX_HOST = "https://api.sandbox.push.apple.com"
WNS_HOST_SUFFIX = ".notify.windows.com"
MAX_COLLAPSE_KEY_BYTES = 64
_FCM_TOKEN = re.compile(r"[A-Za-z0-9_:\-.]{20,4096}")
_APNS_TOKEN = re.compile(r"[0-9a-fA-F]{64,200}")
_PROJECT_ID = re.compile(r"[a-z][a-z0-9\-]{4,28}[a-z0-9]")
_ASCII_ID = re.compile(r"[A-Za-z0-9._\-]{1,128}")
_PACKAGE_SID = re.compile(r"(?:ms-app://)?[sS]-1-15-2(?:-\d{1,10}){7}")


# --- The two injected seams -------------------------------------------------------------------


@dataclass(frozen=True, repr=False)
class HttpRequest:
    """The exact request an adapter would send. ``repr`` never prints headers or body."""

    method: str
    url: str
    headers: Mapping[str, str]
    body: bytes

    def __repr__(self) -> str:
        return "HttpRequest[REDACTED]"


@dataclass(frozen=True, repr=False)
class HttpResponse:
    """Only the status code is read. Provider bodies and headers never enter a decision."""

    status: int

    def __repr__(self) -> str:
        return f"HttpResponse[{self.status}]"


class HttpClient(Protocol):
    """One request, one response; raise ``TimeoutError`` or ``ConnectionError`` on transport loss.

    Implementations must enforce ``timeout`` and must not follow redirects, retry, or log.
    """

    def send(self, request: HttpRequest, *, timeout: float) -> HttpResponse: ...


class DestinationHandles(Protocol):
    """Maps the portal's opaque destination id to the provider's own handle (FCM registration
    token, APNs device token, WNS channel URI), or None when it is unknown or revoked."""

    def handle_for(self, destination_id: UUID) -> str | None: ...


class BearerTokenSource(Protocol):
    """Short-lived OAuth access token (FCM) or channel token (WNS). Never logged or persisted."""

    def bearer_token(self) -> str: ...


class ProviderJwtSource(Protocol):
    """APNs provider token (ES256 JWT, valid under an hour), signed from the key file."""

    def provider_token(self) -> str: ...


# --- Config objects (not read from settings yet) ----------------------------------------------


class _SecretRepr:
    def __repr__(self) -> str:
        return f"{type(self).__name__}[REDACTED]"


@dataclass(frozen=True, repr=False)
class FcmConfig(_SecretRepr):
    """FCM HTTP v1: Firebase project id and the service-account key *path* (never read here)."""

    project_id: str
    service_account_path: Path

    def __post_init__(self) -> None:
        if not isinstance(self.project_id, str) or not _PROJECT_ID.fullmatch(self.project_id):
            raise ValueError("invalid_fcm_project_id")
        if not isinstance(self.service_account_path, Path):
            raise ValueError("invalid_fcm_service_account_path")


@dataclass(frozen=True, repr=False)
class ApnsConfig(_SecretRepr):
    """APNs token auth: Apple team id, key id, the .p8 key *path* (never read here), bundle id."""

    team_id: str
    key_id: str
    key_path: Path
    bundle_id: str
    sandbox: bool = False

    def __post_init__(self) -> None:
        for value in (self.team_id, self.key_id, self.bundle_id):
            if not isinstance(value, str) or not _ASCII_ID.fullmatch(value):
                raise ValueError("invalid_apns_config")
        if not isinstance(self.key_path, Path) or not isinstance(self.sandbox, bool):
            raise ValueError("invalid_apns_config")


@dataclass(frozen=True, repr=False)
class WnsConfig(_SecretRepr):
    """WNS: package SID and client secret (held in memory only, never printed)."""

    package_sid: str
    client_secret: str = field(repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.package_sid, str) or not _PACKAGE_SID.fullmatch(self.package_sid):
            raise ValueError("invalid_wns_package_sid")
        if not isinstance(self.client_secret, str) or not 8 <= len(self.client_secret) <= 512:
            raise ValueError("invalid_wns_client_secret")


# --- Shared pieces ----------------------------------------------------------------------------


def _hint_text(notice: GenericNotice) -> str:
    """The opaque hint as unpadded base64url: all a provider message may carry besides the
    generic notice text."""
    return base64.urlsafe_b64encode(notice.hint.encode()).rstrip(b"=").decode("ascii")


def _check_send(
    platform: PushPlatform, expected: tuple[PushPlatform, ...], ttl_seconds: int, collapse_key: str
) -> None:
    if platform not in expected:
        raise TypeError("wrong_platform_for_transport")
    if not isinstance(ttl_seconds, int) or isinstance(ttl_seconds, bool) or ttl_seconds < 1:
        raise ValueError("invalid_ttl")
    if (
        not isinstance(collapse_key, str)
        or not 1 <= len(collapse_key.encode("ascii", "strict")) <= MAX_COLLAPSE_KEY_BYTES
    ):
        raise ValueError("invalid_collapse_key")


def _classify(status: int, invalid_destination: frozenset[int]) -> ProviderResult:
    """Status code only. Retryable provider trouble is raised, never returned."""
    if 200 <= status < 300:
        return ProviderResult.ACCEPTED
    if status in invalid_destination:
        return ProviderResult.INVALID_DESTINATION
    if status == 429 or 500 <= status < 600:
        raise TransportFailure("provider_unavailable")
    return ProviderResult.PERMANENT_FAILURE


def _post(http: HttpClient, request: HttpRequest) -> HttpResponse:
    try:
        response = http.send(request, timeout=HTTP_TIMEOUT_SECONDS)
    except (TimeoutError, ConnectionError, OSError):
        # Fixed text; the exception text (hosts, paths, provider detail) is dropped on purpose.
        raise TransportFailure("provider_unreachable") from None
    if not isinstance(response, HttpResponse) or not isinstance(response.status, int):
        raise TypeError("invalid_http_response")
    return response


# --- FCM HTTP v1 (Android) --------------------------------------------------------------------


class FcmV1Transport:
    """POST https://fcm.googleapis.com/v1/projects/<id>/messages:send, OAuth bearer token."""

    def __init__(
        self, config: FcmConfig, http: HttpClient, handles: DestinationHandles,
        tokens: BearerTokenSource,
    ) -> None:
        self._config = config
        self._http = http
        self._handles = handles
        self._tokens = tokens

    def build_request(
        self, *, handle: str, notice: GenericNotice, ttl_seconds: int, collapse_key: str
    ) -> HttpRequest:
        message = {
            "message": {
                "token": handle,
                "notification": {"title": notice.title, "body": notice.body},
                "data": {"h": _hint_text(notice)},
                "android": {
                    "collapse_key": collapse_key,
                    "ttl": f"{ttl_seconds}s",
                    "priority": "HIGH",
                },
            }
        }
        return HttpRequest(
            method="POST",
            url=FCM_ENDPOINT.format(project_id=self._config.project_id),
            headers={
                "Authorization": f"Bearer {self._tokens.bearer_token()}",
                "Content-Type": "application/json; charset=UTF-8",
            },
            body=json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        )

    def send(
        self, *, destination_id: UUID, platform: PushPlatform, notice: GenericNotice,
        ttl_seconds: int, collapse_key: str,
    ) -> ProviderResult:
        _check_send(platform, (PushPlatform.ANDROID_FCM,), ttl_seconds, collapse_key)
        handle = self._handles.handle_for(destination_id)
        if handle is None or not _FCM_TOKEN.fullmatch(handle):
            return ProviderResult.INVALID_DESTINATION
        request = self.build_request(
            handle=handle, notice=notice, ttl_seconds=ttl_seconds, collapse_key=collapse_key
        )
        return _classify(_post(self._http, request).status, frozenset({404}))


# --- APNs token auth (iOS and macOS) ----------------------------------------------------------


class ApnsTokenTransport:
    """POST /3/device/<token> over HTTP/2 with ``authorization: bearer <provider JWT>``."""

    def __init__(
        self, config: ApnsConfig, http: HttpClient, handles: DestinationHandles,
        jwts: ProviderJwtSource, clock: Callable[[], int],
    ) -> None:
        self._config = config
        self._http = http
        self._handles = handles
        self._jwts = jwts
        self._clock = clock

    def build_request(
        self, *, handle: str, notice: GenericNotice, ttl_seconds: int, collapse_key: str
    ) -> HttpRequest:
        host = APNS_SANDBOX_HOST if self._config.sandbox else APNS_PRODUCTION_HOST
        payload = {
            "aps": {"alert": {"title": notice.title, "body": notice.body}},
            "h": _hint_text(notice),
        }
        return HttpRequest(
            method="POST",
            url=f"{host}/3/device/{handle.lower()}",
            headers={
                "authorization": f"bearer {self._jwts.provider_token()}",
                "apns-topic": self._config.bundle_id,
                "apns-push-type": "alert",
                "apns-priority": "10",
                "apns-expiration": str(self._clock() + ttl_seconds),
                "apns-collapse-id": collapse_key,
                "content-type": "application/json",
            },
            body=json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"),
        )

    def send(
        self, *, destination_id: UUID, platform: PushPlatform, notice: GenericNotice,
        ttl_seconds: int, collapse_key: str,
    ) -> ProviderResult:
        _check_send(
            platform, (PushPlatform.IOS_APNS, PushPlatform.MACOS_APNS), ttl_seconds, collapse_key
        )
        handle = self._handles.handle_for(destination_id)
        if handle is None or not _APNS_TOKEN.fullmatch(handle):
            return ProviderResult.INVALID_DESTINATION
        request = self.build_request(
            handle=handle, notice=notice, ttl_seconds=ttl_seconds, collapse_key=collapse_key
        )
        # 410: the token is no longer active. 400 (BadDeviceToken and the rest) is permanent.
        return _classify(_post(self._http, request).status, frozenset({410}))


# --- WNS (Windows) ----------------------------------------------------------------------------


def _wns_channel_ok(handle: str) -> bool:
    """The channel URI must be https on a Microsoft notify host: it is a URL we will POST to."""
    try:
        parts = urlsplit(handle)
    except ValueError:
        return False
    host = parts.hostname or ""
    return (
        parts.scheme == "https"
        and host.endswith(WNS_HOST_SUFFIX)
        and parts.username is None
        and parts.password is None
        and parts.port in (None, 443)
        and len(handle) <= 2048
    )


class WnsTransport:
    """POST a toast to the channel URI with an OAuth bearer token for the package SID."""

    def __init__(
        self, config: WnsConfig, http: HttpClient, handles: DestinationHandles,
        tokens: BearerTokenSource,
    ) -> None:
        self._config = config
        self._http = http
        self._handles = handles
        self._tokens = tokens

    def build_request(
        self, *, handle: str, notice: GenericNotice, ttl_seconds: int, collapse_key: str
    ) -> HttpRequest:
        toast = (
            f"<toast launch={quoteattr('h=' + _hint_text(notice))}><visual>"
            '<binding template="ToastGeneric">'
            f"<text>{escape(notice.title)}</text><text>{escape(notice.body)}</text>"
            "</binding></visual></toast>"
        )
        return HttpRequest(
            method="POST",
            url=handle,
            headers={
                "Authorization": f"Bearer {self._tokens.bearer_token()}",
                "Content-Type": "text/xml",
                "X-WNS-Type": "wns/toast",
                "X-WNS-TTL": str(ttl_seconds),
                # WNS tags are at most 16 characters: the head of the stable collapse identity.
                "X-WNS-Tag": collapse_key[:16],
                "X-WNS-Cache-Policy": "cache",
            },
            body=toast.encode("utf-8"),
        )

    def send(
        self, *, destination_id: UUID, platform: PushPlatform, notice: GenericNotice,
        ttl_seconds: int, collapse_key: str,
    ) -> ProviderResult:
        _check_send(platform, (PushPlatform.WINDOWS_WNS,), ttl_seconds, collapse_key)
        handle = self._handles.handle_for(destination_id)
        if handle is None or not _wns_channel_ok(handle):
            return ProviderResult.INVALID_DESTINATION
        request = self.build_request(
            handle=handle, notice=notice, ttl_seconds=ttl_seconds, collapse_key=collapse_key
        )
        return _classify(_post(self._http, request).status, frozenset({404, 410}))


# --- Recording fakes (tests and local rehearsals; no network) ---------------------------------


class RecordingHttpClient:
    """Records every request and answers from a scripted list of statuses (or exceptions)."""

    def __init__(self, *responses: int | BaseException) -> None:
        self.requests: list[HttpRequest] = []
        self._responses = list(responses) or [200]

    def send(self, request: HttpRequest, *, timeout: float) -> HttpResponse:
        self.requests.append(request)
        item = self._responses.pop(0) if len(self._responses) > 1 else self._responses[0]
        if isinstance(item, BaseException):
            raise item
        return HttpResponse(item)


class FixedHandles:
    """A fixed destination-id -> handle table; unknown ids are None."""

    def __init__(self, table: Mapping[UUID, str]) -> None:
        self._table = dict(table)

    def handle_for(self, destination_id: UUID) -> str | None:
        return self._table.get(destination_id)


class FixedToken:
    """A fake token source for both token protocols."""

    def __init__(self, token: str = "fake-token") -> None:  # noqa: S107 (a fake, not a secret)
        self._token = token

    def bearer_token(self) -> str:
        return self._token

    def provider_token(self) -> str:
        return self._token


class RecordingFcmTransport(FcmV1Transport):
    """``FcmV1Transport`` over a recording client: ``.requests`` is what would have been sent."""

    def __init__(
        self, config: FcmConfig, handles: DestinationHandles, *responses: int | BaseException
    ) -> None:
        self.http = RecordingHttpClient(*responses)
        super().__init__(config, self.http, handles, FixedToken())

    @property
    def requests(self) -> list[HttpRequest]:
        return self.http.requests


class RecordingApnsTransport(ApnsTokenTransport):
    """``ApnsTokenTransport`` over a recording client and a fixed clock."""

    def __init__(
        self, config: ApnsConfig, handles: DestinationHandles, *responses: int | BaseException,
        now: int = 1_800_000_000,
    ) -> None:
        self.http = RecordingHttpClient(*responses)
        super().__init__(config, self.http, handles, FixedToken(), lambda: now)

    @property
    def requests(self) -> list[HttpRequest]:
        return self.http.requests


class RecordingWnsTransport(WnsTransport):
    """``WnsTransport`` over a recording client."""

    def __init__(
        self, config: WnsConfig, handles: DestinationHandles, *responses: int | BaseException
    ) -> None:
        self.http = RecordingHttpClient(*responses)
        super().__init__(config, self.http, handles, FixedToken())

    @property
    def requests(self) -> list[HttpRequest]:
        return self.http.requests
