# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The HTTP/2 client the iPhone push goes out through.

Apple's push service accepts HTTP/2 only (over TLS, with ALPN ``h2``), so the portal's push
transport needs a client that speaks it. This is the one place that builds it, as the
``HttpClient`` the transports already use (``notification_transports.HttpClient``): one request,
one response with only a status code read, a transport loss raised as ``TimeoutError`` or
``ConnectionError``, no redirect followed, no retry, no log line.

The client is ``httpx2`` with its ``http2`` extra (``h2``, ``hpack`` and ``hyperframe``), a
runtime dependency of the portal and hash-locked like the others. Everything about a request
(the device token in the path, the provider token in a header) stays out of any exception text:
a failure is raised with fixed words and the cause is dropped.

Start-up check: [`require_http2`] imports ``h2``, so a portal that was installed without the
extra refuses to start with push on (code ``apns_http2_unavailable``) rather than failing at
the first push.
"""

from __future__ import annotations

import ssl
from importlib import import_module

from carlos_patient_portal.apns_provider import ApnsKeyError
from carlos_patient_portal.notification_transports import HttpRequest, HttpResponse


def require_http2() -> None:
    """Refuses (``ApnsKeyError("apns_http2_unavailable")``) unless the HTTP/2 packages import."""
    try:
        import_module("h2.connection")
        import_module("httpx2")
    except ImportError:
        raise ApnsKeyError("apns_http2_unavailable") from None


class Http2Client:
    """An ``HttpClient`` over HTTP/2. One client for the process: it keeps a connection to Apple
    open between pushes (Apple asks for that) and is safe to use from several threads.

    `verify` is the TLS trust: the platform's trust store by default (``httpx2`` uses
    ``truststore``); a test hands in the context of its own test authority. Proxies and the
    environment's certificate overrides are not read (`trust_env` is off): the push goes straight
    to Apple, and nothing in the environment can redirect it.
    """

    def __init__(self, *, verify: ssl.SSLContext | bool = True) -> None:
        require_http2()
        import httpx2

        self._httpx = httpx2
        self._client = httpx2.Client(
            http2=True,
            http1=False,
            verify=verify,
            follow_redirects=False,
            trust_env=False,
            # A pool of one host with a few connections: pushes to Apple are one host.
            limits=httpx2.Limits(max_connections=4, max_keepalive_connections=2),
        )

    def __repr__(self) -> str:
        return "Http2Client[REDACTED]"

    def close(self) -> None:
        self._client.close()

    def send(self, request: HttpRequest, *, timeout: float) -> HttpResponse:
        httpx2 = self._httpx
        try:
            response = self._client.request(
                request.method,
                request.url,
                headers=dict(request.headers),
                content=request.body,
                timeout=httpx2.Timeout(timeout),
            )
        except httpx2.TimeoutException:
            raise TimeoutError("provider_timeout") from None
        except httpx2.HTTPError:
            # A refused connection, a reset, a TLS failure, a protocol error: the portal only
            # needs to know the provider could not be reached. The cause names hosts and paths,
            # so it is dropped.
            raise ConnectionError("provider_unreachable") from None
        try:
            return HttpResponse(response.status_code)
        finally:
            response.close()
