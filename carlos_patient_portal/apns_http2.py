# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The HTTP/2 client the iPhone push goes out through.

Apple's push service accepts HTTP/2 only (over TLS, with ALPN ``h2``), so the portal's push
transport needs a client that speaks it. This is the one place that builds it, as the
``HttpClient`` the transports already use (``notification_transports.HttpClient``): one request,
one response with only a status code read, a transport loss raised as ``TimeoutError`` or
``ConnectionError``, no redirect followed, no retry, and no log line (the HTTP libraries' own log
records, which carry the device token and the provider token, are shut off: see
`silence_http_libraries`).

The client is ``httpx2`` with its ``http2`` extra (``h2``, ``hpack`` and ``hyperframe``), a
runtime dependency of the portal and hash-locked like the others. Everything about a request
(the device token in the path, the provider token in a header) stays out of any exception text:
a failure is raised with fixed words and the cause is dropped.

Start-up check: [`require_http2`] imports ``h2``, so a portal that was installed without the
extra refuses to start with push on (code ``apns_http2_unavailable``) rather than failing at
the first push.
"""

from __future__ import annotations

import logging
import ssl
import weakref
from importlib import import_module

from carlos_patient_portal.apns_provider import ApnsKeyError
from carlos_patient_portal.notification_transports import HttpRequest, HttpResponse

# The libraries under the client log what they do: `httpx2` writes every request at INFO with the
# full URL (the device token is in the path), and `httpcore2` at DEBUG traces the headers (the
# provider token is one). The portal logs no provider detail, so these loggers are shut: records
# stop at the first of them (no propagation to the application's handlers) and are dropped there,
# whatever level an application's logging configuration gives their children.
#
# Known limit: a handler attached directly to a *child* logger (for example `httpcore2.http2`) still
# sees that child's records; nothing in the portal does that, and the guard is repeated before every
# push so a later `dictConfig` cannot reopen the four parents.
_QUIET_LOGGERS = ("httpx2", "httpcore2", "h2", "hpack")


def silence_http_libraries() -> None:
    """Keeps the HTTP libraries' log records out of every handler. Safe to call again."""
    for name in _QUIET_LOGGERS:
        logger = logging.getLogger(name)
        logger.setLevel(logging.WARNING)
        logger.propagate = False
        if not any(isinstance(handler, logging.NullHandler) for handler in logger.handlers):
            logger.addHandler(logging.NullHandler())


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
        silence_http_libraries()
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
        # Closed when this object is collected or the process ends, so the connection to Apple is
        # not left to the operating system.
        weakref.finalize(self, self._client.close)

    def __repr__(self) -> str:
        return "Http2Client[REDACTED]"

    def close(self) -> None:
        self._client.close()

    def send(self, request: HttpRequest, *, timeout: float) -> HttpResponse:
        # Before every push, not only at construction: an application that configures logging
        # after the client was made (a `dictConfig` that reopens `httpx2`) is put right again here.
        silence_http_libraries()
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
