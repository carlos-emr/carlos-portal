# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This program is free software: you can redistribute it and/or modify it under the terms of the
# GNU Affero General Public License as published by the Free Software Foundation, either version 3
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
# even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along with this program.
# If not, see <https://www.gnu.org/licenses/>.

"""A cap on how much of a staff or job request is read, before any code reads it.

The staff and job API authenticates with a signature over the request's body, so its dependency
reads the whole body before it can say whether the caller is anyone at all. FastAPI also reads the
body of every route that declares a request model before it runs a single dependency. Either way
an unauthenticated caller could make the portal hold a body as large as the server in front of it
allows (nginx: 8 MiB), or any size without one. A limit inside the route cannot help for the
routes with a model, so the limit sits here, around the whole API, and counts what arrives.
"""

import re
from collections.abc import Callable

from starlette._utils import get_route_path
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from carlos_patient_portal.mailbox_codec import MAX_UPLOAD

INTERNAL_PATH_PREFIX = "/internal/"

# The largest real staff or job request body is a publish of the clinic's keys: 16 keys of at most
# 683 characters each for the key and a replacement signature (about 26 KiB of JSON). The other
# models carry a few short fields (under 4 KiB even for eight offered appointment times).
INTERNAL_BODY_LIMIT = 64 * 1024

# The one route that takes much more: a sealed delivery, whose own limit is the mailbox's.
INTERNAL_BODY_LIMITS = (
    (re.compile(r"/internal/carlos/patients/[^/]+/mycarlos/deliveries"), MAX_UPLOAD),
)

REFUSAL_BODY = b'{"detail":"request too large"}'


def internal_body_limit(path: str) -> int | None:
    """How many bytes of a request to `path` may be read, or None where nothing is capped here."""
    if not path.startswith(INTERNAL_PATH_PREFIX):
        return None
    for pattern, limit in INTERNAL_BODY_LIMITS:
        if pattern.fullmatch(path):
            return limit
    return INTERNAL_BODY_LIMIT


class BodyLimitMiddleware:
    """Refuses a request whose body is over its limit with 413, however it declares its length.

    A declared `Content-Length` over the limit is refused without running the application. A body
    that says nothing (chunked) or understates is counted as it arrives: past the limit the
    application is told the client went away, so nothing reads further, and whatever it then
    answers is replaced by the 413.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        limit_for: Callable[[str], int | None] = internal_body_limit,
    ) -> None:
        self.app = app
        self.limit_for = limit_for

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        limit = self.limit_for(get_route_path(scope)) if scope["type"] == "http" else None
        if limit is None:
            await self.app(scope, receive, send)
            return

        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > limit:
            await self._refuse(send)
            return

        received = 0
        exceeded = False
        app_answered = False
        refused = False

        async def limited_receive() -> Message:
            nonlocal received, exceeded
            if exceeded:
                return {"type": "http.disconnect"}
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    exceeded = True
                    return {"type": "http.disconnect"}
            return message

        async def refuse_once() -> None:
            nonlocal refused
            if not refused and not app_answered:
                refused = True
                await self._refuse(send)

        async def limited_send(message: Message) -> None:
            nonlocal app_answered
            if exceeded:
                await refuse_once()
                return
            app_answered = True
            await send(message)

        try:
            await self.app(scope, limited_receive, limited_send)
        except Exception:
            # The application may have failed on the client that went away (FastAPI answers a
            # body it could not read with 422); that is this refusal's doing, not its own.
            if not exceeded:
                raise
        if exceeded:
            await refuse_once()

    @staticmethod
    async def _refuse(send: Send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(REFUSAL_BODY)).encode("ascii")),
                    (b"cache-control", b"no-store"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": REFUSAL_BODY})
