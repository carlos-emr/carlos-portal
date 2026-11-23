# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Test doubles for the provider adapters. Tests and local rehearsals only: the application
never imports this module (a test asserts it), and no real credential or network is involved."""

from __future__ import annotations

from collections.abc import Mapping
from uuid import UUID

from carlos_patient_portal.notification_transports import (
    ApnsConfig,
    ApnsTokenTransport,
    DestinationHandles,
    FcmConfig,
    FcmV1Transport,
    HttpRequest,
    HttpResponse,
    WnsConfig,
    WnsTransport,
)


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
