# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Builds the iPhone push transport from settings (iPhone push, piece 7: the outbox wiring).

`availability_dispatch_for` returns the `AvailabilityDispatch` the dispatch worker needs (an APNs
transport and the notice-token key), or None while push is off. It checks the Apple key file as it
builds the signer, so a bad file stops the portal at start-up. The HTTP client is injected:
APNs speaks HTTP/2 only, and the portal's runtime dependencies carry no HTTP/2 client yet, so a
deployment cannot turn push on until one is supplied (a dependency decision, see the pull
request). Nothing here logs, prints or returns key material.
"""

from __future__ import annotations

from base64 import urlsafe_b64decode
from collections.abc import Callable
from time import time

from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.apns_provider import ApnsKeyError, ApnsProviderJwtSigner
from carlos_patient_portal.config import Settings
from carlos_patient_portal.mycarlos_availability import NoticeKeys, PushPlatform
from carlos_patient_portal.mycarlos_availability_dispatch import AvailabilityDispatch
from carlos_patient_portal.mycarlos_push_handles import HandleKeys, SqlDestinationHandles
from carlos_patient_portal.notification_transports import (
    ApnsConfig,
    ApnsTokenTransport,
    HttpClient,
)

__all__ = ["HttpClient", "availability_dispatch_for"]


def availability_dispatch_for(
    settings: Settings,
    session_factory: Callable[[], Session] | sessionmaker[Session],
    http_client: HttpClient | None,
    *,
    clock: Callable[[], int] | None = None,
) -> AvailabilityDispatch | None:
    """The worker's config, or None while iPhone push is off.

    Raises ``ApnsKeyError`` (a fixed code only) when push is on and something is missing: no HTTP
    client (`apns_http_client_unavailable`) or a key file that does not pass its checks.
    """
    if not settings.mycarlos_apns_enabled:
        return None
    if http_client is None:
        raise ApnsKeyError("apns_http_client_unavailable")
    # The settings validator already checked these are present and well formed.
    assert settings.mycarlos_apns_key_path is not None  # noqa: S101
    assert settings.mycarlos_apns_team_id and settings.mycarlos_apns_key_id  # noqa: S101
    assert settings.mycarlos_apns_bundle_id  # noqa: S101
    now = clock or (lambda: int(time()))
    config = ApnsConfig(
        settings.mycarlos_apns_team_id,
        settings.mycarlos_apns_key_id,
        settings.mycarlos_apns_key_path,
        settings.mycarlos_apns_bundle_id,
    )
    signer = ApnsProviderJwtSigner(config, now)
    handles = SqlDestinationHandles(
        session_factory,
        HandleKeys(settings.resolved_outbox_keyring, settings.outbox_active_key_id),
    )
    encoded = settings.secret_value("mycarlos_notice_token_key") or ""
    notice_key = urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    transport = ApnsTokenTransport(config, http_client, handles, signer, now, environments=handles)
    return AvailabilityDispatch(
        {PushPlatform.IOS_APNS: transport},
        NoticeKeys(notice_key),
    )
