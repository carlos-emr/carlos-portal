# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Builds the iPhone push transport from settings (iPhone push, piece 7: the outbox wiring).

`availability_dispatch_for` returns the `AvailabilityDispatch` the dispatch worker needs (an APNs
transport and the notice-token key), or None while push is off. It checks the Apple key file as it
builds the signer, so a bad file stops the portal at start-up. The HTTP client is the portal's
HTTP/2 client (`apns_http2.Http2Client`, since APNs speaks HTTP/2 only), made here unless a test
injects a fake; a portal installed without the HTTP/2 packages refuses to start with push on.
Nothing here logs, prints or returns key material.
"""

from __future__ import annotations

import logging
from base64 import urlsafe_b64decode
from collections.abc import Callable
from time import time

from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.apns_http2 import Http2Client
from carlos_patient_portal.apns_provider import ApnsProviderJwtSigner
from carlos_patient_portal.config import Settings
from carlos_patient_portal.mycarlos_availability import NoticeKeys, PushPlatform
from carlos_patient_portal.mycarlos_availability_dispatch import AvailabilityDispatch
from carlos_patient_portal.mycarlos_push_handles import HandleKeys, SqlDestinationHandles
from carlos_patient_portal.notification_transports import (
    ApnsConfig,
    ApnsTokenTransport,
    HttpClient,
)

__all__ = ["APNS_AUTH_REJECTED", "HttpClient", "availability_dispatch_for"]

logger = logging.getLogger(__name__)

# The failure category operations see when Apple answers 403 (a key or provider-token fault that
# hits every destination at once).
APNS_AUTH_REJECTED = "apns_auth_rejected"


def availability_dispatch_for(
    settings: Settings,
    session_factory: Callable[[], Session] | sessionmaker[Session],
    http_client: HttpClient | None,
    *,
    clock: Callable[[], int] | None = None,
    record_failure: Callable[[str], None] | None = None,
) -> AvailabilityDispatch | None:
    """The worker's config, or None while iPhone push is off.

    Raises ``ApnsKeyError`` (a fixed code only) when push is on and something is missing: the HTTP/2
    packages (`apns_http2_unavailable`) or a key file that does not pass its checks. Without an
    injected `http_client` (tests inject a fake) the real HTTP/2 client is made.
    """
    if not settings.mycarlos_apns_enabled:
        return None
    if http_client is None:
        # The real client: HTTP/2 to Apple (`apns_http2.Http2Client`). Refuses with
        # `apns_http2_unavailable` when the HTTP/2 packages are not installed.
        http_client = Http2Client()
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

    def auth_rejected() -> None:
        # Class only: no token, key id, destination or Apple text. The cached provider token is
        # dropped so the next push signs a fresh one (a clock slip or a rotation cures itself).
        signer.invalidate()
        logger.error("APNs rejected the provider token (%s)", APNS_AUTH_REJECTED)
        if record_failure is not None:
            record_failure(APNS_AUTH_REJECTED)

    transport = ApnsTokenTransport(
        config,
        http_client,
        handles,
        signer,
        now,
        environments=handles,
        on_auth_rejected=auth_rejected,
    )
    return AvailabilityDispatch(
        {PushPlatform.IOS_APNS: transport},
        NoticeKeys(notice_key),
    )
