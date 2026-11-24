# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The APNs device token of a destination: bound by the device, encrypted at rest, deleted with it.

A linked myCarlos on an iPhone asks Apple for a device token and sends it to the portal with
`POST /api/mycarlos/availability/handles`, signed by the link's device key like the other
availability routes (carlos-portal, iPhone push piece 6). This module is the store behind that
route and behind the push transport's lookup:

* `bind` checks the destination is this device's live destination, then stores the token
  encrypted in a table of its own; a new token replaces the old one.
* `forget_push_handles` (in the store) removes tokens; every path that revokes a destination calls
  it, and so does the worker when APNs says 410.
* `SqlDestinationHandles` is the `DestinationHandles` the APNs transport asks (token by destination
  id) and the source of the environment (sandbox or production) the token was made for.

The token never appears in a response, a log line or an exception; the table holds AES-GCM
ciphertext under a key derived from the portal's keyring (the outbox keyring, with its own
derivation label, so the two uses never share a key), with the destination, platform and
environment as associated data: a row copied under another destination or environment does not
decrypt.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from secrets import token_bytes
from uuid import UUID

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal.models import (
    PatientPortalMyCarlosAvailabilitySubscription,
    PatientPortalMyCarlosPushHandle,
)
from carlos_patient_portal.mycarlos_availability import AvailabilityError, Owner, PushPlatform
from carlos_patient_portal.mycarlos_availability_store import EnrollmentRefusal, _uuid_text

# The platforms a handle may be bound for through this route. macOS push comes with the Mac backend.
HANDLE_PLATFORMS = frozenset({PushPlatform.IOS_APNS.value})
ENVIRONMENTS = frozenset({"sandbox", "production"})
_APNS_TOKEN = re.compile(r"[0-9a-fA-F]{64,200}")
_KEY_DERIVATION_INFO = b"carlos-patient-portal mycarlos push handle v1"
_AD_PREFIX = b"carlos-patient-portal:push-handle:v1:"
NONCE_BYTES = 12


class HandleRefusal(EnrollmentRefusal):
    """A fixed, content-free refusal code (never the token)."""


@dataclass(frozen=True, repr=False)
class HandleRequest:
    """What the device sends: its destination, the platform, the environment and the token."""

    destination_id: str
    platform: str
    environment: str
    token: str

    def __repr__(self) -> str:
        return "HandleRequest[REDACTED]"


def parse_handle(request: HandleRequest) -> tuple[str, str, str, str]:
    """The checked fields: destination (canonical UUID text), platform, environment and the token
    (lower-cased hex, 64 to 200 characters)."""
    destination_id = _uuid_text(request.destination_id, "invalid_handle")
    if type(request.platform) is not str or request.platform not in HANDLE_PLATFORMS:
        raise HandleRefusal("invalid_platform")
    if type(request.environment) is not str or request.environment not in ENVIRONMENTS:
        raise HandleRefusal("invalid_environment")
    if type(request.token) is not str or not _APNS_TOKEN.fullmatch(request.token):
        raise HandleRefusal("invalid_handle")
    return destination_id, request.platform, request.environment, request.token.lower()


def _key(secret: str) -> bytes:
    normalized = secret.strip()
    if not normalized:
        raise ValueError("push handle encryption secret must not be blank")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_KEY_DERIVATION_INFO).derive(
        normalized.encode("utf-8")
    )


def _associated_data(destination_id: str, platform: str, environment: str) -> bytes:
    return _AD_PREFIX + f"{destination_id}:{platform}:{environment}".encode("ascii")


@dataclass(frozen=True, repr=False)
class HandleKeys:
    """The keyring the tokens are encrypted under: every key that may decrypt, and the active."""

    keyring: Mapping[str, str]
    active_key_id: str

    def __post_init__(self) -> None:
        if not self.keyring or self.active_key_id not in self.keyring:
            raise AvailabilityError("push_handles_unavailable")

    def __repr__(self) -> str:
        return "HandleKeys[REDACTED]"


def _encrypt(
    keys: HandleKeys, destination_id: str, platform: str, environment: str, token: str
) -> tuple[bytes, bytes]:
    nonce = token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(_key(keys.keyring[keys.active_key_id])).encrypt(
        nonce,
        token.encode("ascii"),
        _associated_data(destination_id, platform, environment),
    )
    return nonce, ciphertext


def _decrypt(keys: HandleKeys, row: PatientPortalMyCarlosPushHandle) -> str | None:
    secret = keys.keyring.get(row.key_id)
    if secret is None:
        return None
    try:
        token = (
            AESGCM(_key(secret))
            .decrypt(
                row.nonce,
                row.ciphertext,
                _associated_data(row.destination_id, row.platform, row.environment),
            )
            .decode("ascii")
        )
    except (InvalidTag, ValueError, UnicodeError):
        return None
    return token if _APNS_TOKEN.fullmatch(token) else None


def bind(
    session: Session,
    owner: Owner,
    request: HandleRequest,
    keys: HandleKeys,
    *,
    now: datetime | None = None,
) -> bool:
    """Stores the token for this device's live destination; True when it is new, False when it
    replaced an earlier one.

    A destination the device does not hold (unknown, another device's, revoked, enrolled for
    another platform, or not opted in to remote notices) is `not_found`: the answer does not say
    which. The caller holds the device row's lock, as enrollment and revocation do, so a
    revocation cannot interleave.
    """
    if not session.in_transaction():
        raise AvailabilityError("transaction_required")
    destination_id, platform, environment, token = parse_handle(request)
    subscription = session.scalars(
        select(PatientPortalMyCarlosAvailabilitySubscription)
        .where(PatientPortalMyCarlosAvailabilitySubscription.destination_id == destination_id)
        .with_for_update()
    ).first()
    if (
        subscription is None
        or subscription.revoked_at is not None
        or not subscription.remote_enabled
        or (subscription.account_id, subscription.device_id) != (owner.account_id, owner.device_id)
        or subscription.platform != platform
    ):
        raise HandleRefusal("not_found")
    nonce, ciphertext = _encrypt(keys, destination_id, platform, environment, token)
    instant = now or datetime.now(UTC)
    row = session.scalars(
        select(PatientPortalMyCarlosPushHandle)
        .where(PatientPortalMyCarlosPushHandle.destination_id == destination_id)
        .with_for_update()
    ).first()
    if row is None:
        session.add(
            PatientPortalMyCarlosPushHandle(
                destination_id=destination_id,
                account_id=owner.account_id,
                device_id=owner.device_id,
                platform=platform,
                environment=environment,
                key_id=keys.active_key_id,
                nonce=nonce,
                ciphertext=ciphertext,
                created_at=instant,
                updated_at=instant,
            )
        )
        session.flush()
        return True
    row.platform = platform
    row.environment = environment
    row.key_id = keys.active_key_id
    row.nonce = nonce
    row.ciphertext = ciphertext
    row.updated_at = instant
    session.flush()
    return False


class SqlDestinationHandles:
    """The APNs transport's lookup: the token of a destination, and the environment it was made
    for. Each call opens its own short session; a row that cannot be decrypted (a key no longer in
    the keyring, a changed row) answers None, which the transport turns into "destination gone"."""

    def __init__(
        self, session_factory: Callable[[], Session] | sessionmaker[Session], keys: HandleKeys
    ) -> None:
        self._session_factory = session_factory
        self._keys = keys

    def _row(self, destination_id: UUID) -> PatientPortalMyCarlosPushHandle | None:
        with self._session_factory() as session:
            row = session.scalars(
                select(PatientPortalMyCarlosPushHandle).where(
                    PatientPortalMyCarlosPushHandle.destination_id == str(destination_id)
                )
            ).first()
            if row is not None:
                session.expunge(row)
            return row

    def handle_for(self, destination_id: UUID) -> str | None:
        row = self._row(destination_id)
        return None if row is None else _decrypt(self._keys, row)

    def environment_for(self, destination_id: UUID) -> str | None:
        row = self._row(destination_id)
        return None if row is None else row.environment
