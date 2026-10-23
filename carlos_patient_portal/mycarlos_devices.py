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

"""Linked myCarlos devices and the clinic keys handed to them (carlos-portal#41, M2).

The portal stores public keys only and never seals, opens, signs or verifies a document. Format:
`docs/architecture/mycarlos-delivery.md`.

- **Clinic keys:** CARLOS publishes its whole key list. A published key never disappears from it:
  a key CARLOS stops using is listed as revoked, so a device learns of the revocation the next
  time it links. A revoked key never becomes active again.
- **Devices:** CARLOS reads a patient's devices (with their public keys, which it seals to), and
  staff can remove one. Removing is final; linking again makes a new device with new keys.
"""

from base64 import urlsafe_b64decode, urlsafe_b64encode
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.clinic_key_proofs import (
    ClinicKeyInventoryError,
    ClinicKeyMaterial,
    validate_clinic_key_inventory,
)

from carlos_patient_portal.models import (
    CLINIC_KEY_STATUS_ACTIVE,
    CLINIC_KEY_STATUS_REVOKED,
    MYCARLOS_DEVICE_STATUS_ACTIVE,
    MYCARLOS_DEVICE_STATUS_REMOVED,
    PatientPortalClinicKey,
    PatientPortalAccount,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosRecipient,
    utc_now,
)

MAX_PUBLISHED_CLINIC_KEYS = 16
CLINIC_KEY_STATUSES = frozenset({CLINIC_KEY_STATUS_ACTIVE, CLINIC_KEY_STATUS_REVOKED})


class ClinicKeyPublishError(ValueError):
    """A key list the portal refuses. `code` is safe to return to CARLOS."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ClinicKeySpec:
    """One key as CARLOS publishes it, already decoded."""

    kid: str
    spki: bytes
    status: str
    replaces_kid: str | None = None
    replacement_signature: bytes | None = None


@dataclass(frozen=True)
class ClinicKeyPublishResult:
    keys: list[PatientPortalClinicKey]
    changed: bool


def as_utc(value: datetime | None) -> datetime | None:
    """A stored time as an aware UTC time. SQLite hands back naive ones; PostgreSQL does not."""
    if value is None or value.tzinfo is not None:
        return value
    return value.replace(tzinfo=UTC)


def b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def strict_b64url_decode(value: str) -> bytes:
    """Decode unpadded base64url, refusing every form but the canonical one (the spec's rule)."""
    if not value.isascii() or "=" in value:
        raise ValueError("not canonical base64url")
    try:
        decoded = urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as exc:
        raise ValueError("not canonical base64url") from exc
    if b64url(decoded) != value:
        raise ValueError("not canonical base64url")
    return decoded


def clinic_key_id(spki: bytes) -> str:
    """`kid` = b64url(SHA-256(SubjectPublicKeyInfo DER)), as CARLOS and myCarlos compute it."""
    return b64url(sha256(spki).digest())


def check_clinic_spki(spki: bytes) -> None:
    """Accept only a P-256 public key in its one DER SubjectPublicKeyInfo encoding."""
    try:
        key = serialization.load_der_public_key(spki)
    except (ValueError, TypeError) as exc:
        raise ClinicKeyPublishError("invalid_key") from exc
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ClinicKeyPublishError("invalid_key")
    canonical = key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if canonical != spki:
        raise ClinicKeyPublishError("invalid_key")


def _check_key_list(specs: list[ClinicKeySpec]) -> None:
    if not 1 <= len(specs) <= MAX_PUBLISHED_CLINIC_KEYS:
        raise ClinicKeyPublishError("invalid_key_list")
    kids = [spec.kid for spec in specs]
    if len(set(kids)) != len(kids):
        raise ClinicKeyPublishError("invalid_key_list")
    for spec in specs:
        check_clinic_spki(spec.spki)
        if clinic_key_id(spec.spki) != spec.kid:
            raise ClinicKeyPublishError("invalid_key")
        if spec.status not in CLINIC_KEY_STATUSES:
            raise ClinicKeyPublishError("invalid_key")
        if (spec.replaces_kid is None) != (spec.replacement_signature is None):
            raise ClinicKeyPublishError("invalid_key")
        if spec.replaces_kid == spec.kid:
            raise ClinicKeyPublishError("invalid_key")


def publish_clinic_keys(
    session: Session,
    *,
    clinic_id: str,
    specs: list[ClinicKeySpec],
    now: datetime | None = None,
) -> ClinicKeyPublishResult:
    """Store CARLOS's whole key list for `clinic_id`. Publishing the same list again is a no-op.

    Refused, with nothing stored: a malformed key or list, a previously published key missing
    from the list (`key_missing`), a revoked key listed as active (`key_revoked`), or a stored
    key whose replacement details differ (`key_changed`). A `kid` is a hash of its key, so the
    key itself can never change under the same `kid`.
    """
    # A stable clinic mutex also exists before the first row. Row locks alone cannot protect
    # complete graph/count validation when concurrent first publishers insert different keys.
    if session.get_bind().dialect.name == "postgresql":
        digest = sha256(b"mycarlos-clinic-key-publish-v1\x00" + clinic_id.encode("utf-8")).digest()
        lock_key = int.from_bytes(digest[:8], "big", signed=True)
        session.execute(select(func.pg_advisory_xact_lock(lock_key))).scalar_one()
    _check_key_list(specs)
    current_time = utc_now() if now is None else now
    # Lock this clinic's rows so two concurrent publishes cannot both pass the checks below.
    stored = {
        key.kid: key
        for key in session.scalars(
            select(PatientPortalClinicKey)
            .where(PatientPortalClinicKey.clinic_id == clinic_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
    }
    listed = {spec.kid for spec in specs}
    try:
        validate_clinic_key_inventory(
            clinic_id,
            [ClinicKeyMaterial(spec.kid, spec.spki, spec.status, spec.replaces_kid,
                               spec.replacement_signature) for spec in specs],
            [ClinicKeyMaterial(key.kid, key.spki, key.status, key.replaces_kid,
                               key.replacement_signature) for key in stored.values()],
        )
    except ClinicKeyInventoryError as exc:
        raise ClinicKeyPublishError(exc.code) from exc
    if set(stored) - listed:
        raise ClinicKeyPublishError("key_missing")
    elsewhere = session.scalars(
        select(PatientPortalClinicKey.kid).where(
            PatientPortalClinicKey.kid.in_(listed - set(stored)),
            PatientPortalClinicKey.clinic_id != clinic_id,
        )
    ).first()
    if elsewhere is not None:
        # The same key published for another clinic: never adopt or move it.
        raise ClinicKeyPublishError("invalid_key")

    changed = False
    for spec in specs:
        key = stored.get(spec.kid)
        if key is None:
            key = insert_clinic_key(session, clinic_id=clinic_id, spec=spec, now=current_time)
            if key is None:
                changed = True
                continue
        if (key.replaces_kid, key.replacement_signature) != (
            spec.replaces_kid,
            spec.replacement_signature,
        ):
            raise ClinicKeyPublishError("key_changed")
        if key.status == CLINIC_KEY_STATUS_REVOKED and spec.status != CLINIC_KEY_STATUS_REVOKED:
            raise ClinicKeyPublishError("key_revoked")
        if key.status != spec.status:
            key.status = CLINIC_KEY_STATUS_REVOKED
            key.revoked_at = current_time
            changed = True
    session.flush()
    keys = list(
        session.scalars(
            select(PatientPortalClinicKey)
            .where(PatientPortalClinicKey.clinic_id == clinic_id)
            .order_by(PatientPortalClinicKey.published_at, PatientPortalClinicKey.kid)
        )
    )
    return ClinicKeyPublishResult(keys=keys, changed=changed)


def insert_clinic_key(
    session: Session,
    *,
    clinic_id: str,
    spec: ClinicKeySpec,
    now: datetime,
) -> PatientPortalClinicKey | None:
    """Store a new key. None when stored; the existing row when a concurrent publish won.

    Two first publishes can both find no row and both insert the same `kid`. The loser's insert
    fails on the primary key inside its own savepoint, and the key just stored is then checked
    like any already published key, instead of the publish failing with a 500.
    """
    try:
        with session.begin_nested():
            session.add(
                PatientPortalClinicKey(
                    kid=spec.kid,
                    clinic_id=clinic_id,
                    spki=spec.spki,
                    status=spec.status,
                    published_at=now,
                    revoked_at=now if spec.status == CLINIC_KEY_STATUS_REVOKED else None,
                    replaces_kid=spec.replaces_kid,
                    replacement_signature=spec.replacement_signature,
                )
            )
    except IntegrityError:
        existing = session.scalar(
            select(PatientPortalClinicKey)
            .where(PatientPortalClinicKey.kid == spec.kid)
            .with_for_update()
        )
        if existing is None or existing.clinic_id != clinic_id:
            raise ClinicKeyPublishError("invalid_key") from None
        return existing
    return None


def recipient_id_for_account(session: Session, account_id: int) -> str | None:
    """The account's recipient ID, or None before its first device links."""
    return session.scalar(
        select(PatientPortalMyCarlosRecipient.recipient_id).where(
            PatientPortalMyCarlosRecipient.account_id == account_id
        )
    )


def devices_for_account(session: Session, account_id: int) -> list[PatientPortalMyCarlosDevice]:
    """Every device the account ever linked, removed ones too, oldest first."""
    return list(
        session.scalars(
            select(PatientPortalMyCarlosDevice)
            .where(PatientPortalMyCarlosDevice.account_id == account_id)
            .order_by(PatientPortalMyCarlosDevice.linked_at, PatientPortalMyCarlosDevice.id)
        )
    )


def remove_device(
    session: Session,
    *,
    account_id: int,
    device_key_id: str,
    removed_by: str,
    now: datetime | None = None,
    mailbox_enabled: bool = False,
) -> tuple[PatientPortalMyCarlosDevice, bool] | None:
    """Remove one of the account's devices. Returns the device and whether this call removed it.

    None when the account has no such device, including one linked to another account, so a
    caller cannot tell whether a key ID exists elsewhere. Removing a removed device changes
    nothing. Deleting the device's waiting copies arrives with the mailbox (milestone M4).
    """
    account = session.scalar(select(PatientPortalAccount).where(
        PatientPortalAccount.id == account_id).with_for_update().execution_options(populate_existing=True))
    if account is None:
        return None
    device = session.scalar(
        select(PatientPortalMyCarlosDevice)
        .where(
            PatientPortalMyCarlosDevice.account_id == account_id,
            PatientPortalMyCarlosDevice.device_key_id == device_key_id,
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    if device is None:
        return None
    if device.status != MYCARLOS_DEVICE_STATUS_ACTIVE:
        return device, False
    if mailbox_enabled:
        from carlos_patient_portal.mailbox import mailbox_lock, remove_waiting
        m = mailbox_lock(session, account_id=account_id, device_key_id=device_key_id,
                         clinic_id=account.clinic_id)
        instant = utc_now() if now is None else now
        remove_waiting(session, m, now=int(instant.timestamp()))
    device.status = MYCARLOS_DEVICE_STATUS_REMOVED
    device.removed_at = utc_now() if now is None else now
    device.removed_by = removed_by
    session.flush()
    return device, True
