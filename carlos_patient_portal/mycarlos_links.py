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

"""Linking a myCarlos device with a one-time code (carlos-portal#41, M2).

The rules are the spec's ("Linking a device" in `docs/architecture/mycarlos-delivery.md`):

- **A code:** a public 8-character `link_id` and a secret 10-character code, bound to one account
  and the signed-in session that made it, for 10 minutes and one use. Only an HMAC of the code is
  stored, under its own key derived from the session secret (`token_keys.py`).
- **Per link:** 5 wrong codes end it. **Per account:** at most 3 pending links (a fourth replaces
  the oldest), and 10 wrong codes within 24 hours, counted only on pending links, stop linking
  until 24 hours after the last one.
- **Checking a code:** only against the one link its `link_id` names, and only while that link is
  pending and the account is under its limit. Every failure is the same `link_code_invalid`. A
  wrong code for a link that has ended counts nothing: its `link_id` was on screen once, and
  counting it would let whoever saw it keep the patient from linking.

Locks are always taken account first, then its link rows, so creating a code and checking one
never wait on each other in opposite orders.
"""

import hmac
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from hashlib import sha256

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal.auth import is_past, lock_is_staff_initiated
from carlos_patient_portal.device_identity import LinkRequest, b64url
from carlos_patient_portal.models import (
    ACCOUNT_STATUS_ACTIVE,
    CLINIC_KEY_STATUS_ACTIVE,
    MYCARLOS_DEVICE_STATUS_ACTIVE,
    MYCARLOS_LINK_CODE_LENGTH,
    MYCARLOS_LINK_ID_LENGTH,
    MYCARLOS_LINK_STATUS_PENDING,
    MYCARLOS_LINK_STATUS_REPLACED,
    MYCARLOS_LINK_STATUS_USED,
    MYCARLOS_MAX_WRONG_CODES_PER_LINK,
    PatientPortalAccount,
    PatientPortalClinicKey,
    PatientPortalMyCarlosDevice,
    PatientPortalMyCarlosLinkCode,
    PatientPortalMyCarlosLinkFailure,
    PatientPortalMyCarlosRecipient,
    PatientPortalSession,
    utc_now,
)

LINK_CODE_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
LINK_CODE_LIFETIME = timedelta(minutes=10)
MAX_PENDING_LINKS_PER_ACCOUNT = 3
MAX_ACCOUNT_WRONG_CODES = 10
ACCOUNT_WRONG_CODE_WINDOW = timedelta(hours=24)
# A new link_id clashing with any stored one is retried; 40 random bits make even one retry rare.
MAX_LINK_ID_ATTEMPTS = 5
RECIPIENT_ID_BYTES = 16
MAX_RECIPIENT_ID_ATTEMPTS = 5

LINK_RESULT_LINKED = "linked"
LINK_RESULT_CODE_INVALID = "link_code_invalid"
LINK_RESULT_DEVICE_EXISTS = "device_exists"
LINK_RESULT_CLINIC_KEYS_MISSING = "clinic_keys_missing"


class LinkingPausedError(Exception):
    """The account reached its wrong-code limit; no code can be made or used for now."""


@dataclass(frozen=True)
class IssuedLinkCode:
    """A new code, shown once. Only `link_id` and an HMAC of `code` are stored."""

    link_id: str
    code: str
    expires_at: datetime

    @property
    def display(self) -> str:
        return display_link_code(self.link_id, self.code)


@dataclass(frozen=True)
class LinkResult:
    """What checking a link request decided. Only `linked` carries the new device."""

    code: str
    account_id: int | None = None
    device: PatientPortalMyCarlosDevice | None = None
    recipient_id: str | None = None


def random_link_text(length: int) -> str:
    return "".join(secrets.choice(LINK_CODE_ALPHABET) for _ in range(length))


def display_link_code(link_id: str, code: str) -> str:
    """`<link_id>-<first 5 of code>-<last 5 of code>`, as the patient sees it."""
    return f"{link_id}-{code[:5]}-{code[5:]}"


def hash_link_code(key: str, link_id: str, code: str) -> str:
    """HMAC-SHA256 over the framed `link_id` and code, so a hash belongs to its own link only."""
    message = b"".join(
        len(part).to_bytes(8, "big") + part for part in (link_id.encode(), code.encode())
    )
    return hmac.new(key.encode("utf-8"), message, sha256).hexdigest()


def session_is_live(
    portal_session: PatientPortalSession | None,
    account: PatientPortalAccount,
    *,
    now: datetime,
    idle_timeout: timedelta,
) -> bool:
    """The same tests as signing in with a session token, without its side effects."""
    if (
        portal_session is None
        or portal_session.account_id != account.id
        or portal_session.revoked_at is not None
        or is_past(portal_session.expires_at, now)
    ):
        return False
    last_seen_at = portal_session.last_seen_at or portal_session.created_at
    if is_past(last_seen_at + idle_timeout, now):
        return False
    return (
        account.status == ACCOUNT_STATUS_ACTIVE
        and not (account.locked_at is not None and lock_is_staff_initiated(account))
        and not account.force_password_reset
    )


def account_linking_paused(session: Session, account_id: int, *, now: datetime) -> bool:
    """10 wrong codes within 24 hours stop linking until 24 hours after the last of them.

    While paused, no wrong code is counted, so the last one stays the one that reached 10; the
    pause therefore ends exactly 24 hours after it, as the spec says, and not earlier when the
    oldest of the 10 leaves a rolling window. Wrong-code rows must be kept for 48 hours.
    """
    latest = session.scalar(
        select(func.max(PatientPortalMyCarlosLinkFailure.failed_at)).where(
            PatientPortalMyCarlosLinkFailure.account_id == account_id,
            PatientPortalMyCarlosLinkFailure.failed_at > now - ACCOUNT_WRONG_CODE_WINDOW,
        )
    )
    if latest is None:
        return False
    in_window = session.scalar(
        select(func.count())
        .select_from(PatientPortalMyCarlosLinkFailure)
        .where(
            PatientPortalMyCarlosLinkFailure.account_id == account_id,
            PatientPortalMyCarlosLinkFailure.failed_at > latest - ACCOUNT_WRONG_CODE_WINDOW,
            PatientPortalMyCarlosLinkFailure.failed_at <= latest,
        )
    )
    return (in_window or 0) >= MAX_ACCOUNT_WRONG_CODES


def link_is_pending(
    link: PatientPortalMyCarlosLinkCode,
    portal_session: PatientPortalSession | None,
    account: PatientPortalAccount,
    *,
    now: datetime,
    idle_timeout: timedelta,
) -> bool:
    return (
        link.status == MYCARLOS_LINK_STATUS_PENDING
        and not is_past(link.expires_at, now)
        and link.wrong_codes < MYCARLOS_MAX_WRONG_CODES_PER_LINK
        and session_is_live(portal_session, account, now=now, idle_timeout=idle_timeout)
    )


def _lock_account(session: Session, account_id: int) -> PatientPortalAccount | None:
    return session.scalar(
        select(PatientPortalAccount).where(PatientPortalAccount.id == account_id).with_for_update()
    )


def create_link_code(
    session: Session,
    *,
    account_id: int,
    session_id: int,
    key: str,
    idle_timeout: timedelta,
    now: datetime | None = None,
) -> IssuedLinkCode:
    """Make a pending link for this account and signed-in session, replacing the oldest of 3.

    Raises LinkingPausedError while the account is over its wrong-code limit.
    """
    current_time = utc_now() if now is None else now
    account = _lock_account(session, account_id)
    if account is None:
        raise ValueError("unknown account")
    if account_linking_paused(session, account_id, now=current_time):
        raise LinkingPausedError()
    candidates = session.scalars(
        select(PatientPortalMyCarlosLinkCode)
        .where(
            PatientPortalMyCarlosLinkCode.account_id == account_id,
            PatientPortalMyCarlosLinkCode.status == MYCARLOS_LINK_STATUS_PENDING,
        )
        .order_by(PatientPortalMyCarlosLinkCode.created_at, PatientPortalMyCarlosLinkCode.id)
        .with_for_update()
    ).all()
    pending = [
        link
        for link in candidates
        if link_is_pending(
            link,
            session.get(PatientPortalSession, link.session_id),
            account,
            now=current_time,
            idle_timeout=idle_timeout,
        )
    ]
    while len(pending) >= MAX_PENDING_LINKS_PER_ACCOUNT:
        pending.pop(0).status = MYCARLOS_LINK_STATUS_REPLACED
    session.flush()

    code = random_link_text(MYCARLOS_LINK_CODE_LENGTH)
    expires_at = current_time + LINK_CODE_LIFETIME
    for _attempt in range(MAX_LINK_ID_ATTEMPTS):
        link_id = random_link_text(MYCARLOS_LINK_ID_LENGTH)
        try:
            with session.begin_nested():
                session.add(
                    PatientPortalMyCarlosLinkCode(
                        account_id=account_id,
                        session_id=session_id,
                        link_id=link_id,
                        code_hash=hash_link_code(key, link_id, code),
                        status=MYCARLOS_LINK_STATUS_PENDING,
                        wrong_codes=0,
                        created_at=current_time,
                        expires_at=expires_at,
                    )
                )
        except IntegrityError:
            continue
        return IssuedLinkCode(link_id=link_id, code=code, expires_at=expires_at)
    raise RuntimeError("could not find a free link_id")


def recipient_id_for(session: Session, account_id: int) -> str:
    """The account's recipient ID, made on its first link: 128 random bits, never from the HCN."""
    existing = session.scalar(
        select(PatientPortalMyCarlosRecipient.recipient_id).where(
            PatientPortalMyCarlosRecipient.account_id == account_id
        )
    )
    if existing is not None:
        return existing
    for _attempt in range(MAX_RECIPIENT_ID_ATTEMPTS):
        recipient_id = b64url(secrets.token_bytes(RECIPIENT_ID_BYTES))
        try:
            with session.begin_nested():
                session.add(
                    PatientPortalMyCarlosRecipient(
                        account_id=account_id,
                        recipient_id=recipient_id,
                        created_at=utc_now(),
                    )
                )
        except IntegrityError:
            continue
        return recipient_id
    raise RuntimeError("could not make a recipient ID")


def link_device(
    session: Session,
    request: LinkRequest,
    *,
    key: str,
    idle_timeout: timedelta,
    now: datetime | None = None,
) -> LinkResult:
    """Spec checks 6 (the code) and 7 (the device key), then the link itself.

    Check 5, an active clinic key, is the caller's: it is clinic-wide and comes first.

    A wrong code is counted here and is part of this transaction, so the caller must commit it
    even though the answer is a refusal; this function never raises for a refused link.
    """
    current_time = utc_now() if now is None else now
    found = session.scalar(
        select(PatientPortalMyCarlosLinkCode.account_id).where(
            PatientPortalMyCarlosLinkCode.link_id == request.link_id
        )
    )
    if found is None:
        return LinkResult(LINK_RESULT_CODE_INVALID)
    account = _lock_account(session, found)
    link = session.scalar(
        select(PatientPortalMyCarlosLinkCode)
        .where(PatientPortalMyCarlosLinkCode.link_id == request.link_id)
        .with_for_update()
    )
    if account is None or link is None or link.account_id != account.id:
        return LinkResult(LINK_RESULT_CODE_INVALID)
    portal_session = session.get(PatientPortalSession, link.session_id)
    if not link_is_pending(
        link, portal_session, account, now=current_time, idle_timeout=idle_timeout
    ) or account_linking_paused(session, account.id, now=current_time):
        return LinkResult(LINK_RESULT_CODE_INVALID, account_id=account.id)
    if not hmac.compare_digest(hash_link_code(key, link.link_id, request.code), link.code_hash):
        link.wrong_codes += 1
        session.add(
            PatientPortalMyCarlosLinkFailure(
                account_id=account.id,
                link_id=link.link_id,
                failed_at=current_time,
            )
        )
        session.flush()
        return LinkResult(LINK_RESULT_CODE_INVALID, account_id=account.id)
    already_linked = session.scalar(
        select(PatientPortalMyCarlosDevice.id).where(
            PatientPortalMyCarlosDevice.device_key_id == request.device_key_id
        )
    )
    if already_linked is not None:
        return LinkResult(LINK_RESULT_DEVICE_EXISTS, account_id=account.id)

    recipient_id = recipient_id_for(session, account.id)
    device = PatientPortalMyCarlosDevice(
        account_id=account.id,
        device_key_id=request.device_key_id,
        x25519_public_key=request.x25519_public_key,
        ed25519_public_key=request.ed25519_public_key,
        device_name=request.device_name,
        status=MYCARLOS_DEVICE_STATUS_ACTIVE,
        linked_at=current_time,
    )
    try:
        with session.begin_nested():
            session.add(device)
    except IntegrityError:
        # The same key linked by a concurrent request a moment ago.
        return LinkResult(LINK_RESULT_DEVICE_EXISTS, account_id=account.id)
    link.status = MYCARLOS_LINK_STATUS_USED
    link.used_at = current_time
    link.device_id = device.id
    session.flush()
    return LinkResult(
        LINK_RESULT_LINKED,
        account_id=account.id,
        device=device,
        recipient_id=recipient_id,
    )


def clinic_has_active_key(session: Session, clinic_id: str) -> bool:
    """Whether CARLOS has published at least one active signing key for the clinic.

    A device pins the key list it receives when it links, and nothing refreshes a pinned list,
    so a device linked before any key exists could never verify a document.
    """
    return (
        session.scalar(
            select(PatientPortalClinicKey.kid)
            .where(
                PatientPortalClinicKey.clinic_id == clinic_id,
                PatientPortalClinicKey.status == CLINIC_KEY_STATUS_ACTIVE,
            )
            .limit(1)
        )
        is not None
    )


def clinic_key_list(session: Session, clinic_id: str) -> list[dict[str, str]]:
    """The keys handed to a device when it links: `kid`, SubjectPublicKeyInfo and status."""
    keys = session.scalars(
        select(PatientPortalClinicKey)
        .where(PatientPortalClinicKey.clinic_id == clinic_id)
        .order_by(PatientPortalClinicKey.published_at, PatientPortalClinicKey.kid)
    )
    return [{"kid": key.kid, "spki": b64url(key.spki), "status": key.status} for key in keys]
