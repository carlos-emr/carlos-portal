# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Refusal paths of the newest iPhone push code that no test reached (coverage round 3).

What is pinned, with FAKE keys, tokens and ids only:

- the Apple key reader: an open that fails for a reason other than a missing file or a link, a
  read that fails, and a file that grows past the size cap between the check and the read are each
  refused with their own fixed code, and the descriptor is closed every time;
- the handle store: a blank encryption secret is never used (reading answers "no token", writing
  refuses) and a bind outside a transaction is refused before anything is read;
- the dispatcher: a stored subscription the policy core refuses permits nothing, and an outbox row
  whose subscription does not exist cannot even be queued (the foreign key refuses it).
"""

from __future__ import annotations

import errno
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from carlos_patient_portal import apns_provider as ap
from carlos_patient_portal import mycarlos_availability_dispatch as dispatch_module
from carlos_patient_portal.models import (
    PatientPortalMyCarlosAvailabilityOutbox as Outbox,
)
from carlos_patient_portal.models import (
    PatientPortalMyCarlosPushHandle,
)
from carlos_patient_portal.mycarlos_availability import AvailabilityError, PushPlatform
from carlos_patient_portal.mycarlos_push_handles import (
    HandleKeys,
    HandleRequest,
    _decrypt,
    _encrypt,
    bind,
)
from tests.test_apns_provider import code_of, write_key
from tests.test_mycarlos_availability_dispatch import (
    NOW,
    Clock,
    db,  # noqa: F401
    enrolled,
    fcm,
    new_copy,
    outbox,
    worker,
)
from tests.test_mycarlos_availability_store import migrated  # noqa: F401
from tests.test_mycarlos_push_handles import KEYS, TOKEN_A

# --- the Apple key reader --------------------------------------------------------------------


class Spy:
    """Wraps `os.open`, `os.read` and `os.close` for the descriptors the key reader opens."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self.opened: list[int] = []
        self.closed: list[int] = []
        self.read_error: OSError | None = None
        self.read_chunks: list[bytes] | None = None
        self.open_error: OSError | None = None
        real_open, real_read, real_close = os.open, os.read, os.close

        def spy_open(path, flags, *args, **kwargs):  # noqa: ANN001, ANN002, ANN003, ANN202
            if self.open_error is not None:
                raise self.open_error
            descriptor = real_open(path, flags, *args, **kwargs)
            self.opened.append(descriptor)
            return descriptor

        def spy_read(descriptor, length):  # noqa: ANN001, ANN202
            if descriptor in self.opened:
                if self.read_error is not None:
                    raise self.read_error
                if self.read_chunks is not None:
                    return self.read_chunks.pop(0) if self.read_chunks else b""
            return real_read(descriptor, length)

        def spy_close(descriptor):  # noqa: ANN001, ANN202
            if descriptor in self.opened:
                self.closed.append(descriptor)
            return real_close(descriptor)

        monkeypatch.setattr(ap.os, "open", spy_open)
        monkeypatch.setattr(ap.os, "read", spy_read)
        monkeypatch.setattr(ap.os, "close", spy_close)


@pytest.mark.parametrize("reason", [errno.EACCES, errno.EIO, errno.ENOTDIR, errno.EMFILE])
def test_an_open_that_fails_for_any_other_reason_is_unreadable_not_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reason: int
) -> None:
    key = write_key(tmp_path / "AuthKey.p8")
    spy = Spy(monkeypatch)
    spy.open_error = OSError(reason, os.strerror(reason), str(key))
    assert code_of(key) == "apns_key_unreadable"
    # Nothing was opened, so there is no descriptor to leak, and the path is not in the error.
    assert spy.opened == []


def test_a_read_that_fails_is_unreadable_and_the_descriptor_is_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = write_key(tmp_path / "AuthKey.p8")
    spy = Spy(monkeypatch)
    spy.read_error = OSError(errno.EIO, "FAKE input/output error")
    assert code_of(key) == "apns_key_unreadable"
    assert len(spy.opened) == 1 and spy.closed == spy.opened


def test_a_file_that_grew_past_the_cap_after_the_size_check_is_refused_by_its_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The size on the descriptor was fine; what the read returns is one byte over the cap (a file
    # that grew between the check and the read, or a short size on a special file).
    key = write_key(tmp_path / "AuthKey.p8")
    spy = Spy(monkeypatch)
    spy.read_chunks = [b"x" * ap.MAX_KEY_FILE_BYTES, b"x"]
    assert code_of(key) == "apns_key_size"
    assert len(spy.opened) == 1 and spy.closed == spy.opened


def test_a_file_of_exactly_the_cap_read_in_pieces_is_not_refused_for_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Exactly the cap is allowed by the size check: the refusal that follows is the key's own.
    key = write_key(tmp_path / "AuthKey.p8")
    spy = Spy(monkeypatch)
    spy.read_chunks = [b"x" * 1000, b"x" * (ap.MAX_KEY_FILE_BYTES - 1000)]
    assert code_of(key) == "apns_key_invalid"
    assert spy.closed == spy.opened


# --- the handle store ------------------------------------------------------------------------

BLANK = HandleKeys({"blank": "   \t "}, "blank")


def test_a_blank_secret_never_encrypts_a_token() -> None:
    with pytest.raises(ValueError, match="must not be blank"):
        _encrypt(BLANK, str(uuid4()), "ios_apns", "sandbox", TOKEN_A)
    # Nor does a secret that is only whitespace pass as long: the check is on what remains.
    for secret in ("", " ", "\n\t "):
        with pytest.raises(ValueError, match="must not be blank"):
            _encrypt(HandleKeys({"k": secret}, "k"), str(uuid4()), "ios_apns", "sandbox", TOKEN_A)


def test_a_token_whose_key_is_now_blank_reads_as_no_token(db) -> None:  # noqa: F811
    owner, _sid, destination = enrolled(db, "blank-secret", platform="ios_apns")
    with db() as session, session.begin():
        bind(session, owner, HandleRequest(str(destination), "ios_apns", "sandbox", TOKEN_A), KEYS)
    with db() as session:
        row = session.scalars(select(PatientPortalMyCarlosPushHandle)).one()
        assert _decrypt(KEYS, row) == TOKEN_A
        # The keyring still names the key the token was written under, but its secret was blanked.
        assert _decrypt(HandleKeys({row.key_id: "  "}, row.key_id), row) is None


def test_binding_outside_a_transaction_is_refused_before_anything_is_read(
    db: sessionmaker,  # noqa: F811
) -> None:
    owner, _sid, destination = enrolled(db, "no-transaction", platform="ios_apns")
    with db() as session:
        assert not session.in_transaction()
        with pytest.raises(AvailabilityError) as raised:
            bind(
                session,
                owner,
                HandleRequest(str(destination), "ios_apns", "sandbox", TOKEN_A),
                KEYS,
            )
        assert str(raised.value) == "transaction_required"
        # Refused first: nothing was queried, so the session never began a transaction.
        assert not session.in_transaction()


# --- the dispatcher ----------------------------------------------------------------------------


def test_a_stored_subscription_the_policy_core_refuses_permits_no_send(
    db,  # noqa: F811
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner, _sid, destination = enrolled(db, "refused-row")
    new_copy(db, owner, 1)
    transport = fcm(destination, 200)
    run = worker(db, Clock(), {PushPlatform.ANDROID_FCM: transport})
    claim = run.claim()
    assert claim is not None and not isinstance(claim, str)

    def refuses(*_args: object, **_kwargs: object) -> object:
        raise AvailabilityError("invalid_subscription")

    # The row read at dispatch time is one the policy core refuses (a stored value it cannot read).
    monkeypatch.setattr(dispatch_module, "current_availability", refuses)
    decision = run.complete(claim)
    assert decision != "provider_accepted"
    assert transport.requests == []
    [row] = outbox(db)
    assert row.status == "done" and row.last_decision == decision
    assert row.lease_token is None and row.lease_until is None


def test_the_database_refuses_an_outbox_row_for_a_subscription_that_does_not_exist(
    db,  # noqa: F811
) -> None:
    # The claim's own "no such subscription" branch is defensive: the foreign key refuses such a
    # row at the insert, so it can never be queued to be claimed.
    with pytest.raises(IntegrityError), db() as session, session.begin():
        session.add(
            Outbox(
                subscription_id=str(uuid4()),
                epoch=str(uuid4()),
                sequence=1,
                expires_at=NOW + 600,
                status="pending",
                attempts=0,
                created_at=NOW,
            )
        )
    assert outbox(db) == []
