# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""The refusals of `invites.py` that no other test drives: input limits, an account that already
exists, a prepared invite whose stored token is gone or unreadable, a resend of an invite that is
no longer pending, an activation that no longer applies, and how a rejected insert is explained.
FAKE staff, FAKE patients, FAKE secrets; an in-memory database."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import timedelta

import pytest
from sqlalchemy.orm import Session, sessionmaker

from carlos_patient_portal import invites
from carlos_patient_portal.invites import (
    MAX_CLINIC_ID_LENGTH,
    AccountAlreadyExistsError,
    InviteNotFoundError,
    InvitePreparationConflictError,
    InvitePreparationInProgressError,
    InvitePreparationKeyUnavailableError,
    PendingInviteExistsError,
    SupersededInviteError,
    activate_prepared_invite,
    create_invite,
    prepare_create_invite,
    prepare_resend_invite,
    resend_invite,
)
from carlos_patient_portal.models import (
    INVITE_STATUS_PREPARED,
    PatientPortalAccount,
    PatientPortalInvite,
    utc_now,
)
from tests.support import (
    IDENTITY_PROOF_SECRET,
    create_service_invite,
    migrated_development_app,
    seeded_identity_proof,
)

STAFF = "FAKE Staff"
SECRET = "e" * 32
KEYS = {"test-key": SECRET}


@pytest.fixture
def factory() -> Iterator[sessionmaker[Session]]:
    app = migrated_development_app()
    yield app.state.session_factory
    app.state.database_engine.dispose()


def prepare(session: Session, demographic_no: int = 1234, operation: str = "op-1"):  # noqa: ANN201
    return prepare_create_invite(
        session,
        demographic_no,
        STAFF,
        delivery_operation_id=operation,
        identity_proof=seeded_identity_proof(),
        proof_secret=IDENTITY_PROOF_SECRET,
        encryption_secret=SECRET,
        encryption_key_id="test-key",
        encryption_keys=KEYS,
    )


def expire(invite: PatientPortalInvite) -> None:
    """Long past its lifetime (the table requires an expiry later than the creation)."""
    invite.created_at = utc_now() - timedelta(days=30)
    invite.expires_at = utc_now() - timedelta(seconds=1)


def add_account(session: Session, demographic_no: int = 1234) -> None:
    session.add(
        PatientPortalAccount(
            clinic_id="default",
            demographic_no=demographic_no,
            username=f"fake{demographic_no}",
            email=f"fake{demographic_no}@example.test",
            password_hash="FAKE-unused",
            status="active",
        )
    )
    session.flush()


# --- input limits ------------------------------------------------------------------------------


def test_a_blank_or_oversized_clinic_id_is_refused() -> None:
    assert invites.normalize_clinic_id("  clinic-a  ") == "clinic-a"
    with pytest.raises(ValueError, match="must not be blank"):
        invites.normalize_clinic_id("   ")
    with pytest.raises(ValueError, match="characters or fewer"):
        invites.normalize_clinic_id("c" * (MAX_CLINIC_ID_LENGTH + 1))
    assert invites.normalize_clinic_id("c" * MAX_CLINIC_ID_LENGTH) == "c" * MAX_CLINIC_ID_LENGTH


def test_a_blank_preparation_secret_is_refused() -> None:
    with pytest.raises(ValueError, match="must not be blank"):
        invites._invite_preparation_key("   ")


@pytest.mark.parametrize("function", ["create", "prepare"])
def test_a_blank_proof_secret_is_refused(factory, function: str) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        with pytest.raises(ValueError, match="proof_secret must not be blank"):
            if function == "create":
                create_invite(
                    session,
                    1234,
                    STAFF,
                    identity_proof=seeded_identity_proof(),
                    proof_secret="   ",
                )
            else:
                prepare_create_invite(
                    session,
                    1234,
                    STAFF,
                    delivery_operation_id="op-blank",
                    identity_proof=seeded_identity_proof(),
                    proof_secret="   ",
                    encryption_secret=SECRET,
                    encryption_key_id="test-key",
                    encryption_keys=KEYS,
                )


# --- a patient who already has an account ------------------------------------------------------


@pytest.mark.parametrize("function", ["create", "prepare"])
def test_a_patient_with_an_account_gets_no_first_invite(factory, function: str) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        add_account(session)
        with pytest.raises(AccountAlreadyExistsError):
            if function == "create":
                create_service_invite(session)
            else:
                prepare(session)
        assert session.query(PatientPortalInvite).count() == 0


# --- a prepared token that cannot be shown again -----------------------------------------------


def test_a_prepared_token_is_shown_only_while_it_is_stored_readable(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        invite, token = prepare(session)
        assert invites._disclose_prepared_token(invite, encryption_keys=KEYS) == token
        # The key it was sealed under is no longer configured.
        with pytest.raises(InvitePreparationKeyUnavailableError):
            invites._disclose_prepared_token(invite, encryption_keys={"other-key": SECRET})
        # A different secret under the same key id cannot open it.
        with pytest.raises(InvitePreparationKeyUnavailableError):
            invites._disclose_prepared_token(invite, encryption_keys={"test-key": "f" * 32})
        # A changed ciphertext is not opened.
        sealed = invite.encrypted_invite_token
        invite.encrypted_invite_token = bytes([sealed[0] ^ 1]) + sealed[1:]
        with pytest.raises(InvitePreparationKeyUnavailableError):
            invites._disclose_prepared_token(invite, encryption_keys=KEYS)
        # Nothing stored at all: the preparation cannot be repeated, it is a conflict.
        invite.encrypted_invite_token = None
        with pytest.raises(InvitePreparationConflictError):
            invites._disclose_prepared_token(invite, encryption_keys=KEYS)
        invite.encrypted_invite_token = sealed
        # An expired preparation is not shown either.
        expire(invite)
        with pytest.raises(InvitePreparationConflictError):
            invites._disclose_prepared_token(invite, encryption_keys=KEYS)


# --- preparing a resend ------------------------------------------------------------------------


def resend_prepare(session: Session, invite_id: int, operation: str = "op-resend"):  # noqa: ANN201
    return prepare_resend_invite(
        session,
        invite_id,
        STAFF,
        delivery_operation_id=operation,
        encryption_secret=SECRET,
        encryption_key_id="test-key",
        encryption_keys=KEYS,
    )


def test_a_resend_of_an_invite_that_does_not_exist_is_not_found(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        with pytest.raises(InviteNotFoundError):
            resend_prepare(session, 987654)


def test_a_resend_of_another_clinics_invite_is_not_found(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        invite, _ = create_service_invite(session, clinic_id="clinic-b")
        with pytest.raises(InviteNotFoundError):
            resend_prepare(session, invite.id)


# --- activating a preparation ------------------------------------------------------------------


def activate(session: Session, invite: PatientPortalInvite, **changes: str):  # noqa: ANN201
    values = {
        "delivery_operation_id": invite.delivery_operation_id,
        "delivery_reference": "FAKE-reference",
        "clinic_id": invite.clinic_id,
        "actor": STAFF,
        **changes,
    }
    return activate_prepared_invite(session, invite.id, **values)


def test_a_preparation_that_is_no_longer_prepared_cannot_be_activated(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        invite, _ = prepare(session)
        invite.status = "superseded"
        invite.encrypted_invite_token = None
        invite.invite_token_nonce = None
        invite.invite_token_key_id = None
        session.flush()
        with pytest.raises(InvitePreparationConflictError):
            activate(session, invite)


def test_an_expired_preparation_cannot_be_activated(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        invite, _ = prepare(session)
        assert invite.status == INVITE_STATUS_PREPARED
        expire(invite)
        session.flush()
        with pytest.raises(InvitePreparationConflictError):
            activate(session, invite)


def test_a_resend_preparation_is_not_activated_when_its_original_is_no_longer_pending(
    factory,  # noqa: ANN001
) -> None:
    with factory() as session, session.begin():
        original, _ = create_service_invite(session)
        prepared, _ = resend_prepare(session, original.id)
        original.status = "superseded"
        session.flush()
        with pytest.raises(InvitePreparationConflictError):
            activate(session, prepared)


# --- a resend of an invite that was already replaced -------------------------------------------


def test_an_invite_that_was_replaced_cannot_be_resent(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        original, _ = create_service_invite(session)
        replacement, _ = resend_invite(session, original.id, STAFF)
        assert replacement.id != original.id
        with pytest.raises(SupersededInviteError):
            resend_invite(session, original.id, STAFF)


# --- explaining a rejected insert --------------------------------------------------------------


def test_a_rejected_insert_is_explained_by_what_holds_the_slot(factory) -> None:  # noqa: ANN001
    with factory() as session, session.begin():
        # Nothing else holds the slot: only a conflict of the operation itself.
        assert isinstance(
            invites._preparation_insert_conflict(
                session,
                clinic_id="default",
                demographic_no=1234,
                delivery_operation_id="op-x",
                first_preparation=False,
            ),
            InvitePreparationConflictError,
        )
        pending, _ = create_service_invite(session)
        explained = invites._preparation_insert_conflict(
            session,
            clinic_id="default",
            demographic_no=pending.demographic_no,
            delivery_operation_id="op-x",
            first_preparation=True,
        )
        assert isinstance(explained, PendingInviteExistsError)
        # A resend always has a pending original, so only a first preparation looks for one.
        resend = invites._preparation_insert_conflict(
            session,
            clinic_id="default",
            demographic_no=pending.demographic_no,
            delivery_operation_id="op-x",
            first_preparation=False,
        )
        assert type(resend) is InvitePreparationConflictError


def test_a_create_that_loses_the_slot_after_the_checks_says_what_holds_it(
    factory,  # noqa: ANN001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with factory() as session, session.begin():
        create_service_invite(session)
        # Another request took the slot between the checks and the insert: the checks see nothing.
        monkeypatch.setattr(invites, "revoke_pending_invites_for_patient", lambda *a, **k: None)
        with pytest.raises(PendingInviteExistsError):
            create_service_invite(session)

    with factory() as session, session.begin():
        prepare(session, demographic_no=777, operation="op-slot")
        monkeypatch.setattr(invites, "_release_preparation_slot", lambda *a, **k: None)
        with pytest.raises(InvitePreparationInProgressError):
            create_service_invite(session, demographic_no=777)


def test_an_account_that_appears_while_a_create_is_checked_is_still_refused(
    factory,  # noqa: ANN001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The account check is repeated after the old invites are retired: an account made in
    between (its first look saw none) still ends the create, and nothing is added."""
    looks = []

    def account_appears_after_the_first_look(*_args: object, **_kwargs: object) -> bool:
        looks.append(1)
        return len(looks) > 1

    monkeypatch.setattr(invites, "patient_has_account", account_appears_after_the_first_look)
    with factory() as session, session.begin():
        with pytest.raises(AccountAlreadyExistsError):
            create_service_invite(session)
        assert len(looks) == 2
        assert session.query(PatientPortalInvite).count() == 0


def test_a_rejected_insert_beside_another_operations_preparation_is_in_progress(
    factory,  # noqa: ANN001
) -> None:
    with factory() as session, session.begin():
        prepared, _ = prepare(session, operation="op-first")
        explained = invites._preparation_insert_conflict(
            session,
            clinic_id="default",
            demographic_no=prepared.demographic_no,
            delivery_operation_id="op-second",
            first_preparation=True,
        )
        assert isinstance(explained, InvitePreparationInProgressError)
        # The same operation repeating itself is not "someone else's".
        same = invites._preparation_insert_conflict(
            session,
            clinic_id="default",
            demographic_no=prepared.demographic_no,
            delivery_operation_id="op-first",
            first_preparation=False,
        )
        assert type(same) is InvitePreparationConflictError
