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

"""The availability store's refusals and race branches that the main store tests do not reach.

A non-boolean remote switch, a call outside a transaction, an expired intent, and the unique-index
races of `enroll` and `acknowledge_revocation` (another device takes the same destination id
between our look and our insert). Every id and value is FAKE.
"""

from datetime import UTC, datetime
from uuid import UUID, uuid4

import pytest
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from carlos_patient_portal import mycarlos_availability_store as store
from carlos_patient_portal.models import PatientPortalMyCarlosAvailabilitySubscription
from carlos_patient_portal.mycarlos_availability import (
    AvailabilityError,
    OutboxIntent,
    Owner,
    PushPlatform,
    ReadyHint,
)
from carlos_patient_portal.mycarlos_availability_store import (
    EnrollmentRefusal,
    RevocationRequest,
    SqlAvailabilityTransaction,
    acknowledge_revocation,
    as_subscription,
    enroll,
    revoke,
    subscriptions_for_owner,
)
from tests.test_mycarlos_availability_store import (  # noqa: F401
    NOW,
    add_owner,
    consent,
    migrated,
)


def lose_the_insert_race(session: Session) -> None:
    """Make the next flush of a new subscription row fail as the unique index would."""

    @event.listens_for(session, "before_flush")
    def _fail(sess, _context, _instances):  # noqa: ANN001, ANN202
        if any(isinstance(row, PatientPortalMyCarlosAvailabilitySubscription) for row in sess.new):
            event.remove(session, "before_flush", _fail)
            raise IntegrityError("INSERT", {}, Exception("unique"))


def other_devices_row(
    session: Session, destination: UUID, *, revoked: bool
) -> PatientPortalMyCarlosAvailabilitySubscription:
    """A subscription for `destination` filed under a second owner, as a racing device left it."""
    other = add_owner(session, "b")
    moment = datetime.fromtimestamp(NOW, tz=UTC)
    return PatientPortalMyCarlosAvailabilitySubscription(
        subscription_id=str(uuid4()),
        account_id=other.account_id,
        device_id=other.device_id,
        epoch=str(uuid4()),
        destination_id=str(destination),
        platform="android_fcm",
        remote_enabled=not revoked,
        remote_consent_version=1,
        permission_observed=not revoked,
        created_at=moment,
        revoked_at=moment if revoked else None,
        revoked_by="device" if revoked else None,
    )


def revoke_while_racing(
    session: Session,
    owner: Owner,
    destination: UUID,
    winner: PatientPortalMyCarlosAvailabilitySubscription | None,
) -> PatientPortalMyCarlosAvailabilitySubscription:
    """`acknowledge_revocation` where our tombstone insert fails and `winner` is there after.

    The first look (a plain select inside `acknowledge_revocation`) finds nothing, so a tombstone
    is inserted; `_destination_row` is only asked after that insert failed, and answers `winner`.
    The lookup is put back whatever happens.
    """
    real = store._destination_row

    def looked_up(_session, _destination_id):  # noqa: ANN001, ANN202
        return winner

    lose_the_insert_race(session)
    store._destination_row = looked_up
    try:
        return acknowledge_revocation(
            session, owner, RevocationRequest("android_fcm", str(destination))
        )
    finally:
        store._destination_row = real


# --- Refusals ----------------------------------------------------------------------------------


@pytest.mark.parametrize("value", ["yes", 1, None])
def test_a_remote_switch_that_is_not_a_boolean_is_an_invalid_enrollment(migrated, value) -> None:  # noqa: F811
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        with pytest.raises(EnrollmentRefusal, match="invalid_enrollment"):
            enroll(session, owner, consent(remote_enabled=value))
        assert subscriptions_for_owner(session, owner, include_revoked=True) == []


def test_revoking_outside_a_transaction_is_refused(migrated) -> None:  # noqa: F811
    engine, _config = migrated
    with Session(engine) as session, pytest.raises(AvailabilityError, match="transaction_required"):
        revoke(session, Owner(1, 1), str(uuid4()))


def test_putting_an_intent_outside_a_transaction_is_refused(migrated) -> None:  # noqa: F811
    engine, _config = migrated
    intent = OutboxIntent(
        Owner(1, 1), uuid4(), PushPlatform.ANDROID_FCM, ReadyHint(uuid4(), uuid4(), 1), NOW + 60
    )
    with Session(engine) as session:
        transaction = SqlAvailabilityTransaction(session, clock=lambda: NOW)
        assert transaction.in_transaction() is False
        with pytest.raises(AvailabilityError, match="transaction_required"):
            transaction.put(intent)


def test_an_intent_that_has_already_expired_is_not_stored(migrated) -> None:  # noqa: F811
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        enroll(session, owner, consent())
        (subscription,) = [as_subscription(r) for r in subscriptions_for_owner(session, owner)]

        def intent(expires_at: int) -> OutboxIntent:
            return OutboxIntent(
                owner,
                subscription.destination_id,
                subscription.platform,
                ReadyHint(subscription.subscription_id, subscription.epoch, 1),
                expires_at,
            )

        transaction = SqlAvailabilityTransaction(session, clock=lambda: NOW)
        # Expiring at this very second is expired; a second later is still live.
        assert transaction.put(intent(NOW)) is False
        assert transaction.put(intent(NOW - 5)) is False
        assert transaction.put(intent(NOW + 1)) is True


# --- The unique-index races ----------------------------------------------------------------------


def test_an_enrollment_whose_insert_fails_with_no_row_behind_it_is_re_raised(migrated) -> None:  # noqa: F811
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        lose_the_insert_race(session)
        # Nobody holds the id afterwards either, so this is not "taken": the error is not hidden.
        with pytest.raises(IntegrityError):
            enroll(session, owner, consent())


def test_a_revocation_whose_insert_fails_with_no_row_behind_it_is_re_raised(migrated) -> None:  # noqa: F811
    engine, _config = migrated
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        with pytest.raises(IntegrityError):
            revoke_while_racing(session, owner, uuid4(), None)


def test_a_revocation_that_loses_the_race_to_a_revoked_row_returns_that_row(migrated) -> None:  # noqa: F811
    engine, _config = migrated
    destination = uuid4()
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        winner = other_devices_row(session, destination, revoked=True)
        answer = revoke_while_racing(session, owner, destination, winner)
        assert answer is winner
        assert answer.revoked_at is not None


def test_a_revocation_that_loses_the_race_to_another_devices_live_row_is_refused(migrated) -> None:  # noqa: F811
    engine, _config = migrated
    destination = uuid4()
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        winner = other_devices_row(session, destination, revoked=False)
        with pytest.raises(EnrollmentRefusal, match="destination_taken"):
            revoke_while_racing(session, owner, destination, winner)


def test_the_race_helper_puts_the_destination_lookup_back(migrated) -> None:  # noqa: F811
    engine, _config = migrated
    real = store._destination_row
    with Session(engine) as session, session.begin():
        owner = add_owner(session, "a")
        with pytest.raises(IntegrityError):
            revoke_while_racing(session, owner, uuid4(), None)
    assert store._destination_row is real
