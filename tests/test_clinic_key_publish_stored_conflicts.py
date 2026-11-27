# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""A clinic key list that disagrees with what the portal already stores is refused whole.

Test-only; FAKE keys derived from labels, an in-memory migrated database, no network. The earlier
refusal tests (`test_round3_clinic_key_refusals.py`) cover a list that is malformed on its own;
these start from a stored list and publish a second one. Each case asserts the exact refusal code
and that the stored keys are exactly what they were.
"""

from sqlalchemy import select

from carlos_patient_portal.models import PatientPortalClinicKey
from carlos_patient_portal.mycarlos_devices import publish_clinic_keys
from tests.test_mycarlos_availability_store import migrated  # noqa: F401 -- `factory` needs it
from tests.test_round3_clinic_key_refusals import (  # noqa: F401 -- shared helpers and fixture
    CLINIC,
    NOW,
    factory,
    refused,
    spec,
)


def publish(factory, specs):  # noqa: F811
    with factory() as session, session.begin():
        publish_clinic_keys(session, clinic_id=CLINIC, specs=specs, now=NOW)


def stored(factory):  # noqa: F811
    with factory() as session:
        return [
            (key.kid, key.status, key.revoked_at)
            for key in session.scalars(select(PatientPortalClinicKey).order_by("kid"))
        ]


def test_a_list_that_drops_a_published_key_is_refused_as_key_missing(factory):  # noqa: F811
    first, second = spec("stored-a"), spec("stored-b")
    publish(factory, [first, second])
    before = stored(factory)

    assert refused(factory, [first]) == "key_missing"

    assert stored(factory) == before


def test_a_revoked_key_listed_as_active_again_is_refused_as_key_revoked(factory):  # noqa: F811
    first, second = spec("revoked-a"), spec("revoked-b")
    publish(factory, [first, second])
    publish(factory, [first, spec("revoked-b", "revoked")])
    before = stored(factory)

    assert refused(factory, [first, second]) == "key_revoked"

    assert stored(factory) == before


def test_a_stored_key_cannot_gain_a_replacement_later_it_is_key_changed(factory):  # noqa: F811
    first, second = spec("changed-a"), spec("changed-b")
    publish(factory, [first, second])
    before = stored(factory)
    named = spec("changed-b", replaces_kid=first.kid, replacement_signature=b"\x01" * 64)

    code = refused(factory, [first, named])

    assert code == "key_changed", code
    assert stored(factory) == before
