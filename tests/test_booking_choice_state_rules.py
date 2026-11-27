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

"""Which booking prompts a patient may still pick from or decline, by status and expiry.

`_require_open_for_patient` reads only the prompt's status and expiry, and `_mark_read` only its
read time, so a plain stand-in for the prompt is enough: no database. Every value is FAKE.
"""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from carlos_patient_portal.booking_choices import (
    BookingChoiceUnavailableError,
    _mark_read,
    _require_open_for_patient,
)
from carlos_patient_portal.booking_prompts import BookingPromptNotFoundError
from carlos_patient_portal.models import (
    BOOKING_PROMPT_STATUS_BOOKED,
    BOOKING_PROMPT_STATUS_CHOICE_PENDING,
    BOOKING_PROMPT_STATUS_DECLINED_ALL,
    BOOKING_PROMPT_STATUS_READ,
    BOOKING_PROMPT_STATUS_SENT,
    BOOKING_PROMPT_STATUS_WITHDRAWN,
)

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)
LIVE = NOW + timedelta(days=1)
ENDED = NOW - timedelta(seconds=1)


def prompt(status: str, expires_at: datetime) -> SimpleNamespace:
    return SimpleNamespace(status=status, expires_at=expires_at, read_at=None)


def test_no_prompt_reads_as_not_found() -> None:
    with pytest.raises(BookingPromptNotFoundError):
        _require_open_for_patient(None, now=NOW)


@pytest.mark.parametrize("status", [BOOKING_PROMPT_STATUS_SENT, BOOKING_PROMPT_STATUS_READ])
def test_a_sent_or_read_prompt_is_open_until_it_expires(status: str) -> None:
    live = prompt(status, LIVE)
    assert _require_open_for_patient(live, now=NOW) is live
    with pytest.raises(BookingPromptNotFoundError):
        _require_open_for_patient(prompt(status, ENDED), now=NOW)
    # Expiring at this very second is expired.
    with pytest.raises(BookingPromptNotFoundError):
        _require_open_for_patient(prompt(status, NOW), now=NOW)


def test_a_declined_prompt_that_has_expired_reads_as_not_found_not_as_a_conflict() -> None:
    with pytest.raises(BookingPromptNotFoundError):
        _require_open_for_patient(prompt(BOOKING_PROMPT_STATUS_DECLINED_ALL, ENDED), now=NOW)


@pytest.mark.parametrize(
    "status",
    [
        BOOKING_PROMPT_STATUS_DECLINED_ALL,
        BOOKING_PROMPT_STATUS_CHOICE_PENDING,
        BOOKING_PROMPT_STATUS_BOOKED,
    ],
)
def test_a_live_prompt_the_patient_already_answered_is_a_conflict(status: str) -> None:
    with pytest.raises(BookingChoiceUnavailableError):
        _require_open_for_patient(prompt(status, LIVE), now=NOW)


@pytest.mark.parametrize("status", [BOOKING_PROMPT_STATUS_WITHDRAWN, "anything-else", ""])
def test_a_withdrawn_or_unknown_status_reads_as_not_found(status: str) -> None:
    with pytest.raises(BookingPromptNotFoundError):
        _require_open_for_patient(prompt(status, LIVE), now=NOW)


def test_opening_a_prompt_marks_it_read_once_and_keeps_the_first_time() -> None:
    unread = prompt(BOOKING_PROMPT_STATUS_SENT, LIVE)
    _mark_read(unread, NOW)
    assert unread.read_at == NOW
    # A later look does not move the time the patient first read it.
    _mark_read(unread, NOW + timedelta(hours=1))
    assert unread.read_at == NOW
