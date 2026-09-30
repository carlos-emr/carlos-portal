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

"""Immutable view state for the portal's browser templates.

These follow the CARLOS `*ViewModel` contract in `docs/architecture/layer-names.md`: one view
model per rendered page, immutable, with no behaviour beyond accessors. Templates read attributes
directly, so a field rename is a type error in the assembler rather than a silently empty cell in
the rendered page — the failure mode an untyped ``dict[str, object]`` context cannot catch.

Assembling these belongs to `presenters.py`; nothing here touches a database session or a request.
"""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class EmailPasswordRowViewModel:
    """One rendered row of the email-password table."""

    id: int
    subject: str
    provider: str
    sent_at: str
    source_reference: str | None
    is_available: bool


@dataclass(frozen=True, slots=True)
class ProviderFilterOptionViewModel:
    """One entry of the dashboard's provider filter."""

    value: str
    label: str


@dataclass(frozen=True, slots=True)
class EmailPasswordDashboardViewModel:
    """View state for the email-password module of `dashboard.jinja`.

    ``provider_option_values`` is kept alongside ``provider_options`` so the template can decide
    whether a currently-selected provider fell outside the capped option list and therefore needs
    rendering as an extra selected entry.
    """

    rows: tuple[EmailPasswordRowViewModel, ...] = ()
    search: str = ""
    provider: str = ""
    provider_options: tuple[ProviderFilterOptionViewModel, ...] = ()
    provider_option_values: tuple[str, ...] = ()
    provider_options_truncated: bool = False
    date_from: str = ""
    date_to: str = ""
    has_filters: bool = False
    filter_error: str | None = None
    page: int = 1
    total_pages: int = 1
    empty_message: str = ""
    previous_href: str | None = None
    next_href: str | None = None


@dataclass(frozen=True, slots=True)
class BookingSlotViewModel:
    """One offered time as a radio option; `id` is the portal's row id, never CARLOS's slot id."""

    id: int
    when: str
    details: str


# What the booking part of an opened prompt shows.
BOOKING_VIEW_CONTACT = "contact"  # No times were offered: contact the clinic, as before.
BOOKING_VIEW_CLOSED = "closed"  # Times were offered but none can be picked now: contact the clinic.
BOOKING_VIEW_CHOOSE = "choose"  # Pick one of the offered times, or say none of them work.
BOOKING_VIEW_PENDING = "pending"  # Waiting for CARLOS to confirm the picked time.
BOOKING_VIEW_BOOKED = "booked"  # CARLOS booked the picked time.


@dataclass(frozen=True, slots=True)
class BookingOfferViewModel:
    """The booking part of an opened prompt.

    ``notice`` is the one status sentence for the state (confirming, booked, taken); ``chosen``
    describes the picked or booked time.
    """

    state: str
    notice: str | None = None
    chosen: str | None = None
    slots: tuple[BookingSlotViewModel, ...] = ()
    choice_href: str = ""
    decline_href: str = ""


@dataclass(frozen=True, slots=True)
class BookingPromptViewModel:
    """One booking prompt as the patient reads it: fixed wording, no clinical detail.

    ``booking`` is built only for the opened prompt, not for each row of the list.
    """

    id: int
    href: str
    title: str
    urgency: str
    suggested_by: str
    contact: str
    sent_at: str
    is_new: bool
    booking: BookingOfferViewModel | None = None


@dataclass(frozen=True, slots=True)
class MessagesViewModel:
    """View state for the messages module of `dashboard.jinja`.

    ``selected`` is the prompt being read, or None on the list. ``not_found`` reports a link to a
    prompt that was withdrawn, expired, or is not the patient's. ``error`` reports a pick or
    decline that could not be saved.
    """

    prompts: tuple[BookingPromptViewModel, ...] = ()
    selected: BookingPromptViewModel | None = None
    not_found: bool = False
    no_online_booking: str = ""
    error: str | None = None
