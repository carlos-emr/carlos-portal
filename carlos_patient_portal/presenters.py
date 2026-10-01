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

"""Read-only assemblers that build one view model for one rendered page.

These follow the CARLOS `*ViewModelAssembler` contract in `docs/architecture/layer-names.md`:
each function builds the view state for exactly one view and performs read-only orchestration.
Assemblers must not write: no audit events, no session mutation, no commits. A write that belongs
to a page render belongs in the route that owns the request, not here.
"""

from collections.abc import Mapping
from datetime import UTC, date, datetime, timedelta
from datetime import time as datetime_time
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from sqlalchemy.orm import Session

from carlos_patient_portal.booking_choices import latest_choice
from carlos_patient_portal.booking_offers import as_utc, current_offered_slots
from carlos_patient_portal.booking_prompts import list_active_prompts_for_account
from carlos_patient_portal.config import DEFAULT_BOOKING_CHOICE_WAIT_MINUTES
from carlos_patient_portal.i18n import (
    DEFAULT_LOCALE,
    format_booking_time,
    format_portal_datetime,
    portal_text,
)
from carlos_patient_portal.models import (
    BOOKING_CHOICE_STATE_BOOKED,
    BOOKING_CHOICE_STATE_PENDING,
    BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE,
    BOOKING_PROMPT_STATUS_BOOKED,
    BOOKING_PROMPT_STATUS_CHOICE_PENDING,
    BOOKING_PROMPT_STATUS_READ,
    BOOKING_PROMPT_STATUS_SENT,
    UNLOCK_SECRET_STATUS_ACTIVE,
    UNLOCK_SECRET_TYPE_EMAIL,
    PatientPortalAccount,
    PatientPortalBookingChoice,
    PatientPortalBookingOfferedSlot,
    PatientPortalBookingPrompt,
    PatientPortalUnlockSecret,
    utc_now,
)
from carlos_patient_portal.unlock_secrets import (
    DEFAULT_UNLOCK_SECRET_LIST_LIMIT,
    MAX_UNLOCK_SECRET_SEARCH_LENGTH,
    count_unlock_secrets,
    list_unlock_secret_provider_options,
    list_unlock_secrets,
)
from carlos_patient_portal.view_models import (
    BOOKING_VIEW_BOOKED,
    BOOKING_VIEW_CHOOSE,
    BOOKING_VIEW_CLOSED,
    BOOKING_VIEW_CONTACT,
    BOOKING_VIEW_PENDING,
    BookingOfferViewModel,
    BookingPromptViewModel,
    BookingSlotViewModel,
    EmailPasswordDashboardViewModel,
    EmailPasswordRowViewModel,
    MessagesViewModel,
    ProviderFilterOptionViewModel,
)

EMAIL_PASSWORD_DASHBOARD_PAGE_SIZE = DEFAULT_UNLOCK_SECRET_LIST_LIMIT
PORTAL_EMAIL_PASSWORD_PATH = "/portal/email-passwords"


def normalize_email_password_dashboard_search(search: str | None) -> str | None:
    if search is None:
        return None
    normalized_search = search.strip()
    if not normalized_search:
        return None
    return normalized_search[:MAX_UNLOCK_SECRET_SEARCH_LENGTH]


def normalize_email_password_dashboard_provider(provider: str | None) -> str | None:
    if provider is None:
        return None
    normalized_provider = provider.strip()
    if normalized_provider in {"id:", "name:"}:
        raise ValueError("structured provider filter must include a value")
    return normalized_provider or None


def dashboard_created_before(
    date_to: date | None,
    *,
    timezone_name: str = "UTC",
) -> datetime | None:
    """Return the exclusive upper bound for a local-date filter, expressed in UTC.

    Storage and FHIR instants stay in UTC while the patient filters by clinic-local dates, so the
    boundary is built in the clinic timezone and converted, not taken as a UTC midnight.
    """
    if date_to is None:
        return None
    if date_to == date.max:
        return datetime.max.replace(tzinfo=UTC)
    local_boundary = datetime.combine(
        date_to + timedelta(days=1),
        datetime_time.min,
        tzinfo=ZoneInfo(timezone_name),
    )
    return local_boundary.astimezone(UTC)


def _dashboard_created_from(
    date_from: date | None,
    *,
    timezone_name: str,
) -> datetime | None:
    if date_from is None:
        return None
    if date_from == date.min:
        return datetime.min.replace(tzinfo=UTC)
    return datetime.combine(
        date_from,
        datetime_time.min,
        tzinfo=ZoneInfo(timezone_name),
    ).astimezone(UTC)


def portal_email_password_page_href(
    *,
    search: str | None,
    provider: str | None,
    date_from: date | None,
    date_to: date | None,
    page: int,
    base_path: str = PORTAL_EMAIL_PASSWORD_PATH,
) -> str:
    query_params: dict[str, str] = {}
    normalized_search = normalize_email_password_dashboard_search(search)
    if normalized_search is not None:
        query_params["q"] = normalized_search
    normalized_provider = normalize_email_password_dashboard_provider(provider)
    if normalized_provider is not None:
        query_params["provider"] = normalized_provider
    if date_from is not None:
        query_params["date_from"] = date_from.isoformat()
    if date_to is not None:
        query_params["date_to"] = date_to.isoformat()
    if page > 1:
        query_params["page"] = str(page)
    query_string = urlencode(query_params)
    if not query_string:
        return base_path
    return f"{base_path}?{query_string}"


def assemble_email_password_row(
    unlock_secret: PatientPortalUnlockSecret,
    *,
    text: dict[str, str],
    timezone_name: str = "UTC",
    locale: str = DEFAULT_LOCALE,
) -> EmailPasswordRowViewModel:
    return EmailPasswordRowViewModel(
        id=unlock_secret.id,
        subject=unlock_secret.label or text["email_password"],
        provider=unlock_secret.created_by,
        sent_at=format_portal_datetime(
            unlock_secret.created_at,
            timezone_name=timezone_name,
            locale=locale,
        ),
        source_reference=unlock_secret.source_reference,
        is_available=unlock_secret.status == UNLOCK_SECRET_STATUS_ACTIVE,
    )


def assemble_email_password_dashboard(
    session: Session,
    account: PatientPortalAccount,
    *,
    search: str | None,
    provider: str | None,
    date_from: date | None,
    date_to: date | None,
    page: int,
    timezone_name: str = "UTC",
    filter_error: str | None = None,
    base_path: str = PORTAL_EMAIL_PASSWORD_PATH,
    locale: str = DEFAULT_LOCALE,
) -> EmailPasswordDashboardViewModel:
    """Build the email-password view state for `dashboard.jinja`."""
    text = portal_text(locale)
    normalized_search = normalize_email_password_dashboard_search(search)
    normalized_provider = normalize_email_password_dashboard_provider(provider)
    invalid_date_range = date_from is not None and date_to is not None and date_from > date_to
    has_filter_error = filter_error is not None or invalid_date_range
    has_filters = any((normalized_search, normalized_provider, date_from, date_to))
    created_from = _dashboard_created_from(date_from, timezone_name=timezone_name)
    created_before = dashboard_created_before(date_to, timezone_name=timezone_name)
    # A rejected filter must not run a query whose bounds were never valid.
    total_records = (
        0
        if has_filter_error
        else count_unlock_secrets(
            session,
            clinic_id=account.clinic_id,
            account_id=account.id,
            demographic_no=account.demographic_no,
            secret_type=UNLOCK_SECRET_TYPE_EMAIL,
            search=normalized_search,
            provider=normalized_provider,
            created_from=created_from,
            created_before=created_before,
        )
    )
    total_pages = max(
        1,
        (total_records + EMAIL_PASSWORD_DASHBOARD_PAGE_SIZE - 1)
        // EMAIL_PASSWORD_DASHBOARD_PAGE_SIZE,
    )
    normalized_page = min(max(page, 1), total_pages)
    offset = (normalized_page - 1) * EMAIL_PASSWORD_DASHBOARD_PAGE_SIZE
    records = (
        []
        if has_filter_error
        else list_unlock_secrets(
            session,
            clinic_id=account.clinic_id,
            account_id=account.id,
            demographic_no=account.demographic_no,
            secret_type=UNLOCK_SECRET_TYPE_EMAIL,
            search=normalized_search,
            provider=normalized_provider,
            created_from=created_from,
            created_before=created_before,
            limit=EMAIL_PASSWORD_DASHBOARD_PAGE_SIZE,
            offset=offset,
        )
    )
    provider_options = list_unlock_secret_provider_options(
        session,
        clinic_id=account.clinic_id,
        account_id=account.id,
        demographic_no=account.demographic_no,
        secret_type=UNLOCK_SECRET_TYPE_EMAIL,
    )
    return EmailPasswordDashboardViewModel(
        rows=tuple(
            assemble_email_password_row(
                record,
                text=text,
                timezone_name=timezone_name,
                locale=locale,
            )
            for record in records
        ),
        search=normalized_search or "",
        provider=normalized_provider or "",
        provider_options=tuple(
            ProviderFilterOptionViewModel(value=value, label=label)
            for value, label in provider_options.options
        ),
        provider_option_values=tuple(value for value, _ in provider_options.options),
        provider_options_truncated=provider_options.truncated,
        date_from=date_from.isoformat() if date_from is not None else "",
        date_to=date_to.isoformat() if date_to is not None else "",
        has_filters=has_filters,
        filter_error=filter_error or (text["date_range_error"] if invalid_date_range else None),
        page=normalized_page,
        total_pages=total_pages,
        empty_message=(
            text["no_matching_email_passwords"] if has_filters else text["no_email_passwords"]
        ),
        previous_href=(
            portal_email_password_page_href(
                search=normalized_search,
                provider=normalized_provider,
                date_from=date_from,
                date_to=date_to,
                page=normalized_page - 1,
                base_path=base_path,
            )
            if normalized_page > 1
            else None
        ),
        next_href=(
            portal_email_password_page_href(
                search=normalized_search,
                provider=normalized_provider,
                date_from=date_from,
                date_to=date_to,
                page=normalized_page + 1,
                base_path=base_path,
            )
            if normalized_page < total_pages
            else None
        ),
    )


def _booking_slot_text(
    slot: PatientPortalBookingOfferedSlot | PatientPortalBookingChoice,
    *,
    text: dict[str, str],
    booking_locations: Mapping[str, str],
    timezone_name: str,
    locale: str,
) -> tuple[str, str]:
    """When a time is, and its duration, visit mode, and location, in the patient's language."""
    if slot.starts_at is None or slot.duration_minutes is None or slot.visit_mode is None:
        raise ValueError("the time is no longer stored")
    date_text, time_text = format_booking_time(slot.starts_at, locale, timezone_name)
    details = [
        text["booking_slot_duration"].format(minutes=slot.duration_minutes),
        text[f"booking_visit_mode_{slot.visit_mode}"],
    ]
    # A code removed from the configuration since the time was offered is simply not shown.
    location = booking_locations.get(slot.location_code or "")
    if location:
        details.append(location)
    return (
        text["booking_slot_when"].format(date=date_text, time=time_text),
        text["booking_slot_detail_separator"].join(details),
    )


def assemble_booking_offer(
    session: Session,
    prompt: PatientPortalBookingPrompt,
    *,
    text: dict[str, str],
    href: str,
    now: datetime,
    wait_minutes: int,
    booking_locations: Mapping[str, str],
    timezone_name: str,
    locale: str,
) -> BookingOfferViewModel:
    """The booking part of one opened prompt: the times to pick, the wait, or the booked time."""

    def slot_text(
        slot: PatientPortalBookingOfferedSlot | PatientPortalBookingChoice,
    ) -> tuple[str, str]:
        return _booking_slot_text(
            slot,
            text=text,
            booking_locations=booking_locations,
            timezone_name=timezone_name,
            locale=locale,
        )

    choice = latest_choice(session, prompt.id)
    if (
        prompt.status == BOOKING_PROMPT_STATUS_BOOKED
        and choice is not None
        and choice.state == BOOKING_CHOICE_STATE_BOOKED
        and choice.starts_at is not None
    ):
        date_text, time_text = format_booking_time(choice.starts_at, locale, timezone_name)
        return BookingOfferViewModel(
            state=BOOKING_VIEW_BOOKED,
            notice=text["booking_booked"].format(date=date_text, time=time_text),
            chosen=slot_text(choice)[1],
        )
    if (
        prompt.status == BOOKING_PROMPT_STATUS_CHOICE_PENDING
        and choice is not None
        and choice.state == BOOKING_CHOICE_STATE_PENDING
        and choice.starts_at is not None
    ):
        # Past the configured wait, the patient is told plainly rather than left on "confirming".
        remaining = as_utc(choice.chosen_at) + timedelta(minutes=wait_minutes) - now
        overdue = remaining <= timedelta(0)
        when, details = slot_text(choice)
        return BookingOfferViewModel(
            state=BOOKING_VIEW_PENDING,
            notice=text[
                "booking_choice_pending_overdue" if overdue else "booking_choice_pending"
            ],
            chosen=text["booking_slot_detail_separator"].join((when, details)),
            wait_remaining_ms=None if overdue else max(1, int(remaining.total_seconds() * 1000)),
            overdue_notice=text["booking_choice_pending_overdue"],
        )
    open_for_choice = prompt.status in (BOOKING_PROMPT_STATUS_SENT, BOOKING_PROMPT_STATUS_READ)
    taken_notice = (
        text["booking_slot_taken"]
        if open_for_choice
        and choice is not None
        and choice.state == BOOKING_CHOICE_STATE_SLOT_UNAVAILABLE
        else None
    )
    slots = current_offered_slots(session, prompt.id, now=now) if open_for_choice else []
    if slots:
        slot_views = []
        for slot in slots:
            when, details = slot_text(slot)
            slot_views.append(BookingSlotViewModel(id=slot.id, when=when, details=details))
        return BookingOfferViewModel(
            state=BOOKING_VIEW_CHOOSE,
            notice=taken_notice,
            slots=tuple(slot_views),
            choice_href=f"{href}/choice",
            decline_href=f"{href}/decline",
        )
    # Declined, or every offered time taken or past: contact the clinic, as for a prompt that never
    # offered times, but without saying the portal cannot book.
    return BookingOfferViewModel(
        state=BOOKING_VIEW_CONTACT if prompt.offer_digest is None else BOOKING_VIEW_CLOSED,
        notice=text["booking_slot_taken_contact"] if taken_notice else None,
    )


def _booking_prompt_view(
    prompt: PatientPortalBookingPrompt,
    *,
    text: dict[str, str],
    href: str,
    clinic_name: str,
    booking_phone: str | None,
    timezone_name: str,
    locale: str,
    booking: BookingOfferViewModel | None = None,
) -> BookingPromptViewModel:
    # Every sentence comes from the catalog; the provider name is the only variable text, and it
    # is escaped by the template like any other value.
    return BookingPromptViewModel(
        id=prompt.id,
        href=href,
        title=text[f"booking_prompt_title_{prompt.appointment_type}"],
        urgency=text[f"booking_prompt_urgency_{prompt.urgency}"],
        suggested_by=(
            text["booking_prompt_suggested_by"].format(provider=prompt.suggested_by)
            if prompt.suggested_by
            else text["booking_prompt_suggested_by_clinic"]
        ),
        contact=(
            text["booking_prompt_contact_phone"].format(
                clinic_name=clinic_name,
                phone=booking_phone,
            )
            if booking_phone
            else text["booking_prompt_contact"].format(clinic_name=clinic_name)
        ),
        sent_at=format_portal_datetime(prompt.created_at, locale, timezone_name),
        is_new=prompt.status == BOOKING_PROMPT_STATUS_SENT,
        booking=booking,
    )


def assemble_messages(
    session: Session,
    account: PatientPortalAccount,
    *,
    base_path: str,
    clinic_name: str,
    booking_phone: str | None,
    selected_prompt: PatientPortalBookingPrompt | None = None,
    not_found: bool = False,
    timezone_name: str = "UTC",
    locale: str = DEFAULT_LOCALE,
    booking_locations: Mapping[str, str] | None = None,
    wait_minutes: int = DEFAULT_BOOKING_CHOICE_WAIT_MINUTES,
    error: str | None = None,
) -> MessagesViewModel:
    """Build the messages view state for `dashboard.jinja`. Read-only: opening is the route's."""
    text = portal_text(locale)

    def href(prompt: PatientPortalBookingPrompt) -> str:
        return f"{base_path.rstrip('/')}/{prompt.id}"

    def view(
        prompt: PatientPortalBookingPrompt,
        booking: BookingOfferViewModel | None = None,
    ) -> BookingPromptViewModel:
        return _booking_prompt_view(
            prompt,
            text=text,
            href=href(prompt),
            clinic_name=clinic_name,
            booking_phone=booking_phone,
            timezone_name=timezone_name,
            locale=locale,
            booking=booking,
        )

    prompts = tuple(view(prompt) for prompt in list_active_prompts_for_account(session, account.id))
    # Built from the prompt the route opened, not looked up in the capped list above.
    selected = (
        view(
            selected_prompt,
            assemble_booking_offer(
                session,
                selected_prompt,
                text=text,
                href=href(selected_prompt),
                now=utc_now(),
                wait_minutes=wait_minutes,
                booking_locations=booking_locations or {},
                timezone_name=timezone_name,
                locale=locale,
            ),
        )
        if selected_prompt is not None
        else None
    )
    return MessagesViewModel(
        prompts=prompts,
        selected=selected,
        not_found=not_found,
        no_online_booking=text["booking_prompt_no_online_booking"],
        error=error,
    )
