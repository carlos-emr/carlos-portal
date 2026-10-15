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

"""Self sign-up: the public page where a patient asks for a portal account (carlos-portal#15).

Every request that passes the form checks gets the same page, status and headers, and takes at
least `PATIENT_PORTAL_SELF_SIGNUP_RESPONSE_FLOOR_MS`, whether it was stored or refused by a rate
limit. The handler never looks a patient up and never waits on CARLOS, so nothing it returns can
say whether the details match a chart. Browser form only: there is no JSON variant.
"""

import asyncio
from time import monotonic
from typing import Annotated

from fastapi import FastAPI, Request, status
from pydantic import ValidationError
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from carlos_patient_portal.i18n import portal_text
from carlos_patient_portal.runtime import (
    PortalRuntime,
    RouteDependencies,
    function_scoped_database_dependency,
)
from carlos_patient_portal.schemas import SignupRequest
from carlos_patient_portal.self_signup import (
    SIGNUP_OUTCOME_RATE_LIMITED,
    SelfSignupPolicy,
    SignupQueueFullError,
    SignupRequestDetails,
    hash_signup_client,
    hash_signup_health_card,
    submit_signup_request,
)
from carlos_patient_portal.web_support import (
    date_of_birth_from_form,
    first_form_value,
    first_form_value_or_empty,
    get_csrf_urlencoded_form_values,
    get_request_client_reference,
    render_public_auth_template,
    request_locale,
)

SIGN_UP_TEMPLATE = "sign_up.jinja"
SIGN_UP_RESULT_TEMPLATE = "auth_result.jinja"
# What a form error shows again. Only a typing aid, so each value is capped. The date of birth is
# the Day, Month and Year boxes activation uses (carlos-portal#30).
SIGN_UP_KEPT_FIELDS = (
    "health_card_number",
    "date_of_birth_day",
    "date_of_birth_month",
    "date_of_birth_year",
    "email",
)
MAX_KEPT_SIGN_UP_VALUE_LENGTH = 256


def is_only_a_date_of_birth_error(exc: ValidationError) -> bool:
    """Whether the date of birth is the only detail in the wrong format."""
    return all("date_of_birth" in tuple(error.get("loc") or ()) for error in exc.errors())


async def hold_response_floor(started_at: float, floor_seconds: float) -> None:
    """Wait out the rest of the floor, so a fast refusal is as slow as a store."""
    remaining = floor_seconds - (monotonic() - started_at)
    if remaining > 0:
        await asyncio.sleep(remaining)


def register_signup_routes(
    app: FastAPI,
    runtime: PortalRuntime,
    route_dependencies: RouteDependencies,
) -> None:
    settings = runtime.settings
    if not settings.self_signup_enabled:
        # Not registered at all: /auth/sign-up then answers exactly as any unknown path does, and
        # nothing can be stored.
        return
    get_app_database_session = route_dependencies.get_app_database_session
    csrf_secret = runtime.token_keys.csrf
    audit_hash_secret = runtime.audit_hash_secret
    policy = SelfSignupPolicy.from_settings(settings)
    response_floor_seconds = settings.self_signup_response_floor_ms / 1000

    def render_sign_up_page(
        request: Request,
        *,
        status_code: int = status.HTTP_200_OK,
        error_message: str | None = None,
        form_values: dict[str, str] | None = None,
    ) -> Response:
        return render_public_auth_template(
            request,
            settings=settings,
            csrf_secret=csrf_secret,
            template_name=SIGN_UP_TEMPLATE,
            status_code=status_code,
            error_message=error_message,
            form_values=form_values,
        )

    @app.get("/auth/sign-up", name="sign_up_page")
    def sign_up_page(request: Request) -> Response:
        return render_sign_up_page(request)

    @app.post(
        "/auth/sign-up",
        status_code=status.HTTP_202_ACCEPTED,
        responses={
            status.HTTP_400_BAD_REQUEST: {"description": "A detail is not in a valid format."},
            status.HTTP_403_FORBIDDEN: {"description": "The CSRF token is invalid."},
            status.HTTP_503_SERVICE_UNAVAILABLE: {"description": "The request backlog is full."},
        },
    )
    async def submit_sign_up(
        request: Request,
        session: Annotated[Session, function_scoped_database_dependency(get_app_database_session)],
    ) -> Response:
        started_at = monotonic()
        text = portal_text(request_locale(request))
        form_values = await get_csrf_urlencoded_form_values(
            request,
            csrf_secret,
            unsupported_media_type_detail="sign-up requires a form request body",
        )
        try:
            payload = SignupRequest.model_validate(
                {
                    "health_card_number": first_form_value(form_values, "health_card_number"),
                    # Shared with activation: the three boxes as one ISO date, or a value the
                    # model refuses when they are not a real date.
                    "date_of_birth": date_of_birth_from_form(form_values),
                    "email": first_form_value(form_values, "email"),
                }
            )
        except ValidationError as exc:
            # A format problem says nothing about any patient, so it is named, and the entries are
            # shown again. Nothing is stored or counted.
            return render_sign_up_page(
                request,
                status_code=status.HTTP_400_BAD_REQUEST,
                error_message=(
                    text["activation_date_of_birth_invalid"]
                    if is_only_a_date_of_birth_error(exc)
                    else text["sign_up_details_invalid"]
                ),
                form_values={
                    field_name: value[:MAX_KEPT_SIGN_UP_VALUE_LENGTH]
                    for field_name in SIGN_UP_KEPT_FIELDS
                    if (value := first_form_value_or_empty(form_values, field_name))
                },
            )
        details = SignupRequestDetails(
            health_card_number=payload.health_card_number,
            date_of_birth=payload.date_of_birth,
            email=payload.email,
        )
        try:
            outcome = await run_in_threadpool(
                submit_signup_request,
                session,
                details=details,
                clinic_id=settings.clinic_id,
                client_reference_hash=hash_signup_client(
                    audit_hash_secret,
                    get_request_client_reference(request, settings),
                ),
                health_card_hash=hash_signup_health_card(
                    audit_hash_secret,
                    details.health_card_number,
                ),
                encryption_secret=runtime.outbox_encryption_secret,
                encryption_key_id=runtime.outbox_active_key_id,
                policy=policy,
            )
        except SignupQueueFullError:
            # Release the admission lock now rather than at dependency teardown. A full backlog is
            # global, so this 503 is the same for every patient and reveals nothing about one.
            await run_in_threadpool(session.rollback)
            runtime.operational_metrics.record_failure("self_signup_queue_full")
            response = render_sign_up_page(
                request,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                error_message=text["sign_up_unavailable"],
            )
            response.headers["Retry-After"] = str(settings.self_signup_queue_retry_after_seconds)
            return response
        await run_in_threadpool(session.commit)
        # Hand the connection back before waiting out the floor.
        await run_in_threadpool(session.close)
        if outcome == SIGNUP_OUTCOME_RATE_LIMITED:
            runtime.operational_metrics.record_failure("self_signup_rate_limited")
        response = render_public_auth_template(
            request,
            settings=settings,
            csrf_secret=csrf_secret,
            template_name=SIGN_UP_RESULT_TEMPLATE,
            status_code=status.HTTP_202_ACCEPTED,
            result_heading=text["sign_up_result_heading"],
            result_message=text["sign_up_result"],
        )
        await hold_response_floor(started_at, response_floor_seconds)
        return response
