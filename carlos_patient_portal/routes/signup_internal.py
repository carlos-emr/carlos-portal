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

"""The internal API CARLOS polls for self sign-up requests (carlos-portal#16, designed in #10).

CARLOS calls the portal; the portal never calls CARLOS. Both routes take the `signup-poll` job
claiming `portal.signup.manage`, and nobody else: staff are refused, whatever they hold, and so is
every other job. The job is audited as the system actor it is, with the key id and assertion id of
the call.

- `POST /internal/carlos/signup-requests/claim` leases pending requests and returns their decrypted
  details: health card number, date of birth and the typed email. The response is the only place
  these leave the portal.
- `POST /internal/carlos/signup-requests/{request_id}/result` reports `matched` (with the invite),
  `no_match` or `ineligible`, and deletes the stored details.

The refusals' `detail` texts are part of the contract and carry no request detail. See
`signup_claims.py` for the rules.
"""

import logging
from datetime import date, datetime
from typing import Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Path, status
from pydantic import BaseModel, ConfigDict, Field, model_validator
from sqlalchemy.orm import Session

from carlos_patient_portal.internal_routes import (
    COMMON_INTERNAL_RESPONSES,
    INTERNAL_CONFLICT_RESPONSES,
    InternalRouteDependencies,
    InternalRuntime,
)
from carlos_patient_portal.job_identity import JobPrincipal
from carlos_patient_portal.models import SIGNUP_RESULT_MATCHED
from carlos_patient_portal.runtime import MAX_DATABASE_ID
from carlos_patient_portal.signup_claims import (
    MAX_SIGNUP_CLAIM_BATCH,
    SignupLeaseExpiredError,
    SignupRequestNotFoundError,
    SignupResultConflictError,
    SignupResultInvalidError,
    claim_signup_requests,
    record_signup_result,
)
from carlos_patient_portal.system_jobs import JOB_SIGNUP_POLL, PERMISSION_SIGNUP_MANAGE

logger = logging.getLogger(__name__)

# `detail` texts CARLOS tells outcomes apart by. None carries a request's content.
SIGNUP_REQUEST_NOT_FOUND_DETAIL = "sign-up request not found"
SIGNUP_LEASE_EXPIRED_DETAIL = "sign-up request lease expired"
SIGNUP_RESULT_CONFLICT_DETAIL = "sign-up request already has a different result"
SIGNUP_RESULT_INVALID_DETAIL = "sign-up result is invalid"

DEFAULT_SIGNUP_CLAIM_BATCH = 10
# `secrets.token_urlsafe(32)`: 43 characters of URL-safe base64.
LEASE_TOKEN_PATTERN = r"^[A-Za-z0-9_-]{43}$"


class InternalSignupClaimRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    limit: int = Field(
        default=DEFAULT_SIGNUP_CLAIM_BATCH,
        strict=True,
        ge=1,
        le=MAX_SIGNUP_CLAIM_BATCH,
    )


class InternalSignupRequestResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: int
    # Shown once, here. The result must present it while the lease runs.
    lease_token: str = Field(repr=False)
    lease_expires_at: datetime
    requested_at: datetime
    # What the patient typed, normalized as stored. Kept out of repr so no log line carries it.
    health_card_number: str = Field(repr=False)
    date_of_birth: date = Field(repr=False)
    email: str = Field(repr=False)


class InternalSignupClaimResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[InternalSignupRequestResponse]


class InternalSignupResultRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    lease_token: str = Field(repr=False, pattern=LEASE_TOKEN_PATTERN)
    result: Literal["matched", "no_match", "ineligible"]
    # The invite CARLOS made for a match, and only then.
    invite_id: int | None = Field(default=None, strict=True, gt=0, le=MAX_DATABASE_ID)

    @model_validator(mode="after")
    def invite_only_with_a_match(self) -> "InternalSignupResultRequest":
        if (self.result == SIGNUP_RESULT_MATCHED) != (self.invite_id is not None):
            raise ValueError("invite_id is required with matched, and accepted only then")
        return self


class InternalSignupResultResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: int
    result: Literal["matched", "no_match", "ineligible"]
    invite_id: int | None
    # False when this result was already recorded: nothing changed.
    recorded: bool



def register_internal_signup_routes(
    app: FastAPI,
    runtime: InternalRuntime,
    deps: InternalRouteDependencies,
) -> None:
    """The claim and result routes for the `signup-poll` job."""

    @app.post(
        "/internal/carlos/signup-requests/claim",
        response_model=InternalSignupClaimResponse,
        responses=COMMON_INTERNAL_RESPONSES,
    )
    def internal_claim_signup_requests(
        payload: InternalSignupClaimRequest,
        principal: Annotated[
            JobPrincipal,
            Depends(deps.job_principal_requiring(JOB_SIGNUP_POLL, PERMISSION_SIGNUP_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        if not runtime.settings.self_signup_enabled:
            # The route is closed while self sign-up is off, like any other unknown path. Results
            # are still taken (below), so details already leased can be deleted.
            raise HTTPException(status_code=404, detail="not found")
        claim = claim_signup_requests(
            session,
            clinic_id=principal.clinic_id,
            limit=payload.limit,
            lease_seconds=runtime.settings.self_signup_claim_lease_seconds,
            encryption_keys=runtime.outbox_encryption_keys
            or {runtime.outbox_active_key_id: runtime.outbox_encryption_secret},
            actor=principal.display_name,
            actor_id=principal.actor_id,
            assertion_key_id=principal.key_id,
            assertion_id=principal.assertion_id,
        )
        if claim.unreadable:
            runtime.operational_metrics.record_failure("signup_request_unreadable")
        return {
            "items": [
                {
                    "request_id": claimed.request_id,
                    "lease_token": claimed.lease_token,
                    "lease_expires_at": claimed.lease_expires_at,
                    "requested_at": claimed.requested_at,
                    "health_card_number": claimed.details.health_card_number,
                    "date_of_birth": claimed.details.date_of_birth,
                    "email": claimed.details.email,
                }
                for claimed in claim.requests
            ]
        }

    @app.post(
        "/internal/carlos/signup-requests/{request_id}/result",
        response_model=InternalSignupResultResponse,
        responses=INTERNAL_CONFLICT_RESPONSES,
    )
    def internal_record_signup_result(
        request_id: Annotated[int, Path(gt=0, le=MAX_DATABASE_ID)],
        payload: InternalSignupResultRequest,
        principal: Annotated[
            JobPrincipal,
            Depends(deps.job_principal_requiring(JOB_SIGNUP_POLL, PERMISSION_SIGNUP_MANAGE)),
        ],
        session: Annotated[Session, deps.session_dependency],
    ) -> dict[str, object]:
        try:
            outcome = record_signup_result(
                session,
                request_id,
                clinic_id=principal.clinic_id,
                lease_token=payload.lease_token,
                result=payload.result,
                invite_id=payload.invite_id,
                identity_proof_secret=runtime.identity_proof_secret,
                encryption_keys=runtime.outbox_encryption_keys
                or {runtime.outbox_active_key_id: runtime.outbox_encryption_secret},
                actor=principal.display_name,
                actor_id=principal.actor_id,
                assertion_key_id=principal.key_id,
                assertion_id=principal.assertion_id,
            )
        except SignupRequestNotFoundError as exc:
            raise HTTPException(status_code=404, detail=SIGNUP_REQUEST_NOT_FOUND_DETAIL) from exc
        except SignupLeaseExpiredError as exc:
            raise HTTPException(status_code=409, detail=SIGNUP_LEASE_EXPIRED_DETAIL) from exc
        except SignupResultConflictError as exc:
            raise HTTPException(status_code=409, detail=SIGNUP_RESULT_CONFLICT_DETAIL) from exc
        except SignupResultInvalidError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=SIGNUP_RESULT_INVALID_DETAIL,
            ) from exc
        return {
            "request_id": outcome.request_id,
            "result": outcome.result,
            "invite_id": outcome.invite_id,
            "recorded": outcome.recorded,
        }
