# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Historical footer evidence for the CARLOS administrator, never a patient API."""

from datetime import UTC, datetime
from datetime import date as calendar_date
from typing import TYPE_CHECKING, Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field

from carlos_patient_portal.footer_audit import FooterAuditStore, FooterAuditUnavailableError
from carlos_patient_portal.staff_identity import StaffPrincipal

if TYPE_CHECKING:
    from carlos_patient_portal.internal_routes import InternalRouteDependencies, InternalRuntime

PERMISSION_EMAIL_AUDIT_READ = "portal.email.audit.read"


class FooterAttemptView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    attempt_id: str
    kind: str
    prepared_at: str
    status: Literal["prepared", "accepted", "failed", "unknown"]
    status_at: str | None
    clinic_id: str
    revision: str
    footer_text: str
    logo_sha256: str | None


class FooterAuditListView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    date: str
    attempts: list[FooterAttemptView] = Field(max_length=100)
    next_before: str | None


def register_footer_audit_routes(
    app: FastAPI,
    runtime: "InternalRuntime",
    deps: "InternalRouteDependencies",
) -> None:
    @app.get("/internal/carlos/email-footer-attempts", response_model=FooterAuditListView)
    def list_email_footer_attempts(
        principal: Annotated[
            StaffPrincipal, Depends(deps.staff_principal_requiring(PERMISSION_EMAIL_AUDIT_READ))
        ],
        response: Response,
        requested_date: Annotated[
            str | None, Query(alias="date", pattern=r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
        ] = None,
        limit: Annotated[int, Query(ge=1, le=100)] = 50,
        before: Annotated[str | None, Query(pattern=r"^[0-9]{20}-[0-9a-f]{32}$")] = None,
    ) -> dict[str, object]:
        if principal.clinic_id != runtime.settings.clinic_id:
            raise HTTPException(status_code=403, detail="staff permission is required")
        day = requested_date or datetime.now(UTC).date().isoformat()
        try:
            calendar_date.fromisoformat(day)
        except ValueError:
            raise HTTPException(status_code=422, detail="audit date is invalid") from None
        # No current-footer retrieval on historical reads. This is the same durable
        # volume used by web and outbox; the derived worker credential cannot read it.
        store = FooterAuditStore(
            runtime.settings.email_footer_audit_directory, runtime.settings.clinic_id
        )
        try:
            result = store.list_attempts(day=day, limit=limit, before=before)
        except (FooterAuditUnavailableError, OSError, ValueError, TypeError):
            raise HTTPException(
                status_code=503, detail="clinic footer audit is unavailable"
            ) from None
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return result
