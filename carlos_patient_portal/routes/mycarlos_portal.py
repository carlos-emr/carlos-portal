# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Patient-owned linking controls, registered only while delivery is enabled."""

from dataclasses import replace
from typing import Annotated

from fastapi import FastAPI, HTTPException, Request
from fastapi import Path as PathParam
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool
from starlette.responses import Response

from carlos_patient_portal.audit import record_audit_event
from carlos_patient_portal.auth import (
    AuthenticatedPortalSession,
    MfaDeliveryUnavailableError,
    MfaRateLimitedError,
    create_mfa_challenge,
)
from carlos_patient_portal.email_delivery import PortalEmailDeliveryError
from carlos_patient_portal.i18n import portal_text
from carlos_patient_portal.models import (
    AUDIT_ACTOR_TYPE_PATIENT,
    AUDIT_EVENT_MYCARLOS_DEVICE_REMOVE,
    AUDIT_EVENT_MYCARLOS_LINK_CODE_CREATE,
    AUDIT_OUTCOME_FAILURE,
    AUDIT_OUTCOME_SUCCESS,
    MFA_DELIVERY_METHOD_EMAIL,
    MFA_DELIVERY_METHOD_SMS,
    PatientPortalAccount,
    utc_now,
)
from carlos_patient_portal.mycarlos_devices import remove_device
from carlos_patient_portal.mycarlos_links import (
    LinkingPausedError,
    clinic_has_active_key,
    create_link_code,
)
from carlos_patient_portal.mycarlos_qr import link_qr_data_uri
from carlos_patient_portal.notifications import record_mfa_delivery_and_commit, send_mfa_challenge
from carlos_patient_portal.presenters import assemble_mycarlos_devices
from carlos_patient_portal.routes.auth import build_auth_dependencies
from carlos_patient_portal.runtime import (
    PortalRuntime,
    RouteDependencies,
    function_scoped_database_dependency,
)
from carlos_patient_portal.sms_delivery import PortalSmsDeliveryError
from carlos_patient_portal.web_support import (
    CONTENT_SECURITY_POLICY,
    CSRF_FORM_FIELD,
    PORTAL_MFA_PROOF_COOKIE_NAME,
    PORTAL_SESSION_COOKIE_NAME,
    is_valid_portal_mfa_proof,
    request_locale,
)


def register_mycarlos_portal_routes(
    app: FastAPI, runtime: PortalRuntime, deps: RouteDependencies
) -> None:
    settings = runtime.settings
    auth_deps = build_auth_dependencies(runtime, deps)
    database = deps.get_app_database_session

    def has_mfa_proof(request: Request) -> bool:
        return is_valid_portal_mfa_proof(
            request.cookies.get(PORTAL_MFA_PROOF_COOKIE_NAME),
            request.cookies.get(PORTAL_SESSION_COOKIE_NAME),
            proof_secret=runtime.token_keys.mycarlos_mfa_proof,
            allow_email=settings.is_development,
        )

    def authenticate_mutation(
        request: Request, session: Session
    ) -> AuthenticatedPortalSession | RedirectResponse:
        authenticated = deps.get_portal_cookie_session_or_redirect(request, session)
        if isinstance(authenticated, RedirectResponse):
            return authenticated
        account_id = authenticated.account.id
        # Authentication can update last_seen and lock its session row. Release that transaction
        # before taking the account lock, so settings changes can keep account -> session order.
        session.commit()
        account = session.scalar(
            select(PatientPortalAccount)
            .where(PatientPortalAccount.id == account_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        if account is None:
            raise HTTPException(status_code=401, detail="authentication required")
        # Re-query instead of refreshing a possibly deleted session row. Expiry, revocation or
        # deletion during the wait must follow the ordinary signed-out path, never become a 500.
        session.expire_all()
        return deps.get_portal_cookie_session_or_redirect(request, session)

    def render(
        request: Request,
        session: Session,
        authenticated: AuthenticatedPortalSession,
        *,
        status_code: int = 200,
        error_key: str | None = None,
        code_display: str | None = None,
        qr_png_data_uri: str | None = None,
        confirmation_key: str | None = None,
    ) -> Response:
        view = assemble_mycarlos_devices(
            session,
            authenticated.account,
            account_path=request.url_for("portal_account").path,
            locale=request_locale(request),
            timezone_name=settings.clinic_timezone,
            portal_address=settings.public_base_url,
        )
        confirmation = next(
            (row for row in view.devices if row.device_key_id == confirmation_key), None
        )
        if confirmation_key is not None and confirmation is None:
            raise HTTPException(status_code=404, detail="device not found")
        view = replace(
            view,
            code_display=code_display,
            qr_png_data_uri=qr_png_data_uri,
            confirmation=confirmation,
            mfa_required=not has_mfa_proof(request),
            error=portal_text(request_locale(request))[error_key] if error_key else None,
        )
        response = deps.render_portal_page(
            request,
            session,
            active_module="mycarlos",
            authenticated_session=authenticated,
            mycarlos=view,
            status_code=status_code,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        if qr_png_data_uri is not None:
            response.headers["Content-Security-Policy"] = (
                f"{CONTENT_SECURITY_POLICY}; img-src 'self' data:"
            )
        return response

    def audit(
        session: Session,
        authenticated: AuthenticatedPortalSession,
        *,
        event_type: str,
        outcome: str,
        reason: str,
        resource_id: str | None = None,
    ) -> None:
        account = authenticated.account
        record_audit_event(
            session,
            event_type=event_type,
            outcome=outcome,
            actor_type=AUDIT_ACTOR_TYPE_PATIENT,
            actor=account.username,
            clinic_id=account.clinic_id,
            demographic_no=account.demographic_no,
            account_id=account.id,
            resource_type="mycarlos_device" if resource_id else "mycarlos_link_code",
            resource_id=resource_id,
            reason=reason,
        )

    async def checked_form(request: Request) -> None:
        values = await deps.get_portal_account_form_values(
            request, csrf_error_detail="linking action could not be completed"
        )
        if set(values) != {CSRF_FORM_FIELD}:
            raise HTTPException(status_code=400, detail="invalid linking form")

    @app.get("/portal/mycarlos", name="portal_mycarlos")
    def linking_page(
        request: Request,
        session: Annotated[Session, function_scoped_database_dependency(database)],
    ) -> Response:
        authenticated = deps.get_portal_cookie_session_or_redirect(request, session)
        if isinstance(authenticated, RedirectResponse):
            return authenticated
        return render(request, session, authenticated)

    def issue_code(request: Request, session: Session) -> Response:
        authenticated = authenticate_mutation(request, session)
        if isinstance(authenticated, RedirectResponse):
            return authenticated
        if not has_mfa_proof(request):
            audit(
                session,
                authenticated,
                event_type=AUDIT_EVENT_MYCARLOS_LINK_CODE_CREATE,
                outcome=AUDIT_OUTCOME_FAILURE,
                reason="mfa_required",
            )
            session.commit()
            return render(
                request, session, authenticated, status_code=403, error_key="mycarlos_mfa_required"
            )
        if not clinic_has_active_key(session, settings.clinic_id):
            audit(
                session,
                authenticated,
                event_type=AUDIT_EVENT_MYCARLOS_LINK_CODE_CREATE,
                outcome=AUDIT_OUTCOME_FAILURE,
                reason="clinic_keys_missing",
            )
            session.commit()
            return render(
                request, session, authenticated, status_code=409, error_key="mycarlos_unavailable"
            )
        try:
            issued = create_link_code(
                session,
                account_id=authenticated.account.id,
                session_id=authenticated.portal_session.id,
                key=runtime.token_keys.mycarlos_link,
                idle_timeout=runtime.auth_policy.session_idle_timeout,
            )
        except LinkingPausedError:
            audit(
                session,
                authenticated,
                event_type=AUDIT_EVENT_MYCARLOS_LINK_CODE_CREATE,
                outcome=AUDIT_OUTCOME_FAILURE,
                reason="linking_paused",
            )
            session.commit()
            return render(
                request, session, authenticated, status_code=429, error_key="mycarlos_paused"
            )
        audit(
            session,
            authenticated,
            event_type=AUDIT_EVENT_MYCARLOS_LINK_CODE_CREATE,
            outcome=AUDIT_OUTCOME_SUCCESS,
            reason="created",
        )
        qr_png_data_uri = link_qr_data_uri(issued, settings.public_base_url)
        session.commit()
        return render(
            request,
            session,
            authenticated,
            code_display=issued.display,
            qr_png_data_uri=qr_png_data_uri,
        )

    @app.post("/portal/mycarlos/code", name="portal_mycarlos_code")
    async def linking_code(
        request: Request,
        session: Annotated[Session, function_scoped_database_dependency(database)],
    ) -> Response:
        await checked_form(request)
        return await run_in_threadpool(issue_code, request, session)

    def start_step_up(request: Request, session: Session) -> Response:
        authenticated = authenticate_mutation(request, session)
        if isinstance(authenticated, RedirectResponse):
            return authenticated
        account = authenticated.account
        if account.phone_number and runtime.sms_sender is not None:
            method = MFA_DELIVERY_METHOD_SMS
        elif settings.is_development and runtime.email_sender is not None:
            method = MFA_DELIVERY_METHOD_EMAIL
        else:
            return render(
                request, session, authenticated, status_code=409, error_key="mycarlos_unavailable"
            )
        try:
            delivery = create_mfa_challenge(
                session,
                account,
                delivery_method=method,
                policy=runtime.auth_policy,
                challenge_token_secret=runtime.token_keys.mfa,
                code_secret=runtime.token_keys.mfa,
                now=utc_now(),
            )
        except MfaRateLimitedError:
            return render(
                request,
                session,
                authenticated,
                status_code=429,
                error_key="mycarlos_mfa_rate_limited",
            )
        except MfaDeliveryUnavailableError:
            return render(
                request, session, authenticated, status_code=409, error_key="mycarlos_unavailable"
            )
        session.commit()
        try:
            send_mfa_challenge(runtime, delivery)
        except (PortalEmailDeliveryError, PortalSmsDeliveryError):
            record_mfa_delivery_and_commit(
                session, delivery=delivery, outcome=AUDIT_OUTCOME_FAILURE
            )
            return render(
                request, session, authenticated, status_code=503, error_key="mycarlos_unavailable"
            )
        record_mfa_delivery_and_commit(session, delivery=delivery, outcome=AUDIT_OUTCOME_SUCCESS)
        return auth_deps.render_mfa_page(request, delivery)

    @app.post("/portal/mycarlos/mfa", name="portal_mycarlos_mfa")
    async def linking_mfa(
        request: Request,
        session: Annotated[Session, function_scoped_database_dependency(database)],
    ) -> Response:
        await checked_form(request)
        return await run_in_threadpool(start_step_up, request, session)

    @app.get(
        "/portal/account/mycarlos/devices/{device_key_id}/remove",
        name="portal_mycarlos_remove_confirmation",
    )
    def removal_confirmation(
        request: Request,
        device_key_id: Annotated[str, PathParam(pattern=r"^[A-Za-z0-9_-]{43}$")],
        session: Annotated[Session, function_scoped_database_dependency(database)],
    ) -> Response:
        authenticated = deps.get_portal_cookie_session_or_redirect(request, session)
        if isinstance(authenticated, RedirectResponse):
            return authenticated
        return render(request, session, authenticated, confirmation_key=device_key_id)

    def remove_owned_device(request: Request, session: Session, device_key_id: str) -> Response:
        authenticated = authenticate_mutation(request, session)
        if isinstance(authenticated, RedirectResponse):
            return authenticated
        if not has_mfa_proof(request):
            return render(
                request, session, authenticated, status_code=403, error_key="mycarlos_mfa_required"
            )
        removed = remove_device(
            session,
            account_id=authenticated.account.id,
            device_key_id=device_key_id,
            removed_by=AUDIT_ACTOR_TYPE_PATIENT,
            mailbox_enabled=settings.mycarlos_mailbox_enabled,
        )
        if removed is None:
            raise HTTPException(status_code=404, detail="device not found")
        device, changed = removed
        audit(
            session,
            authenticated,
            event_type=AUDIT_EVENT_MYCARLOS_DEVICE_REMOVE,
            outcome=AUDIT_OUTCOME_SUCCESS,
            reason="removed" if changed else "already_removed",
            resource_id=str(device.id),
        )
        session.commit()
        return RedirectResponse(
            f"{request.url_for('portal_account').path}?status=mycarlos-device-removed",
            status_code=303,
        )

    @app.post("/portal/account/mycarlos/devices/{device_key_id}/remove")
    async def remove_linked_device(
        request: Request,
        device_key_id: Annotated[str, PathParam(pattern=r"^[A-Za-z0-9_-]{43}$")],
        session: Annotated[Session, function_scoped_database_dependency(database)],
    ) -> Response:
        await checked_form(request)
        return await run_in_threadpool(remove_owned_device, request, session, device_key_id)
