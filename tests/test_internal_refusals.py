# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""What the internal staff routes refuse, with which status and words, and what they leave alone.

FAKE patients only. One app serves the whole module; every test uses its own patient number.
"""

import itertools
import logging
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError, OperationalError
from starlette.requests import Request

from carlos_patient_portal import internal_routes
from carlos_patient_portal.auth import AccountNotFoundError
from carlos_patient_portal.models import (
    PatientPortalAccount,
    PatientPortalAuditEvent,
    PatientPortalUnlockSecret,
)
from carlos_patient_portal.unlock_secrets import UnlockSecretNotFoundError
from tests.test_internal_api import carlos_headers, internal_app, invite_request
from tests.test_mycarlos_internal_routes import MANAGE as DEVICE_MANAGE
from tests.test_mycarlos_internal_routes import device_key_id, mycarlos_app, staff

PATIENTS = itertools.count(7100)
INVITES = "/internal/carlos/patients/{}/invites"
MANAGE = carlos_headers("portal.invite.manage")
SECRETS = carlos_headers("portal.secret.manage")


@pytest.fixture(scope="module")
def app():
    return internal_app()


@pytest.fixture(scope="module")
def client(app):
    # An unhandled error is an answer to check here, not an exception to raise into the test.
    return TestClient(app, raise_server_exceptions=False)


def patient() -> int:
    return next(PATIENTS)


def create_invite(client, number):
    created = client.post(
        INVITES.format(number), headers=MANAGE, json=invite_request(demographic_no=number)
    )
    assert created.status_code == 201, created.text
    return created.json()


def prepare(number, operation):
    return {**invite_request(demographic_no=number), "delivery_operation_id": operation}


def give_an_account(app, number):
    from carlos_patient_portal.credentials import hash_password
    from tests.support import STRONG_PASSWORD

    with app.state.session_factory() as session, session.begin():
        session.add(
            PatientPortalAccount(
                clinic_id=app.state.settings.clinic_id,
                demographic_no=number,
                username=f"fake.{number}",
                email="fake@example.test",
                preferred_mfa_method="email",
                password_hash=hash_password(STRONG_PASSWORD),
                status="active",
            )
        )


def count(app, model):
    with app.state.session_factory() as session:
        return session.scalar(select(func.count()).select_from(model))


# ---- invites ----


def test_a_prepared_invite_must_name_the_patient_the_route_names(client):
    number = patient()
    refused = client.post(
        INVITES.format(number) + "/prepare",
        headers=MANAGE,
        json=prepare(number + 1, "invite-email:scope-1"),
    )
    assert (refused.status_code, refused.json()["detail"]) == (400, "demographic scope mismatch")


@pytest.mark.parametrize("route", ["/prepare", ""], ids=["prepared", "direct"])
def test_an_invite_for_a_patient_who_already_has_an_account_is_a_conflict(app, client, route):
    number = patient()
    give_an_account(app, number)
    body = (
        prepare(number, f"invite-email:account-{number}")
        if route
        else invite_request(demographic_no=number)
    )
    refused = client.post(INVITES.format(number) + route, headers=MANAGE, json=body)
    assert (refused.status_code, refused.json()["detail"]) == (
        409,
        "portal account already exists",
    )


def test_a_second_invite_while_one_is_pending_is_a_conflict_on_the_prepared_route(client):
    number = patient()
    assert (
        client.post(
            INVITES.format(number) + "/prepare",
            headers=MANAGE,
            json=prepare(number, "invite-email:first"),
        ).status_code
        == 201
    )
    # The first is only prepared; a different operation cannot take its place.
    refused = client.post(
        INVITES.format(number) + "/prepare",
        headers=MANAGE,
        json=prepare(number, "invite-email:second"),
    )
    assert refused.status_code == 409


@pytest.mark.parametrize(
    "path,body",
    [
        ("/internal/carlos/invites/{}/resend/prepare", {"delivery_operation_id": "op:resend"}),
        ("/internal/carlos/invites/{}/resend", None),
        ("/internal/carlos/invites/{}/revoke", None),
        (
            "/internal/carlos/invites/{}/commit-delivery",
            {"delivery_operation_id": "op:x", "delivery_reference": "ref:x"},
        ),
    ],
    ids=["prepare resend", "resend", "revoke", "commit delivery"],
)
def test_an_invite_that_is_not_this_clinics_or_not_there_is_not_found(client, path, body):
    refused = client.post(path.format(99_999_999), headers=MANAGE, json=body)
    assert (refused.status_code, refused.json()["detail"]) == (404, "invite not found")


def test_an_invite_that_was_revoked_cannot_be_prepared_for_resend(client):
    invite = create_invite(client, patient())
    assert (
        client.post(f"/internal/carlos/invites/{invite['id']}/revoke", headers=MANAGE).status_code
        == 200
    )
    refused = client.post(
        f"/internal/carlos/invites/{invite['id']}/resend/prepare",
        headers=MANAGE,
        json={"delivery_operation_id": "op:after-revoke"},
    )
    assert (refused.status_code, refused.json()["detail"]) == (409, "invite cannot be resent")


def test_an_invite_cannot_be_committed_for_an_operation_it_was_not_prepared_for(client):
    number = patient()
    prepared = client.post(
        INVITES.format(number) + "/prepare",
        headers=MANAGE,
        json=prepare(number, "invite-email:right"),
    )
    assert prepared.status_code == 201
    refused = client.post(
        f"/internal/carlos/invites/{prepared.json()['id']}/commit-delivery",
        headers=MANAGE,
        json={"delivery_operation_id": "invite-email:wrong", "delivery_reference": "msg:1"},
    )
    assert (refused.status_code, refused.json()["detail"]) == (409, "invite delivery conflicts")


def test_an_accepted_invite_cannot_be_revoked(app, client):
    number = patient()
    invite = create_invite(client, number)
    activated = client.post(
        "/auth/activate",
        json={
            "invite_code": invite["invite_token"],
            "email": invite_request()["email"],
            "date_of_birth": invite_request()["date_of_birth"],
            "health_card_number": invite_request()["health_card_number"],
            "username": f"patient.{number}",
            "password": "Stronger1!word",
        },
    )
    assert activated.status_code == 201, activated.text
    refused = client.post(f"/internal/carlos/invites/{invite['id']}/revoke", headers=MANAGE)
    assert (refused.status_code, refused.json()["detail"]) == (
        409,
        "accepted invite cannot be revoked",
    )


# ---- accounts ----


def test_an_unlock_or_an_access_change_for_a_patient_with_no_account_is_not_found(client):
    number = patient()
    unlock = client.post(
        f"/internal/carlos/patients/{number}/unlock",
        headers=carlos_headers("portal.account.unlock"),
    )
    access = client.post(
        f"/internal/carlos/patients/{number}/portal-account/access",
        headers=carlos_headers("portal.account.manage"),
        json={"enabled": False},
    )
    assert unlock.status_code == access.status_code == 404
    assert unlock.json()["detail"] == access.json()["detail"]


def test_an_account_that_goes_away_while_it_is_unlocked_or_changed_is_not_found(
    app, client, monkeypatch
):
    number = patient()
    give_an_account(app, number)

    def gone(*args, **kwargs):
        raise AccountNotFoundError()

    monkeypatch.setattr(internal_routes, "unlock_patient_account", gone)
    monkeypatch.setattr(internal_routes, "set_patient_account_access", gone)
    unlock = client.post(
        f"/internal/carlos/patients/{number}/unlock",
        headers=carlos_headers("portal.account.unlock"),
    )
    access = client.post(
        f"/internal/carlos/patients/{number}/portal-account/access",
        headers=carlos_headers("portal.account.manage"),
        json={"enabled": False},
    )
    assert unlock.status_code == access.status_code == 404


def test_an_access_change_the_domain_refuses_is_a_422_that_changes_nothing(
    app, client, monkeypatch
):
    number = patient()
    give_an_account(app, number)

    def refuses(*args, **kwargs):
        raise ValueError("FAKE reason the domain refuses")

    monkeypatch.setattr(internal_routes, "set_patient_account_access", refuses)
    refused = client.post(
        f"/internal/carlos/patients/{number}/portal-account/access",
        headers=carlos_headers("portal.account.manage"),
        json={"enabled": False, "reason": "FAKE reason"},
    )
    assert (refused.status_code, refused.json()["detail"]) == (
        422,
        "invalid account access request",
    )
    # The domain's own words are never sent back to the caller.
    assert "FAKE reason the domain" not in refused.text
    with app.state.session_factory() as session:
        account = session.scalar(
            select(PatientPortalAccount).where(PatientPortalAccount.demographic_no == number)
        )
        assert account.status == "active"


def test_removing_a_device_of_a_patient_with_no_account_is_not_found():
    # The route exists only where myCarlos delivery is on, so this test has its own app.
    client = TestClient(mycarlos_app())
    refused = client.post(
        f"/internal/carlos/patients/{patient()}/mycarlos/devices/{device_key_id('none')}/remove",
        headers=staff(DEVICE_MANAGE),
    )
    assert refused.status_code == 404
    assert refused.json()["detail"] == internal_routes.INTERNAL_ACCOUNT_NOT_FOUND_DETAIL


# ---- stored passwords (unlock secrets) ----


def secret_body(reference):
    return {"source_reference": reference, "label": "FAKE letter", "secret_type": "email"}


def test_a_revoked_source_reference_cannot_be_asked_for_again(client):
    number = patient()
    created = client.post(
        f"/internal/carlos/patients/{number}/unlock-secrets",
        headers=SECRETS,
        json=secret_body(f"msg-{number}"),
    )
    assert created.status_code == 201
    revoked = client.post(
        f"/internal/carlos/unlock-secrets/{created.json()['id']}/revoke",
        headers=SECRETS,
        json={"reason": "recalled"},
    )
    assert revoked.status_code == 200
    again = client.post(
        f"/internal/carlos/patients/{number}/unlock-secrets",
        headers=SECRETS,
        json=secret_body(f"msg-{number}"),
    )
    assert (again.status_code, again.json()["detail"]) == (409, "source reference was revoked")


def lose_the_race(monkeypatch):
    """The first look-up finds nothing, as if the other request had not committed yet."""
    real = internal_routes.get_unlock_secret_by_source_reference
    calls = []

    def lookup(*args, **kwargs):
        calls.append(1)
        return None if len(calls) == 1 else real(*args, **kwargs)

    monkeypatch.setattr(internal_routes, "get_unlock_secret_by_source_reference", lookup)


def test_two_requests_for_one_reference_at_once_never_hand_one_patient_anothers_secret(
    client, monkeypatch
):
    owner, other = patient(), patient()
    reference = f"msg-race-{owner}"
    created = client.post(
        f"/internal/carlos/patients/{owner}/unlock-secrets",
        headers=SECRETS,
        json=secret_body(reference),
    )
    assert created.status_code == 201
    lose_the_race(monkeypatch)
    refused = client.post(
        f"/internal/carlos/patients/{other}/unlock-secrets",
        headers=SECRETS,
        json=secret_body(reference),
    )
    assert (refused.status_code, refused.json()["detail"]) == (
        409,
        "source reference belongs to another patient",
    )
    assert created.json()["secret"] not in refused.text


def test_a_lost_race_for_a_revoked_reference_is_refused_and_for_a_pending_one_repeats_it(
    client, monkeypatch
):
    number = patient()
    reference = f"msg-race-{number}"
    first = client.post(
        f"/internal/carlos/patients/{number}/unlock-secrets",
        headers=SECRETS,
        json=secret_body(reference),
    )
    lose_the_race(monkeypatch)
    repeated = client.post(
        f"/internal/carlos/patients/{number}/unlock-secrets",
        headers=SECRETS,
        json=secret_body(reference),
    )
    assert repeated.status_code == 201 and repeated.json()["created"] is False
    assert repeated.json()["id"] == first.json()["id"]
    client.post(
        f"/internal/carlos/unlock-secrets/{first.json()['id']}/revoke",
        headers=SECRETS,
        json={"reason": "recalled"},
    )
    lose_the_race(monkeypatch)
    refused = client.post(
        f"/internal/carlos/patients/{number}/unlock-secrets",
        headers=SECRETS,
        json=secret_body(reference),
    )
    assert (refused.status_code, refused.json()["detail"]) == (409, "source reference was revoked")


def test_a_conflict_that_is_not_a_repeated_reference_is_a_server_error_and_stores_nothing(
    app, client, monkeypatch
):
    number = patient()

    def conflict(*args, **kwargs):
        raise IntegrityError("FAKE", {}, Exception("FAKE"))

    monkeypatch.setattr(internal_routes, "create_unlock_secret", conflict)
    before = count(app, PatientPortalUnlockSecret)
    failed = client.post(
        f"/internal/carlos/patients/{number}/unlock-secrets",
        headers=SECRETS,
        json=secret_body(f"msg-conflict-{number}"),
    )
    assert failed.status_code == 500
    assert "FAKE" not in failed.text
    assert count(app, PatientPortalUnlockSecret) == before


def test_a_secret_that_vanishes_before_it_is_revoked_is_not_found(client, monkeypatch):
    number = patient()
    created = client.post(
        f"/internal/carlos/patients/{number}/unlock-secrets",
        headers=SECRETS,
        json=secret_body(f"msg-vanish-{number}"),
    )

    def gone(*args, **kwargs):
        raise UnlockSecretNotFoundError()

    monkeypatch.setattr(internal_routes, "revoke_unlock_secret", gone)
    refused = client.post(
        f"/internal/carlos/unlock-secrets/{created.json()['id']}/revoke",
        headers=SECRETS,
        json={"reason": "recalled"},
    )
    assert refused.status_code == 404


# ---- the record of what was refused ----


def request_for(route):
    request = Request({"type": "http", "path": "/x", "headers": []})
    request.scope["route"] = route
    return request


def test_the_audit_names_the_route_template_and_never_the_path_that_was_asked(client):
    template = "/internal/carlos/invites/{invite_id}/revoke"
    assert (
        internal_routes.internal_route_template(request_for(SimpleNamespace(path=template)))
        == template
    )
    # Anything else, or no matched route at all, is the one broad name.
    for route in (
        SimpleNamespace(path="/auth/login"),
        SimpleNamespace(path=None),
        SimpleNamespace(),
        None,
    ):
        assert internal_routes.internal_route_template(request_for(route)) == "/internal/carlos/"


def test_a_refusal_is_still_a_refusal_when_the_audit_row_cannot_be_written(
    app, client, monkeypatch, caplog
):
    def cannot_write(*args, **kwargs):
        raise OperationalError("FAKE patient detail", {}, Exception("FAKE"))

    monkeypatch.setattr(internal_routes, "record_audit_event", cannot_write)
    before = count(app, PatientPortalAuditEvent)
    with caplog.at_level(logging.ERROR, logger=internal_routes.logger.name):
        refused = client.post("/internal/carlos/invites/99999999/revoke", headers=MANAGE)
    assert refused.status_code == 404
    assert count(app, PatientPortalAuditEvent) == before
    # Loud in the log, but only the error's kind: never its text, which can hold patient values.
    logged = [r for r in caplog.records if "audit write failed" in r.getMessage()]
    assert len(logged) == 1
    assert "OperationalError" in logged[0].getMessage()
    assert "FAKE patient detail" not in caplog.text
