# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The development admin API's refusals that `test_invites.py` does not drive.

`/dev/admin/*` exists only in a development portal with the explicit flag and the bearer token. Its
routes are a thin map from the invite and account services' refusals to fixed status codes and
texts; these tests drive the remaining ones with real service state (no mocks of the services):
a live preparation blocking a new invite, an invite that a resend already replaced, and an
unknown invite or account.
"""

from fastapi.testclient import TestClient

from carlos_patient_portal.invites import prepare_create_invite
from tests.support import (
    IDENTITY_PROOF_SECRET,
    OUTBOX_ENCRYPTION_SECRET,
    activation_request,
    dev_admin_headers,
    migrated_development_app,
    seeded_identity_proof,
    seeded_invite_request,
)


def created(client: TestClient, **overrides: object) -> dict:
    response = client.post(
        "/dev/admin/invites",
        headers=dev_admin_headers(),
        json=seeded_invite_request(**overrides),
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_a_live_delivery_preparation_blocks_a_new_invite_with_its_own_message() -> None:
    app = migrated_development_app(outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    with app.state.session_factory() as session, session.begin():
        prepare_create_invite(
            session,
            1234,
            "Front Desk",
            delivery_operation_id="op-live-0001",
            identity_proof=seeded_identity_proof(),
            proof_secret=IDENTITY_PROOF_SECRET,
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            encryption_key_id="primary",
            encryption_keys={"primary": OUTBOX_ENCRYPTION_SECRET},
            clinic_id="default",
        )

    response = TestClient(app).post(
        "/dev/admin/invites", headers=dev_admin_headers(), json=seeded_invite_request()
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "another invite delivery is being prepared"}


def test_a_pending_invite_that_wins_a_race_is_a_conflict_and_not_a_server_error(
    monkeypatch,
) -> None:
    """`create_invite` retires an older pending invite first, so this answer is only reachable
    through a race the database's one-pending-invite constraint settles; the route's mapping of it
    is what is checked, with the service replaced by one that loses that race."""
    from carlos_patient_portal.invites import PendingInviteExistsError
    from carlos_patient_portal.routes import dev_admin

    def lose_the_race(*args: object, **kwargs: object):
        raise PendingInviteExistsError()

    monkeypatch.setattr(dev_admin, "create_invite", lose_the_race)
    response = TestClient(migrated_development_app()).post(
        "/dev/admin/invites", headers=dev_admin_headers(), json=seeded_invite_request()
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "pending invite already exists"}


def test_an_invite_a_resend_replaced_cannot_be_resent_or_revoked_again() -> None:
    client = TestClient(migrated_development_app())
    original = created(client)
    resent = client.post(f"/dev/admin/invites/{original['id']}/resend", headers=dev_admin_headers())
    assert resent.status_code == 200, resent.text
    assert resent.json()["id"] != original["id"]

    again = client.post(f"/dev/admin/invites/{original['id']}/resend", headers=dev_admin_headers())
    revoke = client.post(f"/dev/admin/invites/{original['id']}/revoke", headers=dev_admin_headers())

    for response in (again, revoke):
        assert response.status_code == 409
        assert response.json() == {"detail": "invite was superseded"}
    # The replacement is still the one live invite.
    live = client.post(
        f"/dev/admin/invites/{resent.json()['id']}/revoke", headers=dev_admin_headers()
    )
    assert live.status_code == 200
    assert live.json()["status"] == "revoked"


def test_an_invite_whose_delivery_is_not_committed_cannot_be_resent() -> None:
    app = migrated_development_app(outbox_encryption_secret=OUTBOX_ENCRYPTION_SECRET)
    with app.state.session_factory() as session, session.begin():
        prepared, _token = prepare_create_invite(
            session,
            1234,
            "Front Desk",
            delivery_operation_id="op-prepared-0001",
            identity_proof=seeded_identity_proof(),
            proof_secret=IDENTITY_PROOF_SECRET,
            encryption_secret=OUTBOX_ENCRYPTION_SECRET,
            encryption_key_id="primary",
            encryption_keys={"primary": OUTBOX_ENCRYPTION_SECRET},
            clinic_id="default",
        )
        prepared_id = prepared.id

    response = TestClient(app).post(
        f"/dev/admin/invites/{prepared_id}/resend", headers=dev_admin_headers()
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "invite delivery is not committed"}


def test_unlocking_an_account_answers_with_the_account_and_never_a_credential() -> None:
    client = TestClient(migrated_development_app())
    invite = created(client)
    assert (
        client.post("/auth/activate", json=activation_request(invite["invite_token"])).status_code
        == 201
    )

    response = client.post("/dev/admin/accounts/1/unlock", headers=dev_admin_headers())

    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {
        "id",
        "clinic_id",
        "demographic_no",
        "username",
        "email",
        "locked_at",
        "force_password_reset",
        "failed_login_count",
    }
    assert (body["id"], body["demographic_no"], body["locked_at"], body["failed_login_count"]) == (
        1,
        1234,
        None,
        0,
    )


def test_an_unknown_invite_or_account_is_a_plain_not_found() -> None:
    client = TestClient(migrated_development_app())

    revoke = client.post("/dev/admin/invites/999/revoke", headers=dev_admin_headers())
    unlock = client.post("/dev/admin/accounts/999/unlock", headers=dev_admin_headers())

    assert (revoke.status_code, revoke.json()) == (404, {"detail": "invite not found"})
    assert (unlock.status_code, unlock.json()) == (404, {"detail": "account not found"})


def test_none_of_these_routes_answers_without_the_bearer_token() -> None:
    client = TestClient(migrated_development_app())
    for method, path in (
        ("post", "/dev/admin/invites/1/revoke"),
        ("post", "/dev/admin/invites/1/resend"),
        ("post", "/dev/admin/accounts/1/unlock"),
    ):
        response = getattr(client, method)(path)
        # An unauthenticated caller gets the same 404 as for a path that does not exist.
        assert response.status_code == 404, path
        assert "invite" not in response.text.lower()
