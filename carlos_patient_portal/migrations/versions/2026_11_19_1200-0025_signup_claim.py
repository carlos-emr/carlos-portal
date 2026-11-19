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

"""Add the claim lease and result to self sign-up requests, and the `signup.claim` and
`signup.result` audit event types.

CARLOS polls the portal for stored sign-up requests, leases them, and reports what it did with each
(carlos-portal#16). A lease is a token only the claiming call is given (stored as its SHA-256) and
the time it runs out. A reported request deletes its encrypted details: `encrypted_payload` and
`encryption_nonce` become nullable, and a CHECK ties them to `result`, so a row holds either its
details or a result and the invite id, never both. The row stays until its own `expires_at`, so an
identical repeat of the result can be answered as a repeat.

No new table: the grants and the preflight entry for `patient_portal_signup_requests` (0019) already
cover every column.

The audit event-type CHECK is rewritten from the list 0019 left (the only revision after 0017 that
rewrites it) with the two new types added. Downgrade is refused while a reported request or an
audit event of either new type exists: the old schema cannot hold them.

Revision ID: 0025_signup_claim
Revises: 0024_avail_device_removed
Create Date: 2026-11-19 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0025_signup_claim",
    "down_revision": "0024_avail_device_removed",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_AUDIT_TABLE = "patient_portal_audit_events"
_SIGNUP_TABLE = "patient_portal_signup_requests"
_EVENT_CHECK = "ck_patient_portal_audit_events_event_type"

# The 48-type policy 0019 left, unchanged since.
_OLD_EVENT_TYPES = (
    "'activation', 'account.contact_update', 'account.disable', "
    "'account.email_change_confirm', 'account.email_change_request', "
    "'account.enable', 'account.lock', "
    "'account.mfa_update', 'account.password_change', 'account.unlock', "
    "'invite.create', 'invite.list', 'invite.resend', 'invite.revoke', "
    "'job.auth_refused', 'mycarlos.clinic_keys_publish', 'mycarlos.device_list', "
    "'mycarlos.device_remove', 'mycarlos.link', 'mycarlos.link_code_create', "
    "'login', 'mfa.challenge', 'mfa.delivery', 'mfa.resend', 'mfa.verify', "
    "'password_reset.complete', 'password_reset.delivery', "
    "'password_reset.request', 'retention.policy_override', 'session.logout', "
    "'signup.request', "
    "'staff.action', "
    "'fhir.read', 'fhir.search', "
    "'booking_prompt.create', 'booking_prompt.delivery', 'booking_prompt.list', "
    "'booking_prompt.read', 'booking_prompt.withdraw', "
    "'booking_prompt.offer', 'booking_prompt.choice', 'booking_prompt.result', "
    "'booking_prompt.decline', "
    "'unlock_secret.create', 'unlock_secret.list', 'unlock_secret.read', "
    "'unlock_secret.publish', 'unlock_secret.revoke'"
)
_NEW_EVENT_TYPES = _OLD_EVENT_TYPES.replace(
    "'signup.request', ",
    "'signup.request', 'signup.claim', 'signup.result', ",
)

_LEASE_HASH_LENGTH = "ck_pp_signup_requests_lease_token_hash_length"
_LEASE_COMPLETE = "ck_pp_signup_requests_lease_complete"
_RESULT_VALUES = "ck_pp_signup_requests_result_values"
_RESULT_SHAPE = "ck_pp_signup_requests_result_shape"


def upgrade() -> None:
    with op.batch_alter_table(_SIGNUP_TABLE, recreate="always") as batch_op:
        batch_op.alter_column(
            "encrypted_payload",
            existing_type=sa.LargeBinary(),
            nullable=True,
        )
        batch_op.alter_column(
            "encryption_nonce",
            existing_type=sa.LargeBinary(),
            nullable=True,
        )
        batch_op.add_column(sa.Column("lease_token_hash", sa.String(64), nullable=True))
        batch_op.add_column(sa.Column("lease_expires_at", sa.DateTime(timezone=True)))
        batch_op.add_column(sa.Column("result", sa.String(16), nullable=True))
        batch_op.add_column(sa.Column("invite_id", sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column("resulted_at", sa.DateTime(timezone=True)))
        batch_op.create_check_constraint(
            _LEASE_HASH_LENGTH,
            "lease_token_hash is null or length(lease_token_hash) = 64",
        )
        batch_op.create_check_constraint(
            _LEASE_COMPLETE,
            "(lease_token_hash is null) = (lease_expires_at is null)",
        )
        batch_op.create_check_constraint(
            _RESULT_VALUES,
            "result is null or result in ('matched', 'no_match', 'ineligible')",
        )
        batch_op.create_check_constraint(
            _RESULT_SHAPE,
            "(result is null and encrypted_payload is not null and encryption_nonce is not null "
            "and invite_id is null and resulted_at is null) or "
            "(result = 'matched' and encrypted_payload is null and encryption_nonce is null "
            "and invite_id is not null and invite_id > 0 and resulted_at is not null "
            "and lease_token_hash is not null) or "
            "(result in ('no_match', 'ineligible') and encrypted_payload is null "
            "and encryption_nonce is null and invite_id is null and resulted_at is not null "
            "and lease_token_hash is not null)",
        )

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint(_EVENT_CHECK, type_="check")
        batch_op.create_check_constraint(_EVENT_CHECK, f"event_type in ({_NEW_EVENT_TYPES})")


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0025 downgrade requires an online connection to check retained signup data"
        )
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        # Keep both retention decisions valid through the CHECK replacements.
        connection.execute(
            sa.text(
                "LOCK TABLE patient_portal_audit_events, patient_portal_signup_requests "
                "IN ACCESS EXCLUSIVE MODE"
            )
        )
    elif connection.dialect.name == "sqlite":
        # sqlite3's legacy transaction mode leaves SELECT/DDL outside a transaction.
        # Reserve the writer before reading.
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        raise RuntimeError("migration 0025 supports only SQLite and PostgreSQL")
    claim_events = connection.scalar(
        sa.text(
            "select count(*) from patient_portal_audit_events "
            "where event_type in ('signup.claim', 'signup.result')"
        )
    )
    if claim_events:
        # As in 0019: audit events are append-only, and the old constraint cannot hold these rows.
        raise RuntimeError(
            "cannot downgrade migration 0025 while sign-up claim or result audit events exist"
        )
    if connection.scalar(
        sa.text("select count(*) from patient_portal_signup_requests where result is not null")
    ):
        # A reported request has no details; the old schema requires them.
        raise RuntimeError(
            "cannot downgrade migration 0025 while reported sign-up requests exist"
        )

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint(_EVENT_CHECK, type_="check")
        batch_op.create_check_constraint(_EVENT_CHECK, f"event_type in ({_OLD_EVENT_TYPES})")

    with op.batch_alter_table(_SIGNUP_TABLE, recreate="always") as batch_op:
        batch_op.drop_constraint(_RESULT_SHAPE, type_="check")
        batch_op.drop_constraint(_RESULT_VALUES, type_="check")
        batch_op.drop_constraint(_LEASE_COMPLETE, type_="check")
        batch_op.drop_constraint(_LEASE_HASH_LENGTH, type_="check")
        batch_op.drop_column("resulted_at")
        batch_op.drop_column("invite_id")
        batch_op.drop_column("result")
        batch_op.drop_column("lease_expires_at")
        batch_op.drop_column("lease_token_hash")
        batch_op.alter_column(
            "encryption_nonce",
            existing_type=sa.LargeBinary(),
            nullable=False,
        )
        batch_op.alter_column(
            "encrypted_payload",
            existing_type=sa.LargeBinary(),
            nullable=False,
        )
