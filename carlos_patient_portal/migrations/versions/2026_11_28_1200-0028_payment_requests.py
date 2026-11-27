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

"""Payment requests (billing through the portal, Phase 0).

A clinic asks a patient to pay an amount it recorded in CARLOS. The table holds only an opaque
invoice reference, the amount due now in cents with its tax portion, a category from a closed
vocabulary, how the patient is told to pay, a due date and a status: no description, no patient
name, no free text. The portal takes no payment; staff record it in CARLOS, which tells the portal
the request is paid.

The audit event-type CHECK is rewritten from the list 0025 left, with the five payment request
types added. Downgrade is refused while a payment request or an audit event of the new types
exists: the old schema cannot hold them.

Revision ID: 0028_payment_requests
Revises: 0027_mfa_resumed_outcome
Create Date: 2026-11-28 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0028_payment_requests",
    "down_revision": "0027_mfa_resumed_outcome",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_AUDIT_TABLE = "patient_portal_audit_events"
_TABLE = "patient_portal_payment_requests"
_EVENT_CHECK = "ck_patient_portal_audit_events_event_type"

# The policy 0025 left, unchanged since.
_OLD_EVENT_TYPES = (
    "'activation', 'account.contact_update', 'account.disable', "
    "'account.email_change_confirm', 'account.email_change_request', "
    "'account.enable', 'account.lock', "
    "'account.mfa_update', 'account.password_change', 'account.unlock', "
    "'invite.create', 'invite.list', 'invite.resend', 'invite.revoke', "
    "'job.auth_refused', "
    "'mycarlos.clinic_keys_publish', 'mycarlos.device_list', "
    "'mycarlos.device_remove', 'mycarlos.link', 'mycarlos.link_code_create', "
    "'login', 'mfa.challenge', 'mfa.delivery', 'mfa.resend', 'mfa.verify', "
    "'password_reset.complete', 'password_reset.delivery', "
    "'password_reset.request', 'retention.policy_override', 'session.logout', "
    "'signup.request', 'signup.claim', 'signup.result', "
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
    "'booking_prompt.decline', ",
    "'booking_prompt.decline', "
    "'payment_request.create', 'payment_request.list', 'payment_request.paid', "
    "'payment_request.read', 'payment_request.withdraw', ",
)


def upgrade() -> None:
    op.create_table(
        _TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("clinic_id", sa.String(64), nullable=False),
        sa.Column("demographic_no", sa.Integer(), nullable=False),
        sa.Column("account_id", sa.Integer(), nullable=False),
        sa.Column("operation_id", sa.String(64), nullable=False),
        sa.Column("invoice_ref", sa.String(64), nullable=False),
        sa.Column("category", sa.String(32), nullable=False),
        sa.Column("payment_method", sa.String(32), nullable=False),
        sa.Column("currency", sa.String(3), nullable=False),
        sa.Column("amount_cents", sa.Integer(), nullable=False),
        sa.Column("tax_cents", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_by_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("due_on", sa.Date(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("paid_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn_by", sa.String(128), nullable=True),
        sa.Column("withdrawn_by_id", sa.String(128), nullable=True),
        sa.ForeignKeyConstraint(["account_id"], ["patient_portal_accounts.id"], ondelete="CASCADE"),
        sa.CheckConstraint(
            "length(clinic_id) between 1 and 64", name="ck_pp_payment_requests_clinic_id_length"
        ),
        sa.CheckConstraint(
            "demographic_no > 0", name="ck_pp_payment_requests_demographic_no_positive"
        ),
        sa.CheckConstraint(
            "length(operation_id) between 1 and 64",
            name="ck_pp_payment_requests_operation_id_length",
        ),
        sa.CheckConstraint(
            "length(invoice_ref) between 1 and 64",
            name="ck_pp_payment_requests_invoice_ref_length",
        ),
        sa.CheckConstraint(
            "category in ('uninsured_service', 'form_or_note', 'missed_appointment', 'other')",
            name="ck_pp_payment_requests_category",
        ),
        sa.CheckConstraint(
            "payment_method in ('clinic_instructions')",
            name="ck_pp_payment_requests_payment_method",
        ),
        sa.CheckConstraint("currency = 'CAD'", name="ck_pp_payment_requests_currency"),
        sa.CheckConstraint(
            "amount_cents between 1 and 10000000", name="ck_pp_payment_requests_amount"
        ),
        sa.CheckConstraint(
            "tax_cents >= 0 and tax_cents <= amount_cents", name="ck_pp_payment_requests_tax"
        ),
        sa.CheckConstraint(
            "status in ('sent', 'read', 'paid', 'withdrawn')",
            name="ck_pp_payment_requests_status",
        ),
        sa.CheckConstraint(
            "length(created_by) between 1 and 128",
            name="ck_pp_payment_requests_created_by_length",
        ),
        sa.CheckConstraint(
            "expires_at > created_at", name="ck_pp_payment_requests_expiry_after_creation"
        ),
        sa.CheckConstraint(
            "status != 'read' or read_at is not null",
            name="ck_pp_payment_requests_read_at_present",
        ),
        sa.CheckConstraint(
            "status != 'sent' or read_at is null", name="ck_pp_payment_requests_sent_is_unread"
        ),
        sa.CheckConstraint(
            "(status = 'withdrawn' and withdrawn_at is not null and withdrawn_by is not null) or "
            "(status != 'withdrawn' and withdrawn_at is null and withdrawn_by is null and "
            "withdrawn_by_id is null)",
            name="ck_pp_payment_requests_withdrawn_fields",
        ),
        sa.CheckConstraint(
            "(status = 'paid' and paid_at is not null) or (status != 'paid' and paid_at is null)",
            name="ck_pp_payment_requests_paid_fields",
        ),
    )
    op.create_index(
        "ux_pp_payment_requests_clinic_operation",
        _TABLE,
        ["clinic_id", "operation_id"],
        unique=True,
    )
    op.create_index(
        "ux_pp_payment_requests_clinic_invoice_ref",
        _TABLE,
        ["clinic_id", "invoice_ref"],
        unique=True,
    )
    op.create_index(
        "ix_pp_payment_requests_clinic_patient_created",
        _TABLE,
        ["clinic_id", "demographic_no", "created_at"],
    )
    op.create_index(
        "ix_pp_payment_requests_account_status_expires",
        _TABLE,
        ["account_id", "status", "expires_at"],
    )

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint(_EVENT_CHECK, type_="check")
        batch_op.create_check_constraint(_EVENT_CHECK, f"event_type in ({_NEW_EVENT_TYPES})")


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0028 downgrade requires an online connection to check retained rows"
        )
    connection = op.get_bind()
    if connection.dialect.name == "postgresql":
        connection.execute(
            sa.text("LOCK TABLE patient_portal_audit_events IN ACCESS EXCLUSIVE MODE")
        )
    elif connection.dialect.name == "sqlite":
        if not connection.connection.driver_connection.in_transaction:
            connection.exec_driver_sql("BEGIN IMMEDIATE")
    else:
        raise RuntimeError("migration 0028 supports only SQLite and PostgreSQL")
    # `_TABLE` is a module constant, not input.
    if connection.scalar(sa.text(f"select count(*) from {_TABLE}")):  # noqa: S608
        raise RuntimeError("cannot downgrade migration 0028 while payment requests exist")
    if connection.scalar(
        sa.text(
            "select count(*) from patient_portal_audit_events "
            "where event_type like 'payment_request.%'"
        )
    ):
        raise RuntimeError(
            "cannot downgrade migration 0028 while payment request audit events exist"
        )

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint(_EVENT_CHECK, type_="check")
        batch_op.create_check_constraint(_EVENT_CHECK, f"event_type in ({_OLD_EVENT_TYPES})")
    op.drop_index("ix_pp_payment_requests_account_status_expires", table_name=_TABLE)
    op.drop_index("ix_pp_payment_requests_clinic_patient_created", table_name=_TABLE)
    op.drop_index("ux_pp_payment_requests_clinic_invoice_ref", table_name=_TABLE)
    op.drop_index("ux_pp_payment_requests_clinic_operation", table_name=_TABLE)
    op.drop_table(_TABLE)
