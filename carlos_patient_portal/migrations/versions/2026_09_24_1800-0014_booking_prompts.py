# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
#
# This software is published under the GPL GNU General Public License.
# You can redistribute it and/or modify it under the terms published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.

"""Add booking prompts: a clinic's request that a patient book an appointment.

Adds the prompt table, a `booking_prompt` outbox kind for the "message waiting" email linked to
its prompt, and the prompt audit event types.

Revision ID: 0014_booking_prompts
Revises: 0013_drop_redundant_pending_idx
Create Date: 2026-09-24 18:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0014_booking_prompts",
    "down_revision": "0013_drop_redundant_pending_idx",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_OUTBOX_TABLE = "patient_portal_outbound_deliveries"
_AUDIT_TABLE = "patient_portal_audit_events"
_PROMPT_TABLE = "patient_portal_booking_prompts"

_KINDS = (
    "kind in ('password_reset_request', 'password_reset', 'contact_change', 'booking_prompt')"
)
_KIND_FIELDS = (
    "(kind = 'password_reset' and account_id is not null and reset_token_id is not null) or "
    "(kind = 'contact_change' and account_id is not null and reset_token_id is null) or "
    "(kind = 'password_reset_request' and account_id is null and reset_token_id is null) or "
    "(kind = 'booking_prompt' and account_id is not null and reset_token_id is null)"
)
_BOOKING_PROMPT_KIND = "(kind = 'booking_prompt') = (booking_prompt_id is not null)"
_OLD_KINDS = "kind in ('password_reset_request', 'password_reset', 'contact_change')"
_OLD_KIND_FIELDS = (
    "(kind = 'password_reset' and account_id is not null and reset_token_id is not null) or "
    "(kind = 'contact_change' and account_id is not null and reset_token_id is null) or "
    "(kind = 'password_reset_request' and account_id is null and reset_token_id is null)"
)

_OLD_EVENT_TYPES = (
    "'activation', 'account.contact_update', 'account.disable', "
    "'account.email_change_confirm', 'account.email_change_request', "
    "'account.enable', 'account.lock', "
    "'account.mfa_update', 'account.password_change', 'account.unlock', "
    "'invite.create', 'invite.list', 'invite.resend', 'invite.revoke', "
    "'login', 'mfa.challenge', 'mfa.delivery', 'mfa.resend', 'mfa.verify', "
    "'password_reset.complete', 'password_reset.delivery', "
    "'password_reset.request', 'retention.policy_override', 'session.logout', "
    "'staff.action', "
    "'fhir.read', 'fhir.search', "
    "'unlock_secret.create', 'unlock_secret.list', 'unlock_secret.read', "
    "'unlock_secret.publish', 'unlock_secret.revoke'"
)
_NEW_EVENT_TYPES = _OLD_EVENT_TYPES.replace(
    "'fhir.read', 'fhir.search', ",
    "'fhir.read', 'fhir.search', "
    "'booking_prompt.create', 'booking_prompt.delivery', 'booking_prompt.list', "
    "'booking_prompt.read', 'booking_prompt.withdraw', ",
)


def upgrade() -> None:
    op.create_table(
        _PROMPT_TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("clinic_id", sa.String(64), nullable=False),
        sa.Column("demographic_no", sa.Integer(), nullable=False),
        sa.Column(
            "account_id",
            sa.Integer(),
            sa.ForeignKey("patient_portal_accounts.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("operation_id", sa.String(64), nullable=False),
        sa.Column("urgency", sa.String(32), nullable=False),
        sa.Column("appointment_type", sa.String(32), nullable=False),
        sa.Column("suggested_by", sa.String(128), nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("created_by", sa.String(128), nullable=False),
        sa.Column("created_by_id", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("notified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("read_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("withdrawn_by", sa.String(128), nullable=True),
        sa.Column("withdrawn_by_id", sa.String(128), nullable=True),
        sa.CheckConstraint(
            "length(clinic_id) between 1 and 64",
            name="ck_pp_booking_prompts_clinic_id_length",
        ),
        sa.CheckConstraint(
            "demographic_no > 0",
            name="ck_pp_booking_prompts_demographic_no_positive",
        ),
        sa.CheckConstraint(
            "length(operation_id) between 1 and 64",
            name="ck_pp_booking_prompts_operation_id_length",
        ),
        sa.CheckConstraint(
            "urgency in ('routine', 'soon', 'as_soon_as_possible')",
            name="ck_pp_booking_prompts_urgency",
        ),
        sa.CheckConstraint(
            "appointment_type in ('follow_up', 'annual_exam', 'lab_review')",
            name="ck_pp_booking_prompts_appointment_type",
        ),
        sa.CheckConstraint(
            "status in ('sent', 'read', 'withdrawn')",
            name="ck_pp_booking_prompts_status",
        ),
        sa.CheckConstraint(
            "suggested_by is null or length(suggested_by) between 1 and 128",
            name="ck_pp_booking_prompts_suggested_by_length",
        ),
        sa.CheckConstraint(
            "length(created_by) between 1 and 128",
            name="ck_pp_booking_prompts_created_by_length",
        ),
        sa.CheckConstraint(
            "expires_at > created_at",
            name="ck_pp_booking_prompts_expiry_after_creation",
        ),
        sa.CheckConstraint(
            "status != 'read' or read_at is not null",
            name="ck_pp_booking_prompts_read_at_present",
        ),
        sa.CheckConstraint(
            "status != 'sent' or read_at is null",
            name="ck_pp_booking_prompts_sent_is_unread",
        ),
        sa.CheckConstraint(
            "(status = 'withdrawn' and withdrawn_at is not null and withdrawn_by is not null) or "
            "(status != 'withdrawn' and withdrawn_at is null and withdrawn_by is null and "
            "withdrawn_by_id is null)",
            name="ck_pp_booking_prompts_withdrawn_fields",
        ),
    )
    op.create_index(
        "ux_pp_booking_prompts_clinic_operation",
        _PROMPT_TABLE,
        ["clinic_id", "operation_id"],
        unique=True,
    )
    op.create_index(
        "ix_pp_booking_prompts_clinic_patient_created",
        _PROMPT_TABLE,
        ["clinic_id", "demographic_no", "created_at"],
    )
    op.create_index(
        "ix_pp_booking_prompts_account_status_expires",
        _PROMPT_TABLE,
        ["account_id", "status", "expires_at"],
    )
    op.create_index("ix_pp_booking_prompts_expires", _PROMPT_TABLE, ["expires_at"])

    with op.batch_alter_table(_OUTBOX_TABLE) as batch_op:
        batch_op.add_column(sa.Column("booking_prompt_id", sa.Integer(), nullable=True))
        batch_op.create_foreign_key(
            "fk_pp_outbound_delivery_booking_prompt",
            _PROMPT_TABLE,
            ["booking_prompt_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.drop_constraint("ck_pp_outbound_delivery_kind", type_="check")
        batch_op.drop_constraint("ck_pp_outbound_delivery_reset_token_kind", type_="check")
        batch_op.create_check_constraint("ck_pp_outbound_delivery_kind", _KINDS)
        batch_op.create_check_constraint("ck_pp_outbound_delivery_reset_token_kind", _KIND_FIELDS)
        batch_op.create_check_constraint(
            "ck_pp_outbound_delivery_booking_prompt_kind",
            _BOOKING_PROMPT_KIND,
        )
        batch_op.create_index("ix_pp_outbound_delivery_booking_prompt", ["booking_prompt_id"])

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_NEW_EVENT_TYPES})",
        )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0014 downgrade requires an online connection to check booking prompt rows"
        )
    connection = op.get_bind()
    prompt_events = connection.scalar(
        sa.text(
            "select count(*) from patient_portal_audit_events "
            "where event_type like 'booking_prompt.%'"
        )
    )
    if prompt_events:
        # Audit events are append-only; the old constraint cannot hold them, and deleting them to
        # make room would destroy the record. Downgrading past booking prompts is refused instead.
        raise RuntimeError(
            "cannot downgrade migration 0014 while booking prompt audit events exist"
        )

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_OLD_EVENT_TYPES})",
        )

    # Notices are delivery plumbing, not a record; the prompts they point at are dropped below.
    op.execute(
        sa.text("delete from patient_portal_outbound_deliveries where kind = 'booking_prompt'")
    )
    with op.batch_alter_table(_OUTBOX_TABLE) as batch_op:
        batch_op.drop_index("ix_pp_outbound_delivery_booking_prompt")
        batch_op.drop_constraint("ck_pp_outbound_delivery_booking_prompt_kind", type_="check")
        batch_op.drop_constraint("ck_pp_outbound_delivery_reset_token_kind", type_="check")
        batch_op.drop_constraint("ck_pp_outbound_delivery_kind", type_="check")
        batch_op.drop_constraint("fk_pp_outbound_delivery_booking_prompt", type_="foreignkey")
        batch_op.drop_column("booking_prompt_id")
        batch_op.create_check_constraint("ck_pp_outbound_delivery_kind", _OLD_KINDS)
        batch_op.create_check_constraint(
            "ck_pp_outbound_delivery_reset_token_kind",
            _OLD_KIND_FIELDS,
        )

    op.drop_index("ix_pp_booking_prompts_expires", table_name=_PROMPT_TABLE)
    op.drop_index("ix_pp_booking_prompts_account_status_expires", table_name=_PROMPT_TABLE)
    op.drop_index("ix_pp_booking_prompts_clinic_patient_created", table_name=_PROMPT_TABLE)
    op.drop_index("ux_pp_booking_prompts_clinic_operation", table_name=_PROMPT_TABLE)
    op.drop_table(_PROMPT_TABLE)
