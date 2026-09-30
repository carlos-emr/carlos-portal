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

"""Add offered times to booking prompts, and the patient's choice among them.

CARLOS can attach a short list of open times to a booking prompt. The patient picks one in the
portal, CARLOS polls for the choice, books it, and reports the result (carlos-portal#11). Adds the
offered-slot and choice tables, a keyed digest of the offer on the prompt for retry matching, the
`choice_pending`, `booked` and `declined_all` prompt statuses, a `booking_prompt_update` outbox kind
for the "there is an update" email, and the offer, choice, result and decline audit event types.

Revision ID: 0015_booking_offered_slots
Revises: 0014_booking_prompts
Create Date: 2026-09-30 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0015_booking_offered_slots",
    "down_revision": "0014_booking_prompts",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_OUTBOX_TABLE = "patient_portal_outbound_deliveries"
_AUDIT_TABLE = "patient_portal_audit_events"
_PROMPT_TABLE = "patient_portal_booking_prompts"
_SLOT_TABLE = "patient_portal_booking_offered_slots"
_CHOICE_TABLE = "patient_portal_booking_choices"

_OLD_PROMPT_STATUSES = "status in ('sent', 'read', 'withdrawn')"
_NEW_PROMPT_STATUSES = (
    "status in ('sent', 'read', 'withdrawn', 'choice_pending', 'booked', 'declined_all')"
)
_OLD_READ_AT = "status != 'read' or read_at is not null"
_NEW_READ_AT = (
    "status not in ('read', 'choice_pending', 'booked', 'declined_all') or read_at is not null"
)

_OLD_KINDS = (
    "kind in ('password_reset_request', 'password_reset', 'contact_change', 'booking_prompt')"
)
_NEW_KINDS = (
    "kind in ('password_reset_request', 'password_reset', 'contact_change', "
    "'booking_prompt', 'booking_prompt_update')"
)
_OLD_KIND_FIELDS = (
    "(kind = 'password_reset' and account_id is not null and reset_token_id is not null) or "
    "(kind = 'contact_change' and account_id is not null and reset_token_id is null) or "
    "(kind = 'password_reset_request' and account_id is null and reset_token_id is null) or "
    "(kind = 'booking_prompt' and account_id is not null and reset_token_id is null)"
)
_NEW_KIND_FIELDS = (
    "(kind = 'password_reset' and account_id is not null and reset_token_id is not null) or "
    "(kind = 'contact_change' and account_id is not null and reset_token_id is null) or "
    "(kind = 'password_reset_request' and account_id is null and reset_token_id is null) or "
    "(kind in ('booking_prompt', 'booking_prompt_update') and account_id is not null and "
    "reset_token_id is null)"
)
_OLD_BOOKING_PROMPT_KIND = "(kind = 'booking_prompt') = (booking_prompt_id is not null)"
_NEW_BOOKING_PROMPT_KIND = (
    "(kind in ('booking_prompt', 'booking_prompt_update')) = (booking_prompt_id is not null)"
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
    "'booking_prompt.create', 'booking_prompt.delivery', 'booking_prompt.list', "
    "'booking_prompt.read', 'booking_prompt.withdraw', "
    "'unlock_secret.create', 'unlock_secret.list', 'unlock_secret.read', "
    "'unlock_secret.publish', 'unlock_secret.revoke'"
)
_NEW_EVENT_TYPES = _OLD_EVENT_TYPES.replace(
    "'booking_prompt.read', 'booking_prompt.withdraw', ",
    "'booking_prompt.read', 'booking_prompt.withdraw', "
    "'booking_prompt.offer', 'booking_prompt.choice', 'booking_prompt.result', "
    "'booking_prompt.decline', ",
)

_SLOT_COPY_ABSENT = (
    "slot_id is null and starts_at is null and duration_minutes is null and "
    "visit_mode is null and location_code is null"
)
_SLOT_COPY_PRESENT = (
    "slot_id is not null and starts_at is not null and duration_minutes is not null and "
    "visit_mode is not null"
)


def upgrade() -> None:
    # The prompt table is altered before its new children exist, so SQLite's table rebuild has
    # fewer references to carry.
    with op.batch_alter_table(_PROMPT_TABLE) as batch_op:
        batch_op.add_column(sa.Column("offer_digest", sa.String(64), nullable=True))
        batch_op.drop_constraint("ck_pp_booking_prompts_status", type_="check")
        batch_op.drop_constraint("ck_pp_booking_prompts_read_at_present", type_="check")
        batch_op.create_check_constraint("ck_pp_booking_prompts_status", _NEW_PROMPT_STATUSES)
        batch_op.create_check_constraint("ck_pp_booking_prompts_read_at_present", _NEW_READ_AT)
        batch_op.create_check_constraint(
            "ck_pp_booking_prompts_offer_digest_length",
            "offer_digest is null or length(offer_digest) = 64",
        )

    op.create_table(
        _SLOT_TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "prompt_id",
            sa.Integer(),
            sa.ForeignKey(
                f"{_PROMPT_TABLE}.id",
                ondelete="CASCADE",
                name="fk_pp_booking_offered_slots_prompt",
            ),
            nullable=False,
        ),
        sa.Column("position", sa.Integer(), nullable=False),
        sa.Column("slot_id", sa.String(64), nullable=False),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("duration_minutes", sa.Integer(), nullable=False),
        sa.Column("visit_mode", sa.String(16), nullable=False),
        sa.Column("location_code", sa.String(32), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint("position >= 0", name="ck_pp_booking_offered_slots_position"),
        sa.CheckConstraint(
            "length(slot_id) between 1 and 64",
            name="ck_pp_booking_offered_slots_slot_id_length",
        ),
        sa.CheckConstraint(
            "duration_minutes between 5 and 480",
            name="ck_pp_booking_offered_slots_duration",
        ),
        sa.CheckConstraint(
            "visit_mode in ('in_person', 'phone', 'video')",
            name="ck_pp_booking_offered_slots_visit_mode",
        ),
        sa.CheckConstraint(
            "location_code is null or length(location_code) between 1 and 32",
            name="ck_pp_booking_offered_slots_location_code_length",
        ),
    )
    op.create_index(
        "ux_pp_booking_offered_slots_prompt_slot",
        _SLOT_TABLE,
        ["prompt_id", "slot_id"],
        unique=True,
    )
    op.create_index(
        "ux_pp_booking_offered_slots_prompt_position",
        _SLOT_TABLE,
        ["prompt_id", "position"],
        unique=True,
    )
    op.create_index("ix_pp_booking_offered_slots_starts", _SLOT_TABLE, ["starts_at"])

    op.create_table(
        _CHOICE_TABLE,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "prompt_id",
            sa.Integer(),
            sa.ForeignKey(
                f"{_PROMPT_TABLE}.id",
                ondelete="CASCADE",
                name="fk_pp_booking_choices_prompt",
            ),
            nullable=False,
        ),
        sa.Column("clinic_id", sa.String(64), nullable=False),
        sa.Column("slot_id", sa.String(64), nullable=True),
        sa.Column("starts_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("duration_minutes", sa.Integer(), nullable=True),
        sa.Column("visit_mode", sa.String(16), nullable=True),
        sa.Column("location_code", sa.String(32), nullable=True),
        sa.Column("state", sa.String(16), nullable=False),
        sa.Column("chosen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("result_at", sa.DateTime(timezone=True), nullable=True),
        sa.CheckConstraint(
            "length(clinic_id) between 1 and 64",
            name="ck_pp_booking_choices_clinic_id_length",
        ),
        sa.CheckConstraint(
            "state in ('pending', 'booked', 'slot_unavailable', 'withdrawn')",
            name="ck_pp_booking_choices_state",
        ),
        sa.CheckConstraint(
            f"({_SLOT_COPY_ABSENT}) or ({_SLOT_COPY_PRESENT})",
            name="ck_pp_booking_choices_slot_copy_complete",
        ),
        sa.CheckConstraint(
            "state != 'pending' or slot_id is not null",
            name="ck_pp_booking_choices_pending_has_slot",
        ),
        sa.CheckConstraint(
            "(state = 'pending' and result_at is null) or "
            "(state != 'pending' and result_at is not null)",
            name="ck_pp_booking_choices_result_at_matches_state",
        ),
        sa.CheckConstraint(
            "slot_id is null or length(slot_id) between 1 and 64",
            name="ck_pp_booking_choices_slot_id_length",
        ),
        sa.CheckConstraint(
            "duration_minutes is null or duration_minutes between 5 and 480",
            name="ck_pp_booking_choices_duration",
        ),
        sa.CheckConstraint(
            "visit_mode is null or visit_mode in ('in_person', 'phone', 'video')",
            name="ck_pp_booking_choices_visit_mode",
        ),
        sa.CheckConstraint(
            "location_code is null or length(location_code) between 1 and 32",
            name="ck_pp_booking_choices_location_code_length",
        ),
    )
    op.create_index("ix_pp_booking_choices_prompt", _CHOICE_TABLE, ["prompt_id", "id"])
    op.create_index(
        "ux_pp_booking_choices_pending_prompt",
        _CHOICE_TABLE,
        ["prompt_id"],
        unique=True,
        sqlite_where=sa.text("state = 'pending'"),
        postgresql_where=sa.text("state = 'pending'"),
    )
    op.create_index(
        "ix_pp_booking_choices_clinic_state_chosen",
        _CHOICE_TABLE,
        ["clinic_id", "state", "chosen_at"],
    )
    op.create_index(
        "ix_pp_booking_choices_state_starts",
        _CHOICE_TABLE,
        ["state", "starts_at"],
    )

    with op.batch_alter_table(_OUTBOX_TABLE) as batch_op:
        batch_op.drop_constraint("ck_pp_outbound_delivery_booking_prompt_kind", type_="check")
        batch_op.drop_constraint("ck_pp_outbound_delivery_reset_token_kind", type_="check")
        batch_op.drop_constraint("ck_pp_outbound_delivery_kind", type_="check")
        batch_op.create_check_constraint("ck_pp_outbound_delivery_kind", _NEW_KINDS)
        batch_op.create_check_constraint(
            "ck_pp_outbound_delivery_reset_token_kind",
            _NEW_KIND_FIELDS,
        )
        batch_op.create_check_constraint(
            "ck_pp_outbound_delivery_booking_prompt_kind",
            _NEW_BOOKING_PROMPT_KIND,
        )

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_NEW_EVENT_TYPES})",
        )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0015 downgrade requires an online connection to check booking choice rows"
        )
    connection = op.get_bind()
    choice_events = connection.scalar(
        sa.text(
            "select count(*) from patient_portal_audit_events where event_type in "
            "('booking_prompt.offer', 'booking_prompt.choice', 'booking_prompt.result', "
            "'booking_prompt.decline')"
        )
    )
    if choice_events:
        # As in 0014: audit events are append-only, and the old constraint cannot hold these.
        raise RuntimeError(
            "cannot downgrade migration 0015 while offered-time audit events exist"
        )
    new_statuses = connection.scalar(
        sa.text(
            "select count(*) from patient_portal_booking_prompts "
            "where status in ('choice_pending', 'booked', 'declined_all')"
        )
    )
    if new_statuses:
        # Folding a booked or declined prompt back to `read` would tell staff the patient has not
        # answered, so the downgrade is refused rather than rewriting what happened.
        raise RuntimeError(
            "cannot downgrade migration 0015 while prompts are choice_pending, booked or "
            "declined_all"
        )

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_OLD_EVENT_TYPES})",
        )

    # Update notices are delivery plumbing, not a record.
    op.execute(
        sa.text(
            "delete from patient_portal_outbound_deliveries where kind = 'booking_prompt_update'"
        )
    )
    with op.batch_alter_table(_OUTBOX_TABLE) as batch_op:
        batch_op.drop_constraint("ck_pp_outbound_delivery_booking_prompt_kind", type_="check")
        batch_op.drop_constraint("ck_pp_outbound_delivery_reset_token_kind", type_="check")
        batch_op.drop_constraint("ck_pp_outbound_delivery_kind", type_="check")
        batch_op.create_check_constraint("ck_pp_outbound_delivery_kind", _OLD_KINDS)
        batch_op.create_check_constraint(
            "ck_pp_outbound_delivery_reset_token_kind",
            _OLD_KIND_FIELDS,
        )
        batch_op.create_check_constraint(
            "ck_pp_outbound_delivery_booking_prompt_kind",
            _OLD_BOOKING_PROMPT_KIND,
        )

    op.drop_index("ix_pp_booking_choices_state_starts", table_name=_CHOICE_TABLE)
    op.drop_index("ix_pp_booking_choices_clinic_state_chosen", table_name=_CHOICE_TABLE)
    op.drop_index("ux_pp_booking_choices_pending_prompt", table_name=_CHOICE_TABLE)
    op.drop_index("ix_pp_booking_choices_prompt", table_name=_CHOICE_TABLE)
    op.drop_table(_CHOICE_TABLE)
    op.drop_index("ix_pp_booking_offered_slots_starts", table_name=_SLOT_TABLE)
    op.drop_index("ux_pp_booking_offered_slots_prompt_position", table_name=_SLOT_TABLE)
    op.drop_index("ux_pp_booking_offered_slots_prompt_slot", table_name=_SLOT_TABLE)
    op.drop_table(_SLOT_TABLE)

    with op.batch_alter_table(_PROMPT_TABLE) as batch_op:
        batch_op.drop_constraint("ck_pp_booking_prompts_offer_digest_length", type_="check")
        batch_op.drop_constraint("ck_pp_booking_prompts_read_at_present", type_="check")
        batch_op.drop_constraint("ck_pp_booking_prompts_status", type_="check")
        batch_op.drop_column("offer_digest")
        batch_op.create_check_constraint("ck_pp_booking_prompts_status", _OLD_PROMPT_STATUSES)
        batch_op.create_check_constraint("ck_pp_booking_prompts_read_at_present", _OLD_READ_AT)
