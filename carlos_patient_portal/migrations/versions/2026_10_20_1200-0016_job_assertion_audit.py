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

"""Audit CARLOS job callers: the refused-call event and the signing key and nonce of each call.

CARLOS jobs (the booking sync now, self sign-up later) call the internal API with their own signed
`X-CARLOS-Job-Assertion` instead of posing as a CARLOS provider. Adds the `job.auth_refused` audit
event type, for a job call whose signature verified but was refused, and two nullable audit
columns: `assertion_key_id`, the key id that signed the call, and `assertion_id`, its one-time
assertion UUID. Existing rows keep both empty.

Revision ID: 0016_job_assertion_audit
Revises: 0015_booking_offered_slots
Create Date: 2026-10-20 12:00:00+00:00
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0016_job_assertion_audit",
    "down_revision": "0015_booking_offered_slots",
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_AUDIT_TABLE = "patient_portal_audit_events"

# Keep the sibling signup history valid when upgrading an already-applied branch.
_OLD_EVENT_TYPES = (
    "'activation', 'account.contact_update', 'account.disable', "
    "'account.email_change_confirm', 'account.email_change_request', "
    "'account.enable', 'account.lock', "
    "'account.mfa_update', 'account.password_change', 'account.unlock', "
    "'invite.create', 'invite.list', 'invite.resend', 'invite.revoke', "
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
    "'invite.create', 'invite.list', 'invite.resend', 'invite.revoke', ",
    "'invite.create', 'invite.list', 'invite.resend', 'invite.revoke', "
    "'job.auth_refused', ",
)
_KEY_ID_LENGTH_CHECK = "assertion_key_id is null or length(assertion_key_id) between 1 and 64"
_ASSERTION_ID_LENGTH_CHECK = "assertion_id is null or length(assertion_id) = 36"


def upgrade() -> None:
    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.add_column(sa.Column("assertion_key_id", sa.String(64), nullable=True))
        batch_op.add_column(sa.Column("assertion_id", sa.String(36), nullable=True))
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_NEW_EVENT_TYPES})",
        )
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_assertion_key_id_length",
            _KEY_ID_LENGTH_CHECK,
        )
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_assertion_id_length",
            _ASSERTION_ID_LENGTH_CHECK,
        )


def downgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError(
            "migration 0016 downgrade requires an online connection to check job audit rows"
        )
    connection = op.get_bind()
    job_rows = connection.scalar(
        sa.text(
            "select count(*) from patient_portal_audit_events where "
            "event_type = 'job.auth_refused' or assertion_key_id is not null "
            "or assertion_id is not null"
        )
    )
    if job_rows:
        # As in 0014 and 0015: audit events are append-only, the old constraint cannot hold the
        # new type, and dropping the columns would discard which key signed a job's call.
        raise RuntimeError(
            "cannot downgrade migration 0016 while job caller audit rows exist; archive or "
            "remove them under an approved retention procedure before retrying"
        )

    with op.batch_alter_table(_AUDIT_TABLE) as batch_op:
        batch_op.drop_constraint(
            "ck_patient_portal_audit_events_assertion_id_length",
            type_="check",
        )
        batch_op.drop_constraint(
            "ck_patient_portal_audit_events_assertion_key_id_length",
            type_="check",
        )
        batch_op.drop_constraint("ck_patient_portal_audit_events_event_type", type_="check")
        batch_op.create_check_constraint(
            "ck_patient_portal_audit_events_event_type",
            f"event_type in ({_OLD_EVENT_TYPES})",
        )
        batch_op.drop_column("assertion_id")
        batch_op.drop_column("assertion_key_id")
