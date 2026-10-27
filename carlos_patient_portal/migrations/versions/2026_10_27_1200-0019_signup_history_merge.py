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

"""Converge both applied signup/job histories after mailbox approval.

This is a forward-only merge: both original revision IDs and parents remain valid.
All physical prerequisites are verified before changing the shared audit CHECK.
Missing/unknown schemas are refused, never stamped or repaired into a later state.

Revision ID: 0019_signup_history_merge
Revises: 0018_mycarlos_mailbox_approval, 0016_self_signup_requests
"""

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import context, op

from carlos_patient_portal.migrations._signup_history_schema_0019 import (
    EXPECTED_TABLE_HASHES,
    _namespace,
    verify_schema,
)

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0019_signup_history_merge",
    "down_revision": ("0018_mycarlos_mailbox_approval", "0016_self_signup_requests"),
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

_AUDIT_TYPES = frozenset(
    {
        "account.contact_update",
        "account.disable",
        "account.email_change_confirm",
        "account.email_change_request",
        "account.enable",
        "account.lock",
        "account.mfa_update",
        "account.password_change",
        "account.unlock",
        "activation",
        "booking_prompt.choice",
        "booking_prompt.create",
        "booking_prompt.decline",
        "booking_prompt.delivery",
        "booking_prompt.list",
        "booking_prompt.offer",
        "booking_prompt.read",
        "booking_prompt.result",
        "booking_prompt.withdraw",
        "fhir.read",
        "fhir.search",
        "invite.create",
        "invite.list",
        "invite.resend",
        "invite.revoke",
        "job.auth_refused",
        "login",
        "mfa.challenge",
        "mfa.delivery",
        "mfa.resend",
        "mfa.verify",
        "mycarlos.clinic_keys_publish",
        "mycarlos.device_list",
        "mycarlos.device_remove",
        "mycarlos.link",
        "mycarlos.link_code_create",
        "password_reset.complete",
        "password_reset.delivery",
        "password_reset.request",
        "retention.policy_override",
        "session.logout",
        "signup.request",
        "staff.action",
        "unlock_secret.create",
        "unlock_secret.list",
        "unlock_secret.publish",
        "unlock_secret.read",
        "unlock_secret.revoke",
    }
)
_UPSTREAM_ONLY_TYPES = _AUDIT_TYPES - {"signup.request"}
_SIGNUP_ONLY_TYPES = _AUDIT_TYPES - {
    "job.auth_refused",
    "mycarlos.clinic_keys_publish",
    "mycarlos.device_list",
    "mycarlos.device_remove",
    "mycarlos.link",
    "mycarlos.link_code_create",
}
_AUDIT_CHECK = "ck_patient_portal_audit_events_event_type"


def _audit_types(expression: str) -> frozenset[str]:
    # Reflection preserves IN on SQLite and reports PostgreSQL's equivalent =ANY(ARRAY).
    # Whitelist those shapes; recognizing the same literals in an OR-true CHECK is unsafe.
    values = re.findall(r"'([a-z][a-z_.]*)'", expression)
    remaining = re.sub(r"'([a-z][a-z_.]*)'", "?", expression)
    remaining = re.sub(r"::(?:character varying|text)(?:\[\])?", "", remaining)
    remaining = re.sub(r'[\s()\[\]" ]', "", remaining).lower()
    parameters = ",".join("?" for _ in values)
    if len(values) != len(set(values)) or remaining not in {
        "event_typein" + parameters,
        "event_type=anyarray" + parameters,
    }:
        raise RuntimeError("migration 0019 refuses an unknown audit CHECK expression")
    return frozenset(values)


def upgrade() -> None:
    if context.is_offline_mode():
        raise RuntimeError("migration 0019 requires an online connection to verify both histories")
    bind = op.get_bind()
    if bind.dialect.name not in {"sqlite", "postgresql"}:
        raise RuntimeError("migration 0019 supports only SQLite and PostgreSQL")
    schema = _namespace(bind)
    inspector = sa.inspect(bind)
    if set(inspector.get_table_names(schema=schema)) != set(
        EXPECTED_TABLE_HASHES[bind.dialect.name]
    ):
        raise RuntimeError("migration 0019 refuses missing or unexpected prerequisite tables")
    checks = inspector.get_check_constraints("patient_portal_audit_events", schema=schema)
    expressions = [item["sqltext"] for item in checks if item["name"] == _AUDIT_CHECK]
    if len(expressions) != 1:
        raise RuntimeError("migration 0019 refuses prerequisite audit CHECK drift")
    audit_types = _audit_types(expressions[0])
    if audit_types not in {_AUDIT_TYPES, _UPSTREAM_ONLY_TYPES, _SIGNUP_ONLY_TYPES}:
        raise RuntimeError("migration 0019 refuses an unknown audit event allowlist")
    verify_schema(bind)
    if audit_types != _AUDIT_TYPES:
        # Both old branches can already be stamped on an empty database. Reconcile only
        # their recognized final allowlists, after every physical prerequisite passed.
        with op.batch_alter_table(
            "patient_portal_audit_events",
            schema=schema if bind.dialect.name == "postgresql" else None,
        ) as batch_op:
            batch_op.drop_constraint(_AUDIT_CHECK, type_="check")
            batch_op.create_check_constraint(
                _AUDIT_CHECK,
                "event_type in (" + ", ".join(repr(t) for t in sorted(_AUDIT_TYPES)) + ")",
            )


def downgrade() -> None:
    # Unmerging would reintroduce two heads and incompatible historical audit policies.
    # Refuse immediately, including on an empty database; no retention decision is implied.
    raise RuntimeError("migration 0019 is forward-only; restore a compatible backup to roll back")
