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
from sqlalchemy.dialects.sqlite import dialect as sqlite_dialect

_ALEMBIC_REVISION_IDENTIFIERS: dict[str, str | Sequence[str] | None] = {
    "revision": "0019_signup_history_merge",
    "down_revision": ("0018_mycarlos_mailbox_approval", "0016_self_signup_requests"),
    "branch_labels": None,
    "depends_on": None,
}
globals().update(_ALEMBIC_REVISION_IDENTIFIERS)

# Frozen parent schema, not imports from models that may gain columns in later revisions.
# Each column is name=portable-type, with ? only for nullable columns.
_REQUIRED_COLUMNS = {
    "patient_portal_accounts": (
        "clinic_id=VARCHAR(64) created_at=DATETIME demographic_no=INTEGER disabled_at=DATETIME? "
        "disabled_by=VARCHAR(128)? disabled_by_id=VARCHAR(128)? disabled_reason=VARCHAR(64)? "
        "email=VARCHAR(254) failed_login_count=INTEGER failed_mfa_count=INTEGER "
        "force_password_reset=BOOLEAN id=INTEGER last_login_at=DATETIME? "
        "last_mfa_email_sent_at=DATETIME? last_mfa_sms_sent_at=DATETIME? locked_at=DATETIME? "
        "locked_by=VARCHAR(128)? locked_by_id=VARCHAR(128)? password_hash=VARCHAR(512) "
        "password_updated_at=DATETIME phone_number=VARCHAR(32)? preferred_mfa_method=VARCHAR(8) "
        "status=VARCHAR(16) updated_at=DATETIME username=VARCHAR(64) "
    ),
    "patient_portal_audit_events": (
        "account_id=INTEGER? actor=VARCHAR(128)? actor_id=VARCHAR(128)? actor_type=VARCHAR(16) "
        "assertion_id=VARCHAR(36)? assertion_key_id=VARCHAR(64)? "
        "client_reference_hash=VARCHAR(64)? "
        "clinic_id=VARCHAR(64)? created_at=DATETIME demographic_no=INTEGER? event_type=VARCHAR(64) "
        "id=INTEGER invite_id=INTEGER? invite_token_hash=VARCHAR(64)? outcome=VARCHAR(16) "
        "reason=VARCHAR(64)? resource_id=VARCHAR(128)? resource_type=VARCHAR(64)? "
    ),
    "patient_portal_booking_choices": (
        "chosen_at=DATETIME clinic_id=VARCHAR(64) duration_minutes=INTEGER? id=INTEGER "
        "location_code=VARCHAR(32)? prompt_id=INTEGER result_at=DATETIME? slot_id=VARCHAR(64)? "
        "starts_at=DATETIME? state=VARCHAR(16) visit_mode=VARCHAR(16)? "
    ),
    "patient_portal_booking_offered_slots": (
        "created_at=DATETIME duration_minutes=INTEGER id=INTEGER location_code=VARCHAR(32)? "
        "position=INTEGER prompt_id=INTEGER slot_id=VARCHAR(64) starts_at=DATETIME "
        "visit_mode=VARCHAR(16) "
    ),
    "patient_portal_booking_prompts": (
        "account_id=INTEGER appointment_type=VARCHAR(32) clinic_id=VARCHAR(64) created_at=DATETIME "
        "created_by=VARCHAR(128) created_by_id=VARCHAR(128)? demographic_no=INTEGER "
        "expires_at=DATETIME id=INTEGER notified_at=DATETIME? offer_digest=VARCHAR(64)? "
        "operation_id=VARCHAR(64) read_at=DATETIME? status=VARCHAR(16) suggested_by=VARCHAR(128)? "
        "urgency=VARCHAR(32) withdrawn_at=DATETIME? withdrawn_by=VARCHAR(128)? "
        "withdrawn_by_id=VARCHAR(128)? "
    ),
    "patient_portal_clinic_keys": (
        "clinic_id=VARCHAR(64) kid=VARCHAR(43) published_at=DATETIME replacement_signature=BLOB? "
        "replaces_kid=VARCHAR(43)? revoked_at=DATETIME? spki=BLOB status=VARCHAR(16) "
    ),
    "patient_portal_contact_review_requests": (
        "account_id=INTEGER clinic_id=VARCHAR(64) demographic_no=INTEGER email_after=VARCHAR(254) "
        "email_before=VARCHAR(254) id=INTEGER phone_number_after=VARCHAR(32)? "
        "phone_number_before=VARCHAR(32)? requested_at=DATETIME review_decision=VARCHAR(16)? "
        "reviewed_at=DATETIME? reviewed_by=VARCHAR(128)? reviewed_by_id=VARCHAR(128)? "
        "revision=VARCHAR(64) status=VARCHAR(16) "
    ),
    "patient_portal_email_change_requests": (
        "account_id=INTEGER confirmed_at=DATETIME? created_at=DATETIME "
        "email_confirmed_at=DATETIME? "
        "expires_at=DATETIME id=INTEGER new_email=VARCHAR(254) new_phone_number=VARCHAR(32)? "
        "phone_code_hash=VARCHAR(64)? phone_code_sent_at=DATETIME? phone_confirmed_at=DATETIME? "
        "phone_failed_attempts=INTEGER status=VARCHAR(16) token_hash=VARCHAR(64) "
    ),
    "patient_portal_invites": (
        "accepted_account_id=INTEGER? accepted_at=DATETIME? clinic_id=VARCHAR(64) "
        "created_at=DATETIME created_by=VARCHAR(128) created_by_id=VARCHAR(128)? "
        "delivery_operation_id=VARCHAR(64)? delivery_reference=VARCHAR(128)? "
        "demographic_no=INTEGER "
        "encrypted_invite_token=BLOB? expires_at=DATETIME id=INTEGER "
        "invite_token_key_id=VARCHAR(64)? invite_token_nonce=BLOB? last_sent_at=DATETIME "
        "last_sent_by=VARCHAR(128) last_sent_by_id=VARCHAR(128)? "
        "proof_date_of_birth_hash=VARCHAR(64)? proof_email_hash=VARCHAR(64)? "
        "proof_hash_version=VARCHAR(16)? proof_health_card_hash=VARCHAR(64)? "
        "proof_salt=VARCHAR(64)? revoked_at=DATETIME? revoked_by=VARCHAR(128)? "
        "revoked_by_id=VARCHAR(128)? sent_count=INTEGER status=VARCHAR(16) "
        "supersedes_invite_id=INTEGER? token_hash=VARCHAR(64) updated_at=DATETIME "
    ),
    "patient_portal_mfa_challenges": (
        "account_id=INTEGER challenge_token_hash=VARCHAR(64) code_hash=VARCHAR(64) "
        "created_at=DATETIME delivery_method=VARCHAR(8) expires_at=DATETIME "
        "failed_attempts=INTEGER "
        "id=INTEGER last_email_sent_at=DATETIME? last_sms_sent_at=DATETIME? status=VARCHAR(16) "
        "updated_at=DATETIME verified_at=DATETIME? "
    ),
    "patient_portal_mycarlos_approval_clinics": (
        "approval_sequence=BIGINT challenge_sequence=BIGINT clinic_id=VARCHAR(64) "
        "request_sequence=BIGINT "
    ),
    "patient_portal_mycarlos_approval_requests": (
        "acceptance=TEXT? account_id=INTEGER approval=TEXT? approval_sequence=BIGINT? "
        "candidate_kid=VARCHAR(43) challenge=TEXT? challenge_id=VARCHAR(43)? "
        "challenge_sequence=BIGINT? clinic_id=VARCHAR(64) decision_body_hash=VARCHAR(64)? "
        "demographic_no=INTEGER device_id=INTEGER expires_at=BIGINT intent=TEXT "
        "intent_body_hash=VARCHAR(64) predecessor_kid=VARCHAR(43)? reason=VARCHAR(40)? "
        "recipient_id=VARCHAR(64) request_id=VARCHAR(36) request_sequence=BIGINT "
        "status=VARCHAR(20) "
    ),
    "patient_portal_mycarlos_devices": (
        "account_id=INTEGER device_key_id=VARCHAR(43) device_name=VARCHAR(64) "
        "ed25519_public_key=BLOB id=INTEGER last_seen_at=DATETIME? linked_at=DATETIME "
        "removed_at=DATETIME? removed_by=VARCHAR(16)? status=VARCHAR(16) "
        "vault_head_link=VARCHAR(64)? vault_head_link_at=DATETIME? x25519_public_key=BLOB "
    ),
    "patient_portal_mycarlos_link_codes": (
        "account_id=INTEGER code_hash=VARCHAR(64) created_at=DATETIME device_id=INTEGER? "
        "expires_at=DATETIME id=INTEGER link_id=VARCHAR(8) session_id=INTEGER status=VARCHAR(16) "
        "used_at=DATETIME? wrong_codes=INTEGER "
    ),
    "patient_portal_mycarlos_link_failures": (
        "account_id=INTEGER failed_at=DATETIME id=INTEGER link_id=VARCHAR(8) "
    ),
    "patient_portal_mycarlos_mailbox_accounts": (
        "account_id=INTEGER waiting_bytes=BIGINT waiting_count=INTEGER "
    ),
    "patient_portal_mycarlos_mailbox_anchors": (
        "clinic_id=VARCHAR(64) device_key_id=VARCHAR(43) id=INTEGER proof_id=INTEGER "
        "proof_kind=VARCHAR(16) recipient_id=VARCHAR(64) recorded_at=BIGINT sequence=BIGINT "
        "vault_head_link=VARCHAR(64) "
    ),
    "patient_portal_mycarlos_mailbox_blobs": ("copy_id=INTEGER sealed=BLOB "),
    "patient_portal_mycarlos_mailbox_clinics": (
        "acked_through=BIGINT clinic_id=VARCHAR(64) event_sequence=BIGINT "
        "ordinary_event_bytes=BIGINT reserved_terminal_bytes=BIGINT retained_floor=BIGINT "
        "terminal_event_bytes=BIGINT waiting_bytes=BIGINT waiting_count=INTEGER "
    ),
    "patient_portal_mycarlos_mailbox_copies": (
        "account_id=INTEGER body_sha256=VARCHAR(64) ciphertext_sha256=VARCHAR(64) "
        "clinic_id=VARCHAR(64) created_at=BIGINT delivery_id=VARCHAR(36) device_id=INTEGER "
        "device_key_id=VARCHAR(43) expires_at=BIGINT id=INTEGER receipt_sha256=VARCHAR(64)? "
        "recipient_id=VARCHAR(64) sequence=BIGINT size=INTEGER status=VARCHAR(16) "
        "terminal_at=BIGINT? "
    ),
    "patient_portal_mycarlos_mailbox_devices": (
        "anchor_sequence=BIGINT delivery_sequence=BIGINT device_id=INTEGER "
        "removal_event_recorded=BOOLEAN waiting_bytes=BIGINT waiting_count=INTEGER "
    ),
    "patient_portal_mycarlos_mailbox_events": (
        "budget=VARCHAR(16) charged_bytes=INTEGER clinic_id=VARCHAR(64) delivery_id=VARCHAR(36)? "
        "device_key_id=VARCHAR(43) id=INTEGER kind=VARCHAR(16) occurred_at=BIGINT payload=BLOB "
        "receipt_proof_id=INTEGER? recipient_id=VARCHAR(64) request_proof_id=INTEGER? "
        "sequence=BIGINT "
    ),
    "patient_portal_mycarlos_mailbox_proofs": (
        "compact=BLOB device_key_id=VARCHAR(43) id=INTEGER recorded_at=BIGINT sha256=VARCHAR(64) "
    ),
    "patient_portal_mycarlos_mailbox_rates": (
        "bucket=VARCHAR(128) bytes=BIGINT clinic_id=VARCHAR(64) count=INTEGER minute=BIGINT "
    ),
    "patient_portal_mycarlos_recipients": (
        "account_id=INTEGER created_at=DATETIME recipient_id=VARCHAR(64) "
    ),
    "patient_portal_outbound_deliveries": (
        "account_id=INTEGER? attempt_count=INTEGER available_at=DATETIME "
        "booking_prompt_id=INTEGER? "
        "created_at=DATETIME delivered_at=DATETIME? encrypted_payload=BLOB "
        "encryption_key_id=VARCHAR(64) encryption_nonce=BLOB id=INTEGER kind=VARCHAR(32) "
        "last_failure_code=VARCHAR(64)? lease_expires_at=DATETIME? message_id=VARCHAR(255) "
        "reset_token_id=INTEGER? status=VARCHAR(16) "
    ),
    "patient_portal_password_reset_tokens": (
        "account_id=INTEGER client_reference_hash=VARCHAR(64)? created_at=DATETIME "
        "expires_at=DATETIME id=INTEGER status=VARCHAR(16) token_hash=VARCHAR(64) "
        "used_at=DATETIME? "
    ),
    "patient_portal_sessions": (
        "account_id=INTEGER created_at=DATETIME expires_at=DATETIME id=INTEGER "
        "last_seen_at=DATETIME? revoked_at=DATETIME? revoked_reason=VARCHAR(64)? "
        "token_hash=VARCHAR(64) "
    ),
    "patient_portal_signup_requests": (
        "clinic_id=VARCHAR(64) created_at=DATETIME encrypted_payload=BLOB "
        "encryption_key_id=VARCHAR(64) encryption_nonce=BLOB expires_at=DATETIME "
        "health_card_hash=VARCHAR(64) id=INTEGER "
    ),
    "patient_portal_staff_assertion_uses": (
        "assertion_id=VARCHAR(36) created_at=DATETIME expires_at=DATETIME "
    ),
    "patient_portal_unlock_secrets": (
        "account_id=INTEGER? clinic_id=VARCHAR(64) created_at=DATETIME created_by=VARCHAR(128) "
        "created_by_id=VARCHAR(128)? demographic_no=INTEGER encrypted_secret=BLOB "
        "encryption_algorithm=VARCHAR(32) encryption_context=VARCHAR(36)? "
        "encryption_key_id=VARCHAR(64) encryption_nonce=BLOB id=INTEGER label=VARCHAR(128)? "
        "last_viewed_at=DATETIME? revoke_reason=VARCHAR(64)? revoked_at=DATETIME? "
        "revoked_by=VARCHAR(128)? revoked_by_id=VARCHAR(128)? secret_type=VARCHAR(16) "
        "source_reference=VARCHAR(128)? status=VARCHAR(16) updated_at=DATETIME "
    ),
}

_REQUIRED_CHECKS = {
    "patient_portal_accounts": (
        "ck_patient_portal_accounts_clinic_id_length "
        "ck_patient_portal_accounts_demographic_no_positive "
        "ck_patient_portal_accounts_disabled_fields_complete "
        "ck_patient_portal_accounts_failed_login_count_non_negative "
        "ck_patient_portal_accounts_failed_mfa_count_non_negative "
        "ck_patient_portal_accounts_lock_fields_complete "
        "ck_patient_portal_accounts_locked_by_length "
        "ck_patient_portal_accounts_phone_number_length "
        "ck_patient_portal_accounts_preferred_mfa_method ck_patient_portal_accounts_status "
        "ck_patient_portal_accounts_username_length "
    ),
    "patient_portal_audit_events": (
        "ck_patient_portal_audit_events_actor_id_length ck_patient_portal_audit_events_actor_type "
        "ck_patient_portal_audit_events_actor_type_length "
        "ck_patient_portal_audit_events_assertion_id_length "
        "ck_patient_portal_audit_events_assertion_key_id_length "
        "ck_patient_portal_audit_events_client_reference_hash_length "
        "ck_patient_portal_audit_events_clinic_id_length "
        "ck_patient_portal_audit_events_demographic_no_positive "
        "ck_patient_portal_audit_events_event_type "
        "ck_patient_portal_audit_events_event_type_length "
        "ck_patient_portal_audit_events_invite_token_hash_length "
        "ck_patient_portal_audit_events_outcome ck_patient_portal_audit_events_outcome_length "
        "ck_patient_portal_audit_events_reason_length "
        "ck_patient_portal_audit_events_resource_id_length "
        "ck_patient_portal_audit_events_resource_type_length "
    ),
    "patient_portal_booking_choices": (
        "ck_pp_booking_choices_clinic_id_length ck_pp_booking_choices_duration "
        "ck_pp_booking_choices_location_code_length ck_pp_booking_choices_pending_has_slot "
        "ck_pp_booking_choices_result_at_matches_state ck_pp_booking_choices_slot_copy_complete "
        "ck_pp_booking_choices_slot_id_length ck_pp_booking_choices_state "
        "ck_pp_booking_choices_visit_mode "
    ),
    "patient_portal_booking_offered_slots": (
        "ck_pp_booking_offered_slots_duration ck_pp_booking_offered_slots_location_code_length "
        "ck_pp_booking_offered_slots_position ck_pp_booking_offered_slots_slot_id_length "
        "ck_pp_booking_offered_slots_visit_mode "
    ),
    "patient_portal_booking_prompts": (
        "ck_pp_booking_prompts_appointment_type ck_pp_booking_prompts_clinic_id_length "
        "ck_pp_booking_prompts_created_by_length ck_pp_booking_prompts_demographic_no_positive "
        "ck_pp_booking_prompts_expiry_after_creation ck_pp_booking_prompts_offer_digest_length "
        "ck_pp_booking_prompts_operation_id_length ck_pp_booking_prompts_read_at_present "
        "ck_pp_booking_prompts_sent_is_unread ck_pp_booking_prompts_status "
        "ck_pp_booking_prompts_suggested_by_length ck_pp_booking_prompts_urgency "
        "ck_pp_booking_prompts_withdrawn_fields "
    ),
    "patient_portal_clinic_keys": (
        "ck_pp_clinic_keys_clinic_id_length ck_pp_clinic_keys_kid_length "
        "ck_pp_clinic_keys_replacement_complete ck_pp_clinic_keys_replacement_signature_length "
        "ck_pp_clinic_keys_replaces_kid_length ck_pp_clinic_keys_revoked_at "
        "ck_pp_clinic_keys_spki_length ck_pp_clinic_keys_status "
    ),
    "patient_portal_contact_review_requests": (
        "ck_patient_portal_contact_review_requests_clinic_id_length "
        "ck_patient_portal_contact_review_requests_email_after_length "
        "ck_patient_portal_contact_review_requests_email_before_length "
        "ck_patient_portal_contact_review_requests_phone_after_length "
        "ck_patient_portal_contact_review_requests_phone_before_length "
        "ck_patient_portal_contact_review_requests_reviewed_by_length "
        "ck_patient_portal_contact_review_requests_status "
        "ck_pp_contact_review_demographic_positive "
        "ck_pp_contact_review_reviewed_present ck_pp_contact_review_unreviewed_null "
    ),
    "patient_portal_email_change_requests": (
        "ck_pp_email_change_confirmed_at_present ck_pp_email_change_confirmed_requires_both_proofs "
        "ck_pp_email_change_expires_after_created ck_pp_email_change_new_email_length "
        "ck_pp_email_change_new_phone_length ck_pp_email_change_phone_attempts_non_negative "
        "ck_pp_email_change_phone_code_hash_length ck_pp_email_change_status "
        "ck_pp_email_change_token_hash_length ck_pp_email_change_unconfirmed_confirmed_at_null "
    ),
    "patient_portal_invites": (
        "ck_patient_portal_invites_accepted_fields_present "
        "ck_patient_portal_invites_clinic_id_length "
        "ck_patient_portal_invites_demographic_no_positive "
        "ck_patient_portal_invites_expires_after_created "
        "ck_patient_portal_invites_nonaccepted_fields_null "
        "ck_patient_portal_invites_nonrevoked_fields_null "
        "ck_patient_portal_invites_proof_date_of_birth_hash_length "
        "ck_patient_portal_invites_proof_email_hash_length "
        "ck_patient_portal_invites_proof_fields_complete "
        "ck_patient_portal_invites_proof_hash_version "
        "ck_patient_portal_invites_proof_health_card_hash_length "
        "ck_patient_portal_invites_proof_salt_length "
        "ck_patient_portal_invites_revoked_fields_present "
        "ck_patient_portal_invites_sent_count_non_negative ck_patient_portal_invites_status "
        "ck_patient_portal_invites_token_hash_length ck_pp_invites_delivery_operation_length "
        "ck_pp_invites_delivery_reference_has_operation ck_pp_invites_delivery_reference_length "
        "ck_pp_invites_prepared_fields_present ck_pp_invites_prepared_token_fields_complete "
        "ck_pp_invites_token_key_id_length ck_pp_invites_token_nonce_length "
        "ck_pp_invites_token_only_while_prepared "
    ),
    "patient_portal_mfa_challenges": (
        "ck_patient_portal_mfa_challenges_code_hash_length "
        "ck_patient_portal_mfa_challenges_delivery_method "
        "ck_patient_portal_mfa_challenges_expires_after_created "
        "ck_patient_portal_mfa_challenges_failed_attempts_non_negative "
        "ck_patient_portal_mfa_challenges_status "
        "ck_patient_portal_mfa_challenges_token_hash_length "
        "ck_patient_portal_mfa_challenges_unverified_verified_at_null "
        "ck_patient_portal_mfa_challenges_verified_at_present "
    ),
    "patient_portal_mycarlos_approval_clinics": "",
    "patient_portal_mycarlos_approval_requests": "",
    "patient_portal_mycarlos_devices": (
        "ck_pp_mycarlos_devices_device_key_id_length ck_pp_mycarlos_devices_device_name_length "
        "ck_pp_mycarlos_devices_ed25519_length ck_pp_mycarlos_devices_removal_complete "
        "ck_pp_mycarlos_devices_removed_by ck_pp_mycarlos_devices_status "
        "ck_pp_mycarlos_devices_vault_head_link_at ck_pp_mycarlos_devices_vault_head_link_length "
        "ck_pp_mycarlos_devices_x25519_length "
    ),
    "patient_portal_mycarlos_link_codes": (
        "ck_pp_mycarlos_link_codes_code_hash_length "
        "ck_pp_mycarlos_link_codes_expiry_after_creation "
        "ck_pp_mycarlos_link_codes_link_id_length ck_pp_mycarlos_link_codes_status "
        "ck_pp_mycarlos_link_codes_used_complete ck_pp_mycarlos_link_codes_wrong_codes "
    ),
    "patient_portal_mycarlos_link_failures": ("ck_pp_mycarlos_link_failures_link_id_length "),
    "patient_portal_mycarlos_mailbox_accounts": ("ck_pp_mailbox_account_counters "),
    "patient_portal_mycarlos_mailbox_anchors": ("ck_pp_mailbox_anchor_kind "),
    "patient_portal_mycarlos_mailbox_blobs": ("ck_pp_mailbox_blob_size "),
    "patient_portal_mycarlos_mailbox_clinics": ("ck_pp_mailbox_clinic_counters "),
    "patient_portal_mycarlos_mailbox_copies": (
        "ck_pp_mailbox_copy_bindings ck_pp_mailbox_copy_state ck_pp_mailbox_copy_terminal "
    ),
    "patient_portal_mycarlos_mailbox_devices": ("ck_pp_mailbox_device_counters "),
    "patient_portal_mycarlos_mailbox_events": (
        "ck_pp_mailbox_event_evidence ck_pp_mailbox_event_kind "
    ),
    "patient_portal_mycarlos_mailbox_proofs": ("ck_pp_mailbox_proof_size "),
    "patient_portal_mycarlos_mailbox_rates": "",
    "patient_portal_mycarlos_recipients": ("ck_pp_mycarlos_recipients_recipient_id_length "),
    "patient_portal_outbound_deliveries": (
        "ck_pp_outbound_delivery_attempts_non_negative ck_pp_outbound_delivery_booking_prompt_kind "
        "ck_pp_outbound_delivery_delivered_at_present ck_pp_outbound_delivery_key_id_length "
        "ck_pp_outbound_delivery_kind ck_pp_outbound_delivery_lease_matches_status "
        "ck_pp_outbound_delivery_message_id_length ck_pp_outbound_delivery_nonce_length "
        "ck_pp_outbound_delivery_reset_token_kind ck_pp_outbound_delivery_status "
    ),
    "patient_portal_password_reset_tokens": (
        "ck_patient_portal_password_reset_tokens_client_hash_length "
        "ck_patient_portal_password_reset_tokens_expires_after_created "
        "ck_patient_portal_password_reset_tokens_status "
        "ck_patient_portal_password_reset_tokens_token_hash_length "
        "ck_patient_portal_password_reset_tokens_unused_used_at_null "
        "ck_patient_portal_password_reset_tokens_used_at_present "
    ),
    "patient_portal_sessions": (
        "ck_patient_portal_sessions_expires_after_created "
        "ck_patient_portal_sessions_revocation_fields_complete "
        "ck_patient_portal_sessions_revoked_reason_length "
        "ck_patient_portal_sessions_token_hash_length "
    ),
    "patient_portal_signup_requests": (
        "ck_pp_signup_requests_clinic_id_length ck_pp_signup_requests_expiry_after_creation "
        "ck_pp_signup_requests_health_card_hash_length ck_pp_signup_requests_key_id_length "
        "ck_pp_signup_requests_nonce_length "
    ),
    "patient_portal_staff_assertion_uses": (
        "ck_pp_staff_assertion_use_expiry_after_creation ck_pp_staff_assertion_use_id_length "
    ),
    "patient_portal_unlock_secrets": (
        "ck_patient_portal_unlock_secrets_account_id_positive "
        "ck_patient_portal_unlock_secrets_algorithm_length "
        "ck_patient_portal_unlock_secrets_ciphertext_present "
        "ck_patient_portal_unlock_secrets_clinic_id_length "
        "ck_patient_portal_unlock_secrets_context_length "
        "ck_patient_portal_unlock_secrets_created_by_length "
        "ck_patient_portal_unlock_secrets_demographic_no_positive "
        "ck_patient_portal_unlock_secrets_key_id_length "
        "ck_patient_portal_unlock_secrets_label_length "
        "ck_patient_portal_unlock_secrets_nonce_length "
        "ck_patient_portal_unlock_secrets_nonrevoked_fields_null "
        "ck_patient_portal_unlock_secrets_revoke_reason_length "
        "ck_patient_portal_unlock_secrets_revoked_by_length "
        "ck_patient_portal_unlock_secrets_revoked_fields_present "
        "ck_patient_portal_unlock_secrets_secret_type "
        "ck_patient_portal_unlock_secrets_source_reference_length "
        "ck_patient_portal_unlock_secrets_status "
    ),
}

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
    inspector = sa.inspect(bind)
    tables = set(inspector.get_table_names()) - {"alembic_version"}
    if tables != set(_REQUIRED_COLUMNS):
        raise RuntimeError("migration 0019 refuses missing or unexpected prerequisite tables")
    audit_types = frozenset()
    for table, expected in _REQUIRED_COLUMNS.items():
        actual = set()
        for column in inspector.get_columns(table):
            portable = column["type"].as_generic().compile(dialect=sqlite_dialect())
            actual.add(column["name"] + "=" + portable + ("?" if column["nullable"] else ""))
            if (
                bind.dialect.name == "postgresql"
                and isinstance(column["type"], sa.DateTime)
                and not column["type"].timezone
            ):
                raise RuntimeError(
                    "migration 0019 refuses a prerequisite timestamp without timezone"
                )
        if actual != set(expected.split()):
            raise RuntimeError("migration 0019 refuses prerequisite column drift")
        checks = inspector.get_check_constraints(table)
        if {item["name"] for item in checks} != set(_REQUIRED_CHECKS[table].split()):
            raise RuntimeError("migration 0019 refuses prerequisite CHECK drift")
        if table == "patient_portal_audit_events":
            audit_types = _audit_types(
                next(item["sqltext"] for item in checks if item["name"] == _AUDIT_CHECK)
            )
    if audit_types not in {_AUDIT_TYPES, _UPSTREAM_ONLY_TYPES, _SIGNUP_ONLY_TYPES}:
        raise RuntimeError("migration 0019 refuses an unknown audit event allowlist")
    if audit_types != _AUDIT_TYPES:
        # Both old branches can already be stamped on an empty database. Reconcile only
        # their recognized final allowlists, after every physical prerequisite passed.
        with op.batch_alter_table("patient_portal_audit_events") as batch_op:
            batch_op.drop_constraint(_AUDIT_CHECK, type_="check")
            batch_op.create_check_constraint(
                _AUDIT_CHECK,
                "event_type in (" + ", ".join(repr(t) for t in sorted(_AUDIT_TYPES)) + ")",
            )


def downgrade() -> None:
    # Unmerging would reintroduce two heads and incompatible historical audit policies.
    # Refuse immediately, including on an empty database; no retention decision is implied.
    raise RuntimeError("migration 0019 is forward-only; restore a compatible backup to roll back")
