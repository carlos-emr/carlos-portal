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

"""English text for the patient portal: the source every other locale translates.

Every key here must exist, with the same `{placeholders}`, in each translated locale once
that locale is listed as complete in tests/test_i18n_catalog.py. A key a locale has not
translated yet falls back to this English text (`i18n.portal_text`).
"""

# The sign-in heading, button and form name say the same thing.
SIGN_IN_LABEL = "Sign in"

TEXT: dict[str, str] = {
    "account": "Account",
    "account_change_error": "Account change could not be completed.",
    "account_help": "Account help",
    "account_status_contact_notice_failed": (
        "Portal contact updated, but the confirmation email could not be sent. "
        "Contact the clinic if you did not expect this change."
    ),
    "account_status_contact_updated": (
        "Portal contact updated. Staff will review the matching CARLOS demographics."
    ),
    "account_status_contact_confirmation_required": (
        "Confirm the new email address and enter the code sent to the new phone number. "
        "Your current contact details remain active until both are confirmed."
    ),
    "account_status_email_confirmation_required": (
        "Check the new email address for a confirmation link. Your current address keeps "
        "receiving sign-in codes and password reset links until you use it."
    ),
    "account_status_email_confirmation_notice_failed": (
        "Confirmation could not be emailed to the new address. Your contact details were not "
        "changed. Try again, or contact the clinic."
    ),
    "account_status_phone_confirmation_required": (
        "Enter the confirmation code sent to the new phone number. Your current phone number "
        "remains active until it is confirmed."
    ),
    "account_status_phone_confirmation_invalid": (
        "The phone confirmation code is invalid or expired. Request another code and try again."
    ),
    "account_status_phone_confirmation_notice_failed": (
        "A confirmation code could not be sent to the new phone number. Your contact details "
        "were not changed. Try again, or contact the clinic."
    ),
    "account_status_phone_confirmation_rate_limited": (
        "A phone confirmation code was sent recently. Wait before requesting another."
    ),
    "account_status_mfa_updated": "Two-step verification settings updated.",
    "account_status_no_change": "No account changes.",
    "account_status_password_updated": "Password updated.",
    "all_providers": "All providers",
    "activate_account": "Activate account",
    "activation_details": (
        "Enter the invitation details supplied by your clinic and create your portal sign-in."
    ),
    "activation_date_of_birth_invalid": (
        "Check the date of birth: enter a real date, for example 15 June 1985."
    ),
    "activation_error": "The activation details could not be verified.",
    "activation_password_rejected": (
        "Choose a different password: use at least 12 characters, avoid common words or "
        "patterns, and don't include your username, email, birth date or health card number."
    ),
    "activation_reenter_password": "Your other entries are kept: enter your password again.",
    "activation_heading": "Activate your account",
    "activation_rate_limited": (
        "Too many activation attempts were made. Wait before trying again."
    ),
    "activation_success": "Your portal account is ready.",
    "activation_success_heading": "Account activated",
    "back_to_sign_in": "Back to sign in",
    "booking_prompt_contact": "To book, contact {clinic_name}.",
    "booking_prompt_contact_phone": "To book, call {clinic_name} at {phone}.",
    "booking_prompt_no_online_booking": "Appointments cannot be booked in this portal.",
    "booking_prompt_suggested_by": "{provider} suggested this appointment.",
    "booking_prompt_suggested_by_clinic": "Your clinic suggested this appointment.",
    "booking_prompt_title_annual_exam": "Book your annual exam",
    "booking_prompt_title_follow_up": "Book a follow-up appointment",
    "booking_prompt_title_lab_review": "Book an appointment to review your lab results",
    "booking_prompt_urgency_as_soon_as_possible": "Please book as soon as possible.",
    "booking_prompt_urgency_routine": "Please book at a time that suits you.",
    "booking_prompt_urgency_soon": "Please book within the next few weeks.",
    "booking_booked": "Booked for {date} at {time}.",
    "booking_choice_error": (
        "That time could not be chosen. Review the message below and try again."
    ),
    "booking_choice_pending": "We are confirming your time with the clinic.",
    "booking_choice_pending_overdue": (
        "The clinic will confirm your time. If it is urgent, call the clinic."
    ),
    "booking_choice_pending_overdue_phone": (
        "The clinic will confirm your time. If it is urgent, call the clinic at {phone}."
    ),
    "booking_choice_expired": (
        "That time passed before the clinic could confirm it. Please pick another."
    ),
    "booking_choice_expired_contact": (
        "That time passed before the clinic could confirm it. Please contact the clinic."
    ),
    "booking_choose": "Choose this time",
    "booking_decline": "None of these work",
    "booking_month_1": "January",
    "booking_month_2": "February",
    "booking_month_3": "March",
    "booking_month_4": "April",
    "booking_month_5": "May",
    "booking_month_6": "June",
    "booking_month_7": "July",
    "booking_month_8": "August",
    "booking_month_9": "September",
    "booking_month_10": "October",
    "booking_month_11": "November",
    "booking_month_12": "December",
    "booking_offer_intro": (
        "The clinic has offered these times. Pick one and the clinic will confirm it."
    ),
    "booking_slot_date": "{weekday} {day} {month}",
    "booking_slot_detail_separator": " · ",
    "booking_slot_duration_one": "{minutes} minute",
    "booking_slot_duration_other": "{minutes} minutes",
    "booking_slot_taken": "That time was just taken. Please pick another.",
    "booking_slot_taken_contact": "That time was just taken. Please contact the clinic.",
    "booking_slot_time": "{hour:02d}:{minute:02d}",
    "booking_slot_when": "{date} at {time}",
    "booking_slots_legend": "Available times",
    "booking_visit_mode_in_person": "In person",
    "booking_visit_mode_phone": "By phone",
    "booking_visit_mode_video": "By video",
    "booking_weekday_0": "Monday",
    "booking_weekday_1": "Tuesday",
    "booking_weekday_2": "Wednesday",
    "booking_weekday_3": "Thursday",
    "booking_weekday_4": "Friday",
    "booking_weekday_5": "Saturday",
    "booking_weekday_6": "Sunday",
    "email_change_confirm": "Confirm email address",
    "email_change_complete_error": (
        "This confirmation link is no longer valid. Request the change again from your "
        "account page."
    ),
    "email_change_complete_heading": "Confirm your new email address",
    "email_change_complete_intro": (
        "Confirming updates the email address used for sign-in codes and password reset links."
    ),
    "email_change_success": (
        "Your email address is updated. Clinic staff will review the matching CARLOS chart details."
    ),
    "email_change_success_heading": "Email address confirmed",
    "email_change_phone_confirmation_pending": (
        "Your new email address is confirmed. Sign in and enter the code sent to the new "
        "phone number to finish the contact change."
    ),
    "change_password": "Change password",
    "clinic": "Clinic",
    "clinic_help": "Clinic help",
    "clinic_help_message": (
        "Contact the clinic if you cannot access your account or verification method."
    ),
    "contact_info": "Contact info",
    "contact_change_notice_failed": (
        "Your contact information is updated and you have been signed out, but a security "
        "notice could not be sent. Contact the clinic if you did not make this change."
    ),
    "contact_change_success": (
        "Your contact information is updated. For security, you have been signed out; sign in "
        "again with your updated verification method. Clinic staff will review the matching "
        "CARLOS chart details."
    ),
    "contact_change_success_heading": "Contact information updated",
    "contact_the_clinic": "Contact the clinic",
    "copy": "Copy",
    "copy_failed": "Select and copy manually",
    "copied": "Copied",
    "current_password": "Current password",
    "dashboard": "Dashboard",
    "dashboard_account_description": "Manage your password and contact information.",
    "dashboard_documents_description": "Documents may be available in a future release.",
    "dashboard_email_passwords_description": (
        "Retrieve passwords for encrypted documents from your clinic."
    ),
    "dashboard_greeting": "Patient portal",
    "dashboard_help_description": "Find clinic and account support information.",
    "dashboard_messages_description": (
        "Requests from your clinic, such as a reminder to book an appointment."
    ),
    "date_from": "From date",
    "date_format_error": "Enter valid from and to dates.",
    "filter_error": "Enter valid filters.",
    "date_range_error": "The from date must not be later than the to date.",
    "date_of_birth": "Date of birth",
    "date_of_birth_day": "Day",
    "date_of_birth_hint": "For example, 15 June 1985.",
    "date_of_birth_month": "Month",
    "date_of_birth_month_1": "January",
    "date_of_birth_month_2": "February",
    "date_of_birth_month_3": "March",
    "date_of_birth_month_4": "April",
    "date_of_birth_month_5": "May",
    "date_of_birth_month_6": "June",
    "date_of_birth_month_7": "July",
    "date_of_birth_month_8": "August",
    "date_of_birth_month_9": "September",
    "date_of_birth_month_10": "October",
    "date_of_birth_month_11": "November",
    "date_of_birth_month_12": "December",
    "date_of_birth_month_choose": "Choose a month",
    "date_of_birth_year": "Year",
    "date_to": "To date",
    "development_mfa_code": (
        "Development sign-in code (same code as sent by email, to make testing quicker, "
        "will be removed later):"
    ),
    "development_reset_link": (
        "Development password reset link (also sent by email when email is configured):"
    ),
    "documents": "Documents",
    "email": "Email",
    "email_codes_rate": "Email codes can be resent once per minute.",
    "email_password": "Document password",
    "email_password_page_indicator": "Page {page} of {total_pages}",
    "email_password_pages": "Document password pages",
    "email_passwords": "Document passwords",
    "email_passwords_region": "Document passwords",
    "forgot_username_password": "Forgot username or password?",
    "forgot_username_help": "If you do not know your username, contact the clinic.",
    "future": "Future",
    "health_card_number": "Health card number (HCN/HIN)",
    "help": "Help",
    "hide_password": "Hide password",
    "incorrect_mfa_code": "The code was not accepted. Try again or request a new code.",
    "incorrect_username_or_password": "Incorrect Username or Password",
    "invite_code": "Invitation code",
    "language_aria_label": "Language",
    "logo_alt": "CARLOS",
    "logout": "Logout",
    "message_back": "Back to messages",
    "message_new": "New",
    "message_not_found": "That message is no longer available.",
    "message_sent_at": "Sent {sent_at}",
    "messages": "Messages",
    "messages_empty": "You have no messages from your clinic.",
    "messages_new_count_one": "{count} new",
    "messages_new_count_other": "{count} new",
    "mfa": "Two-step verification",
    "mfa_code": "Code",
    "mfa_code_sent_email": "Code sent to {destination} by email.",
    "mfa_code_sent_email_unmasked": "Code sent to your email address.",
    "mfa_code_sent_sms": "Code sent to {destination} by SMS.",
    "mfa_code_sent_sms_unmasked": "Code sent to your mobile number.",
    "mfa_delivery_unavailable": "That delivery method is unavailable.",
    "mfa_email": "Email",
    "mfa_heading": "Sign-in code",
    "mfa_help_message": ("Contact {clinic_name} if you cannot receive or use your sign-in code."),
    "mfa_new_code_sent_email": "A new code was sent by email.",
    "mfa_new_code_sent_sms": "A new code was sent by SMS.",
    "mfa_rate_limited_one": "A code was sent recently. Try again in {seconds} second.",
    "mfa_rate_limited_other": "A code was sent recently. Try again in {seconds} seconds.",
    "mfa_resend": "Resend code",
    "mfa_sign_in_again": "Sign in again to request a new sign-in code.",
    "mfa_send_by": "Send code by",
    "mfa_settings": "Two-step verification settings",
    "mfa_sms": "SMS",
    "mfa_sms_rate": "SMS codes can be resent once every five minutes.",
    "mfa_verify": "Verify",
    "mfa_verification_failed": "Two-step verification could not be completed.",
    "modal_close": "OK",
    "module_navigation": "Portal modules",
    "mfa_method": "Method",
    "new_password": "New password",
    "new_password_confirmation": "Confirm new password",
    "next": "Next",
    "no_email_passwords": "No document passwords",
    "no_matching_email_passwords": "No matching document passwords",
    "open_reset_page": "Open reset page",
    "password_label": "Password",
    "password_hidden": "Hidden",  # NOSONAR - translation label, not a credential
    "password_for": "Password for {subject}",
    "password_confirmation": "Confirm password",
    "password_invalid": "The new password does not meet the password requirements.",
    "password_mismatch": "The password confirmation does not match.",
    "password_placeholder": "password",
    "password_requirements": (
        "Use at least 12 characters. Avoid common passwords and account, clinic, or personal "
        "information; several unrelated words are a good choice."
    ),
    "password_reset_complete_error": "The password reset link is invalid or has expired.",
    "password_reset_complete_heading": "Choose a new password",
    "password_reset_forced": "You must reset your password before signing in.",
    "password_reset_link_sent": (
        "If the account details match, a password reset link has been sent by email."
    ),
    "password_reset_request_details": (
        "Enter your portal username and the email address registered with your clinic."
    ),
    "password_reset_request_heading": "Reset your password",
    "password_reset_send": "Send reset link",  # NOSONAR - translation label
    "password_reset_success": "Your password has been reset. Sign in with the new password.",
    "password_reset_success_heading": "Password reset",
    "password_reset_update": "Update password",
    "password_updated": "Password updated",
    "patient_dashboard": "Patient dashboard",
    "phone": "Phone",
    "phone_required_for_sms": "Required when SMS is selected.",
    "phone_confirmation_code": "Phone confirmation code",
    "confirm_phone": "Confirm phone number",
    "resend_phone_confirmation": "Send another code",
    "previous": "Previous",
    "provider": "Provider",
    "provider_options_truncated": (
        "Only the most recent providers are listed. Use the search box to narrow your results."
    ),
    "reveal": "Reveal",
    "reveal_failed": "Password could not be revealed. Try again.",
    "reveal_password_hint": "Enter your current password before revealing a document password.",
    "password_reset_temporarily_unavailable": (
        "Password reset is temporarily unavailable. Please try again shortly."
    ),
    "revealing": "Revealing...",
    "reset_filters": "Clear filters",
    "search": "Search",
    "sent": "Sent",
    "session_locked_details": (
        "Clinic staff must unlock this account before another sign-in or password reset. "
        "Contact the clinic for help."
    ),
    "request_failed_heading": "Request could not be completed",
    "request_failed_details": (
        "The portal could not complete that request. This usually means the page was open "
        "for a while - return to the portal and try again."
    ),
    "service_busy_heading": "Too many requests",
    "service_busy_details": (
        "The portal received too many requests from this connection. Wait a moment and try again."
    ),
    "service_maintenance_heading": "Portal unavailable",
    "service_maintenance_details": (
        "The portal is temporarily unavailable for maintenance. Try again shortly, or contact "
        "the clinic if you need help now."
    ),
    # The product's name, shown when a deployment keeps the default name (a clinic's own name is
    # shown as configured).
    "service_name_default": "CARLOS Patient Portal",
    # A fault that is not maintenance: the database or a stored credential cannot be reached.
    "service_unavailable_heading": "Portal temporarily unavailable",
    "service_unavailable_details": (
        "The portal cannot be reached right now. Try again in a few minutes, or contact the "
        "clinic if you need help now."
    ),
    "session_locked_heading": "Account locked",
    "sign_in_aria_label": SIGN_IN_LABEL,
    "sign_in_button": SIGN_IN_LABEL,
    "sign_in_heading": SIGN_IN_LABEL,
    "show_password": "Show password",
    "source_code": "Source code",
    "subject": "Subject",
    "unavailable": "Unavailable",
    "update_contact": "Update contact",
    "update_mfa": "Update two-step verification",
    "update_password": "Update password",
    "username": "Username",
    "username_label": "User Name",
    "username_placeholder": "username",
    "username_unavailable": "That username is unavailable.",
    "verification_delivery_failed": "The sign-in code could not be sent. Please try again.",
    "view_module": "Open",
}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
    "mycarlos_mfa_rate_limited": (
        "A sign-in code was sent recently. Please wait before requesting another."
    ),
    "mycarlos_link": "Link myCarlos",
    "mycarlos_devices": "Linked devices",
    "mycarlos_instruction": (
        "In myCarlos, choose the option to link to your clinic’s portal, then enter this code."
    ),
    "mycarlos_code_label": "Linking code",
    "mycarlos_lifetime": "This code works once, for 10 minutes. Stay signed in to this portal.",
    "mycarlos_approval": "The device must also be approved before it can receive documents.",
    "mycarlos_create": "Create a code",
    "mycarlos_another": "Create another code",
    "mycarlos_linked": "Linked",
    "mycarlos_last_seen": "Last seen",
    "mycarlos_empty": "No linked devices. Choose Link myCarlos to add one.",
    "mycarlos_remove_question": "Remove this device?",
    "mycarlos_remove_effect": (
        "This device will stop receiving new documents. To use it again, link it "
        "again. Documents already saved in myCarlos stay there."
    ),
    "mycarlos_remove": "Remove device",
    "mycarlos_remove_named": "Remove device: {name}",
    "mycarlos_keep": "Keep device",
    "mycarlos_paused": "Linking is paused because of too many incorrect codes. Try again later.",
    "mycarlos_unavailable": "Linking is unavailable. Contact your clinic.",
    "mycarlos_removed": "Device removed.",
    "mycarlos_not_seen": "Not yet seen",
    "mycarlos_mfa_required": "Verify your sign-in before linking or removing a device.",
    "mycarlos_verify": "Verify sign-in",
    "mycarlos_portal_address": "Portal address",
    "mycarlos_qr_label": "Scan in myCarlos",
    "mycarlos_qr_alt": "QR code for linking myCarlos to this portal.",
    "mycarlos_qr_unavailable": (
        "QR code unavailable. Contact your clinic if you cannot use this portal address."
    ),
}
