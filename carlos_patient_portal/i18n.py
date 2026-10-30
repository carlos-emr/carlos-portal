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

"""Locale resolution and the portal's user-facing text.

Translations are not written yet. Rather than advertise four languages that do nothing, the
machinery is real and every locale resolves through `TEXT_CATALOG` with a per-key fallback to
English: selecting French switches the locale, persists it, and renders the English string for any
key French has not defined. Adding a translation is then only a matter of adding keys to
`TEXT_CATALOG["fr"]` — no route, template, or context change is needed, and a partial translation
renders rather than raising KeyError.
"""

import math
from dataclasses import dataclass
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

DEFAULT_LOCALE = "en"
# Display preference only — it selects strings and a date format, and carries no authorization or
# identity meaning, which is why the switch route can accept a GET without a CSRF token.
LOCALE_COOKIE_NAME = "portal_locale"
LOCALE_COOKIE_MAX_AGE_SECONDS = 365 * 24 * 60 * 60
DEFAULT_DATETIME_FORMAT = "%Y-%m-%d %H:%M %Z"
DATETIME_FORMATS = {
    DEFAULT_LOCALE: DEFAULT_DATETIME_FORMAT,
    # Placeholders alongside the English catalog: ISO-style ordering is unambiguous in every one of
    # these locales, so it is a safe default until a translator sets the real convention.
    "fr": DEFAULT_DATETIME_FORMAT,
    "es": DEFAULT_DATETIME_FORMAT,
    "pl": DEFAULT_DATETIME_FORMAT,
    "pt-BR": DEFAULT_DATETIME_FORMAT,
}
SIGN_IN_LABEL = "Sign in"


@dataclass(frozen=True)
class LocaleOption:
    code: str
    short_label: str
    label: str


SUPPORTED_LOCALES: tuple[LocaleOption, ...] = (
    LocaleOption(code="en", short_label="EN", label="English"),
    LocaleOption(code="fr", short_label="FR", label="French"),
    LocaleOption(code="es", short_label="ES", label="Spanish"),
    LocaleOption(code="pl", short_label="PL", label="Polish"),
    LocaleOption(code="pt-BR", short_label="PT-BR", label="Portuguese (Brazil)"),
)

TEXT_CATALOG: dict[str, dict[str, str]] = {
    DEFAULT_LOCALE: {
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
            "receiving verification codes and password reset links until you use it."
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
        "account_status_mfa_updated": "MFA settings updated.",
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
        "booking_slot_duration": "{minutes} minutes",
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
            "Confirming updates the email address used for sign-in verification codes and "
            "password reset links."
        ),
        "email_change_success": (
            "Your email address is updated. Clinic staff will review the matching CARLOS chart "
            "details."
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
            "Retrieve passwords for encrypted messages from your clinic."
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
            "Development MFA code (same code as sent by email, to make testing quicker, "
            "will be removed later):"
        ),
        "development_reset_link": (
            "Development password reset link (also sent by email when email is configured):"
        ),
        "documents": "Documents",
        "email": "Email",
        "email_codes_rate": "Email codes can be resent once per minute.",
        "email_password": "Email password",
        "email_password_pages": "Email password pages",
        "email_passwords": "Email passwords",
        "email_passwords_region": "Email passwords",
        "filters": "Filters",
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
        "messages_new_count": "{count} new",
        "mfa": "MFA",
        "mfa_code": "Code",
        "mfa_code_sent": "Code sent to {destination} by {method}.",
        "mfa_delivery_unavailable": "That delivery method is unavailable.",
        "mfa_email": "Email",
        "mfa_heading": "Verification code",
        "mfa_help_message": (
            "Contact {clinic_name} if you cannot receive or use your verification code."
        ),
        "mfa_new_code_sent": "A new code was sent by {method}.",
        "mfa_rate_limited": "A code was sent recently. Try again in {seconds} seconds.",
        "mfa_resend": "Resend code",
        "mfa_sign_in_again": "Sign in again to request a new verification code.",
        "mfa_send_by": "Send code by",
        "mfa_settings": "MFA settings",
        "mfa_sms": "SMS",
        "mfa_sms_rate": "SMS codes can be resent once every five minutes.",
        "mfa_verify": "Verify",
        "mfa_verification_failed": "MFA could not be verified.",
        "modal_close": "OK",
        "module_navigation": "Portal modules",
        "mfa_method": "Method",
        "new_password": "New password",
        "new_password_confirmation": "Confirm new password",
        "next": "Next",
        "no_email_passwords": "No email passwords",
        "no_matching_email_passwords": "No matching email passwords",
        "of": "of",
        "open_reset_page": "Open reset page",
        "page": "Page",
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
        "reveal_password_hint": "Enter your current password before revealing a passphrase.",
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
            "The portal received too many requests from this connection. Wait a moment and try "
            "again."
        ),
        "service_maintenance_heading": "Portal unavailable",
        "service_maintenance_details": (
            "The portal is temporarily unavailable for maintenance. Try again shortly, or contact "
            "the clinic if you need help now."
        ),
        "session_locked_heading": "Account locked",
        "sign_in_aria_label": SIGN_IN_LABEL,
        "sign_in_button": SIGN_IN_LABEL,
        "sign_in_heading": SIGN_IN_LABEL,
        "sign_up_contact_clinic": (
            "If your clinic does not have your email address, or has an old one, contact the "
            "clinic before you request an account."
        ),
        "sign_up_details_invalid": (
            "Check your details: enter your health card number, a real date of birth and a valid "
            "email address."
        ),
        "sign_up_email": "Email address your clinic has for you",
        "sign_up_email_hint": (
            "Used only to check your details. The link is sent only to the email address already "
            "in your clinic's records."
        ),
        "sign_up_heading": "Request a portal account",
        "sign_up_intro": (
            "Enter your health card number, your date of birth and the email address your clinic "
            "has for you. If they match your clinic's records, you will be emailed a link to "
            "finish setting up your account."
        ),
        # Worded as carlos-portal#15 specifies. Shown for every accepted request, matched or not.
        "sign_up_result": (
            "If your details match our records, we have emailed you a link to finish setting up "
            "your account. If nothing arrives, contact the clinic."
        ),
        "sign_up_result_heading": "Request received",
        "sign_up_submit": "Request account",
        "sign_up_unavailable": (
            "Account requests are temporarily unavailable. Try again later, or contact the clinic."
        ),
        "show_password": "Show password",
        "source_code": "Source code",
        "subject": "Subject",
        "unavailable": "Unavailable",
        "update_contact": "Update contact",
        "update_mfa": "Update MFA",
        "update_password": "Update password",
        "username": "Username",
        "username_label": "User Name",
        "username_placeholder": "username",
        "username_unavailable": "That username is unavailable.",
        "verification_delivery_failed": "Verification code could not be sent. Please try again.",
        "view_module": "Open",
    }
}

# The first translated strings. Every key a locale does not define still falls back to English.
TEXT_CATALOG["fr"] = {
    "hide_password": "Masquer le mot de passe",
    "show_password": "Afficher le mot de passe",
    "booking_month_1": "janvier",
    "booking_month_2": "février",
    "booking_month_3": "mars",
    "booking_month_4": "avril",
    "booking_month_5": "mai",
    "booking_month_6": "juin",
    "booking_month_7": "juillet",
    "booking_month_8": "août",
    "booking_month_9": "septembre",
    "booking_month_10": "octobre",
    "booking_month_11": "novembre",
    "booking_month_12": "décembre",
    "booking_slot_date": "{weekday} {day} {month}",
    "booking_weekday_0": "Lundi",
    "booking_weekday_1": "Mardi",
    "booking_weekday_2": "Mercredi",
    "booking_weekday_3": "Jeudi",
    "booking_weekday_4": "Vendredi",
    "booking_weekday_5": "Samedi",
    "booking_weekday_6": "Dimanche",
    "date_of_birth_month_1": "Janvier",
    "date_of_birth_month_2": "Février",
    "date_of_birth_month_3": "Mars",
    "date_of_birth_month_4": "Avril",
    "date_of_birth_month_5": "Mai",
    "date_of_birth_month_6": "Juin",
    "date_of_birth_month_7": "Juillet",
    "date_of_birth_month_8": "Août",
    "date_of_birth_month_9": "Septembre",
    "date_of_birth_month_10": "Octobre",
    "date_of_birth_month_11": "Novembre",
    "date_of_birth_month_12": "Décembre",
    "activation_date_of_birth_invalid": (
        "Vérifiez la date de naissance : entrez une date réelle, par exemple 15 juin 1985."
    ),
    "date_of_birth": "Date de naissance",
    "date_of_birth_day": "Jour",
    "date_of_birth_hint": "Par exemple, 15 juin 1985.",
    "date_of_birth_month": "Mois",
    "date_of_birth_month_choose": "Choisissez un mois",
    "date_of_birth_year": "Année",
    "activation_password_rejected": (
        "Choisissez un autre mot de passe : utilisez au moins 12 caractères, évitez les mots ou "
        "les suites courants, et n’y mettez pas votre nom d’utilisateur, votre courriel, votre "
        "date de naissance ni votre numéro de carte santé."
    ),
    "activation_reenter_password": (
        "Vos autres renseignements sont conservés : saisissez de nouveau votre mot de passe."
    ),
}
TEXT_CATALOG["es"] = {
    "hide_password": "Ocultar contraseña",
    "show_password": "Mostrar contraseña",
    "booking_month_1": "enero",
    "booking_month_2": "febrero",
    "booking_month_3": "marzo",
    "booking_month_4": "abril",
    "booking_month_5": "mayo",
    "booking_month_6": "junio",
    "booking_month_7": "julio",
    "booking_month_8": "agosto",
    "booking_month_9": "septiembre",
    "booking_month_10": "octubre",
    "booking_month_11": "noviembre",
    "booking_month_12": "diciembre",
    "booking_slot_date": "{weekday} {day} de {month}",
    "booking_weekday_0": "Lunes",
    "booking_weekday_1": "Martes",
    "booking_weekday_2": "Miércoles",
    "booking_weekday_3": "Jueves",
    "booking_weekday_4": "Viernes",
    "booking_weekday_5": "Sábado",
    "booking_weekday_6": "Domingo",
    "date_of_birth_month_1": "Enero",
    "date_of_birth_month_2": "Febrero",
    "date_of_birth_month_3": "Marzo",
    "date_of_birth_month_4": "Abril",
    "date_of_birth_month_5": "Mayo",
    "date_of_birth_month_6": "Junio",
    "date_of_birth_month_7": "Julio",
    "date_of_birth_month_8": "Agosto",
    "date_of_birth_month_9": "Septiembre",
    "date_of_birth_month_10": "Octubre",
    "date_of_birth_month_11": "Noviembre",
    "date_of_birth_month_12": "Diciembre",
    "activation_date_of_birth_invalid": (
        "Revise la fecha de nacimiento: introduzca una fecha real, por ejemplo, 15 de junio de "
        "1985."
    ),
    "date_of_birth": "Fecha de nacimiento",
    "date_of_birth_day": "Día",
    "date_of_birth_hint": "Por ejemplo, 15 de junio de 1985.",
    "date_of_birth_month": "Mes",
    "date_of_birth_month_choose": "Elija un mes",
    "date_of_birth_year": "Año",
    "activation_password_rejected": (
        "Elija otra contraseña: use al menos 12 caracteres, evite palabras o patrones comunes y "
        "no incluya su nombre de usuario, correo electrónico, fecha de nacimiento ni número de "
        "tarjeta de salud."
    ),
    "activation_reenter_password": "Sus demás datos se conservan: vuelva a escribir su contraseña.",
}
TEXT_CATALOG["pl"] = {
    "hide_password": "Ukryj hasło",
    "show_password": "Pokaż hasło",
    "booking_month_1": "stycznia",
    "booking_month_2": "lutego",
    "booking_month_3": "marca",
    "booking_month_4": "kwietnia",
    "booking_month_5": "maja",
    "booking_month_6": "czerwca",
    "booking_month_7": "lipca",
    "booking_month_8": "sierpnia",
    "booking_month_9": "września",
    "booking_month_10": "października",
    "booking_month_11": "listopada",
    "booking_month_12": "grudnia",
    "booking_slot_date": "{weekday}, {day} {month}",
    "booking_weekday_0": "Poniedziałek",
    "booking_weekday_1": "Wtorek",
    "booking_weekday_2": "Środa",
    "booking_weekday_3": "Czwartek",
    "booking_weekday_4": "Piątek",
    "booking_weekday_5": "Sobota",
    "booking_weekday_6": "Niedziela",
    "date_of_birth_month_1": "Styczeń",
    "date_of_birth_month_2": "Luty",
    "date_of_birth_month_3": "Marzec",
    "date_of_birth_month_4": "Kwiecień",
    "date_of_birth_month_5": "Maj",
    "date_of_birth_month_6": "Czerwiec",
    "date_of_birth_month_7": "Lipiec",
    "date_of_birth_month_8": "Sierpień",
    "date_of_birth_month_9": "Wrzesień",
    "date_of_birth_month_10": "Październik",
    "date_of_birth_month_11": "Listopad",
    "date_of_birth_month_12": "Grudzień",
    "activation_date_of_birth_invalid": (
        "Sprawdź datę urodzenia: wpisz prawdziwą datę, na przykład 15 czerwca 1985."
    ),
    "date_of_birth": "Data urodzenia",
    "date_of_birth_day": "Dzień",
    "date_of_birth_hint": "Na przykład 15 czerwca 1985.",
    "date_of_birth_month": "Miesiąc",
    "date_of_birth_month_choose": "Wybierz miesiąc",
    "date_of_birth_year": "Rok",
    "activation_password_rejected": (
        "Wybierz inne hasło: użyj co najmniej 12 znaków, unikaj popularnych słów i schematów "
        "oraz nie umieszczaj w nim nazwy użytkownika, adresu e-mail, daty urodzenia ani numeru "
        "karty zdrowia."
    ),
    "activation_reenter_password": "Pozostałe dane zostały zachowane: wpisz ponownie hasło.",
}
TEXT_CATALOG["pt-BR"] = {
    "hide_password": "Ocultar senha",
    "show_password": "Mostrar senha",
    "booking_month_1": "janeiro",
    "booking_month_2": "fevereiro",
    "booking_month_3": "março",
    "booking_month_4": "abril",
    "booking_month_5": "maio",
    "booking_month_6": "junho",
    "booking_month_7": "julho",
    "booking_month_8": "agosto",
    "booking_month_9": "setembro",
    "booking_month_10": "outubro",
    "booking_month_11": "novembro",
    "booking_month_12": "dezembro",
    "booking_slot_date": "{weekday}, {day} de {month}",
    "booking_weekday_0": "Segunda-feira",
    "booking_weekday_1": "Terça-feira",
    "booking_weekday_2": "Quarta-feira",
    "booking_weekday_3": "Quinta-feira",
    "booking_weekday_4": "Sexta-feira",
    "booking_weekday_5": "Sábado",
    "booking_weekday_6": "Domingo",
    "date_of_birth_month_1": "Janeiro",
    "date_of_birth_month_2": "Fevereiro",
    "date_of_birth_month_3": "Março",
    "date_of_birth_month_4": "Abril",
    "date_of_birth_month_5": "Maio",
    "date_of_birth_month_6": "Junho",
    "date_of_birth_month_7": "Julho",
    "date_of_birth_month_8": "Agosto",
    "date_of_birth_month_9": "Setembro",
    "date_of_birth_month_10": "Outubro",
    "date_of_birth_month_11": "Novembro",
    "date_of_birth_month_12": "Dezembro",
    "activation_date_of_birth_invalid": (
        "Verifique a data de nascimento: informe uma data real, por exemplo, 15 de junho de 1985."
    ),
    "date_of_birth": "Data de nascimento",
    "date_of_birth_day": "Dia",
    "date_of_birth_hint": "Por exemplo, 15 de junho de 1985.",
    "date_of_birth_month": "Mês",
    "date_of_birth_month_choose": "Escolha um mês",
    "date_of_birth_year": "Ano",
    "activation_password_rejected": (
        "Escolha outra senha: use pelo menos 12 caracteres, evite palavras ou padrões comuns e "
        "não inclua seu nome de usuário, e-mail, data de nascimento nem número do cartão de saúde."
    ),
    "activation_reenter_password": "Seus outros dados foram mantidos: digite sua senha novamente.",
}

# Every supported locale gets an entry so `portal_text` never falls back wholesale to English and
# a translator can start filling one in without touching anything else. Nearly empty today: the
# per-key merge in `portal_text` supplies the English string for anything a locale has not defined,
# which is what makes a half-finished translation render instead of raising KeyError.
for _locale in SUPPORTED_LOCALES:
    TEXT_CATALOG.setdefault(_locale.code, {})

# Self sign-up (carlos-portal#15). Merged into each locale rather than assigned, and after every
# locale exists, so translations defined above for other pages are kept.
_SIGN_UP_TEXT: dict[str, dict[str, str]] = {
    "fr": {
        "sign_up_contact_clinic": (
            "Si votre clinique n’a pas votre adresse courriel, ou en a une ancienne, communiquez "
            "avec la clinique avant de demander un compte."
        ),
        "sign_up_details_invalid": (
            "Vérifiez vos renseignements : entrez votre numéro de carte santé, une date de "
            "naissance réelle et une adresse courriel valide."
        ),
        "sign_up_email": "Adresse courriel inscrite à votre dossier à la clinique",
        "sign_up_email_hint": (
            "Sert seulement à vérifier vos renseignements. Le lien est envoyé uniquement à "
            "l’adresse courriel déjà inscrite au dossier de la clinique."
        ),
        "sign_up_heading": "Demander un compte du portail",
        "sign_up_intro": (
            "Entrez votre numéro de carte santé, votre date de naissance et l’adresse courriel "
            "inscrite à votre dossier à la clinique. Si ces renseignements correspondent au "
            "dossier de la clinique, vous recevrez par courriel un lien pour terminer la "
            "configuration de votre compte."
        ),
        "sign_up_result": (
            "Si vos renseignements correspondent à notre dossier, nous vous avons envoyé par "
            "courriel un lien pour terminer la configuration de votre compte. Si vous ne recevez "
            "rien, communiquez avec la clinique."
        ),
        "sign_up_result_heading": "Demande reçue",
        "sign_up_submit": "Demander un compte",
        "sign_up_unavailable": (
            "Les demandes de compte sont temporairement indisponibles. Réessayez plus tard ou "
            "communiquez avec la clinique."
        ),
    },
    "es": {
        "sign_up_contact_clinic": (
            "Si su clínica no tiene su correo electrónico, o tiene uno antiguo, comuníquese con la "
            "clínica antes de solicitar una cuenta."
        ),
        "sign_up_details_invalid": (
            "Revise sus datos: introduzca su número de tarjeta de salud, una fecha de nacimiento "
            "real y un correo electrónico válido."
        ),
        "sign_up_email": "Correo electrónico registrado en su clínica",
        "sign_up_email_hint": (
            "Solo se usa para comprobar sus datos. El enlace se envía únicamente al correo "
            "electrónico que ya figura en los registros de su clínica."
        ),
        "sign_up_heading": "Solicitar una cuenta del portal",
        "sign_up_intro": (
            "Introduzca su número de tarjeta de salud, su fecha de nacimiento y el correo "
            "electrónico que su clínica tiene registrado. Si coinciden con los registros de la "
            "clínica, recibirá por correo electrónico un enlace para terminar de configurar su "
            "cuenta."
        ),
        "sign_up_result": (
            "Si sus datos coinciden con nuestros registros, le hemos enviado por correo "
            "electrónico un enlace para terminar de configurar su cuenta. Si no recibe nada, "
            "comuníquese con la clínica."
        ),
        "sign_up_result_heading": "Solicitud recibida",
        "sign_up_submit": "Solicitar cuenta",
        "sign_up_unavailable": (
            "Las solicitudes de cuenta no están disponibles por el momento. Inténtelo de nuevo más "
            "tarde o comuníquese con la clínica."
        ),
    },
    "pl": {
        "sign_up_contact_clinic": (
            "Jeśli przychodnia nie ma Twojego adresu e-mail albo ma nieaktualny, skontaktuj się "
            "z przychodnią, zanim poprosisz o założenie konta."
        ),
        "sign_up_details_invalid": (
            "Sprawdź swoje dane: wpisz numer karty zdrowia, poprawną datę urodzenia i prawidłowy "
            "adres e-mail."
        ),
        "sign_up_email": "Adres e-mail zapisany w przychodni",
        "sign_up_email_hint": (
            "Służy tylko do sprawdzenia Twoich danych. Link jest wysyłany wyłącznie na adres "
            "e-mail, który przychodnia ma już w dokumentacji."
        ),
        "sign_up_heading": "Poproś o założenie konta w portalu",
        "sign_up_intro": (
            "Wpisz numer karty zdrowia, datę urodzenia i adres e-mail, który przychodnia ma w "
            "Twojej dokumentacji. Jeśli dane zgadzają się z dokumentacją przychodni, otrzymasz "
            "e-mailem link do dokończenia konfiguracji konta."
        ),
        "sign_up_result": (
            "Jeśli Twoje dane zgadzają się z naszą dokumentacją, wysłaliśmy Ci e-mailem link do "
            "dokończenia konfiguracji konta. Jeśli nic nie dotrze, skontaktuj się z przychodnią."
        ),
        "sign_up_result_heading": "Prośba otrzymana",
        "sign_up_submit": "Wyślij prośbę",
        "sign_up_unavailable": (
            "Chwilowo nie można wysłać prośby o założenie konta. Spróbuj ponownie później lub "
            "skontaktuj się z przychodnią."
        ),
    },
    "pt-BR": {
        "sign_up_contact_clinic": (
            "Se a sua clínica não tiver o seu e-mail, ou tiver um antigo, entre em contato com a "
            "clínica antes de solicitar uma conta."
        ),
        "sign_up_details_invalid": (
            "Verifique seus dados: informe o número do cartão de saúde, uma data de nascimento "
            "real e um e-mail válido."
        ),
        "sign_up_email": "E-mail cadastrado na sua clínica",
        "sign_up_email_hint": (
            "Usado apenas para conferir seus dados. O link é enviado somente para o e-mail que já "
            "consta no cadastro da sua clínica."
        ),
        "sign_up_heading": "Solicitar uma conta no portal",
        "sign_up_intro": (
            "Informe o número do seu cartão de saúde, sua data de nascimento e o e-mail que consta "
            "no seu cadastro na clínica. Se os dados conferirem com os registros da clínica, você "
            "receberá por e-mail um link para concluir a configuração da sua conta."
        ),
        "sign_up_result": (
            "Se seus dados conferirem com nossos registros, enviamos para você por e-mail um link "
            "para concluir a configuração da sua conta. Se nada chegar, entre em contato com a "
            "clínica."
        ),
        "sign_up_result_heading": "Solicitação recebida",
        "sign_up_submit": "Solicitar conta",
        "sign_up_unavailable": (
            "As solicitações de conta estão temporariamente indisponíveis. Tente novamente mais "
            "tarde ou entre em contato com a clínica."
        ),
    },
}
for _locale_code, _sign_up_text in _SIGN_UP_TEXT.items():
    TEXT_CATALOG.setdefault(_locale_code, {}).update(_sign_up_text)

def normalize_locale(value: str | None) -> str | None:
    """Match a requested locale to a supported one, case- and separator-insensitively.

    Accepts the shapes a browser actually sends: `PT-br`, `pt_BR`, and a bare `pt` all resolve to
    `pt-BR`. Returns None when nothing matches, so callers can distinguish "not supported" from
    "supported and happens to be the default".
    """
    if not value:
        return None
    candidate = value.strip().replace("_", "-").casefold()
    if not candidate:
        return None
    for locale in SUPPORTED_LOCALES:
        if locale.code.casefold() == candidate:
            return locale.code
    # A bare language subtag matches the first supported locale in that language, so `pt` finds
    # `pt-BR` without the caller having to know the region.
    language = candidate.split("-", 1)[0]
    for locale in SUPPORTED_LOCALES:
        if locale.code.casefold().split("-", 1)[0] == language:
            return locale.code
    return None


def _accept_language_weight(parameters: str) -> float:
    weight = 1.0
    for parameter in parameters.split(";"):
        name, _, raw_value = parameter.partition("=")
        if name.strip().casefold() != "q":
            continue
        try:
            weight = float(raw_value)
        except ValueError:
            weight = 0.0
        if not math.isfinite(weight) or not 0 <= weight <= 1:
            weight = 0.0
    return weight


def parse_accept_language(header_value: str | None) -> str | None:
    """Pick the highest-weighted supported locale from an Accept-Language header.

    Deliberately tolerant: a malformed q-value sorts as 0 rather than raising, because a bad header
    from one browser must not turn a page render into a 500.
    """
    if not header_value:
        return None
    candidates: list[tuple[float, int, str]] = []
    for position, part in enumerate(header_value.split(",")):
        tag, _, parameters = part.strip().partition(";")
        if not tag.strip() or tag.strip() == "*":
            continue
        weight = _accept_language_weight(parameters)
        if weight <= 0:
            continue
        # Position breaks ties in header order, which is the order the browser expressed.
        candidates.append((-weight, position, tag.strip()))
    for _, _, tag in sorted(candidates):
        matched = normalize_locale(tag)
        if matched is not None:
            return matched
    return None


def resolve_locale(
    *,
    cookie_value: str | None = None,
    accept_language: str | None = None,
) -> str:
    """Resolve the locale to render in: explicit choice first, then the browser's, then English."""
    return (
        normalize_locale(cookie_value) or parse_accept_language(accept_language) or DEFAULT_LOCALE
    )


MYCARLOS_TEXT_CATALOG: dict[str, dict[str, str]] = {
    "en": {
        "mycarlos_mfa_rate_limited": (
            "A sign-in code was sent recently. Please wait before requesting another."
        ),
        "mycarlos_link": "Link myCarlos",
        "mycarlos_devices": "Linked devices",
        "mycarlos_instruction": (
            "In myCarlos, choose the option to link to your clinic’s portal, then enter this code."
        ),
        "mycarlos_code_label": "One-time code",
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
        "mycarlos_keep": "Keep device",
        "mycarlos_paused": (
            "Linking is paused because of too many incorrect codes. Try again later."
        ),
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
    },
    "fr": {
        "mycarlos_mfa_rate_limited": (
            "Un code de connexion vient d’être envoyé. Veuillez patienter avant d’en "
            "demander un autre."
        ),
        "mycarlos_link": "Associer myCarlos",
        "mycarlos_devices": "Appareils associés",
        "mycarlos_instruction": (
            "Dans myCarlos, choisissez l’option permettant d’associer le portail de "
            "votre clinique, puis saisissez ce code."
        ),
        "mycarlos_code_label": "Code à usage unique",
        "mycarlos_lifetime": (
            "Ce code est valable une seule fois, pendant 10 minutes. Restez connecté à ce portail."
        ),
        "mycarlos_approval": (
            "L’appareil doit aussi être approuvé avant de pouvoir recevoir des documents."
        ),
        "mycarlos_create": "Créer un code",
        "mycarlos_another": "Créer un autre code",
        "mycarlos_linked": "Associé le",
        "mycarlos_last_seen": "Dernière activité",
        "mycarlos_empty": (
            "Aucun appareil associé. Choisissez Associer myCarlos pour en ajouter un."
        ),
        "mycarlos_remove_question": "Retirer cet appareil ?",
        "mycarlos_remove_effect": (
            "Cet appareil ne recevra plus de nouveaux documents. Pour le réutiliser, "
            "associez-le à nouveau. Les documents déjà enregistrés dans myCarlos y "
            "restent."
        ),
        "mycarlos_remove": "Retirer l’appareil",
        "mycarlos_keep": "Garder l’appareil",
        "mycarlos_paused": (
            "L’association est suspendue en raison d’un trop grand nombre de codes "
            "incorrects. Réessayez plus tard."
        ),
        "mycarlos_unavailable": "L’association est indisponible. Contactez votre clinique.",
        "mycarlos_removed": "Appareil retiré.",
        "mycarlos_not_seen": "Aucune activité",
        "mycarlos_mfa_required": (
            "Vérifiez votre connexion avant d’associer ou de retirer un appareil."
        ),
        "mycarlos_verify": "Vérifier la connexion",
        "mycarlos_portal_address": "Adresse du portail",
        "mycarlos_qr_label": "Scanner dans myCarlos",
        "mycarlos_qr_alt": "Code QR pour lier myCarlos à ce portail.",
        "mycarlos_qr_unavailable": (
            "Code QR indisponible. Contactez votre clinique si vous ne pouvez pas utiliser "
            "cette adresse du portail."
        ),
    },
    "es": {
        "mycarlos_mfa_rate_limited": (
            "Se ha enviado un código de acceso hace poco. Espere antes de pedir otro."
        ),
        "mycarlos_link": "Vincular myCarlos",
        "mycarlos_devices": "Dispositivos vinculados",
        "mycarlos_instruction": (
            "En myCarlos, elija la opción para vincular el portal de su clínica y luego"
            " introduzca este código."
        ),
        "mycarlos_code_label": "Código de un solo uso",
        "mycarlos_lifetime": (
            "Este código sirve una sola vez, durante 10 minutos. Mantenga la sesión "
            "iniciada en este portal."
        ),
        "mycarlos_approval": (
            "El dispositivo también debe ser aprobado antes de poder recibir documentos."
        ),
        "mycarlos_create": "Crear un código",
        "mycarlos_another": "Crear otro código",
        "mycarlos_linked": "Vinculado",
        "mycarlos_last_seen": "Última actividad",
        "mycarlos_empty": (
            "No hay dispositivos vinculados. Elija Vincular myCarlos para añadir uno."
        ),
        "mycarlos_remove_question": "¿Quitar este dispositivo?",
        "mycarlos_remove_effect": (
            "Este dispositivo dejará de recibir documentos nuevos. Para volver a "
            "usarlo, vincúlelo de nuevo. Los documentos ya guardados en myCarlos "
            "permanecen allí."
        ),
        "mycarlos_remove": "Quitar dispositivo",
        "mycarlos_keep": "Conservar dispositivo",
        "mycarlos_paused": (
            "La vinculación está pausada porque se introdujeron demasiados códigos "
            "incorrectos. Inténtelo más tarde."
        ),
        "mycarlos_unavailable": "La vinculación no está disponible. Contacte con su clínica.",
        "mycarlos_removed": "Dispositivo eliminado de la lista.",
        "mycarlos_not_seen": "Aún sin actividad",
        "mycarlos_mfa_required": (
            "Verifique su inicio de sesión antes de vincular o quitar un dispositivo."
        ),
        "mycarlos_verify": "Verificar inicio de sesión",
        "mycarlos_portal_address": "Dirección del portal",
        "mycarlos_qr_label": "Escanear en myCarlos",
        "mycarlos_qr_alt": "Código QR para vincular myCarlos con este portal.",
        "mycarlos_qr_unavailable": (
            "Código QR no disponible. Contacte con su clínica si no puede usar esta dirección "
            "del portal."
        ),
    },
    "pl": {
        "mycarlos_mfa_rate_limited": (
            "Kod logowania został niedawno wysłany. Poczekaj, zanim poprosisz o kolejny."
        ),
        "mycarlos_link": "Połącz myCarlos",
        "mycarlos_devices": "Połączone urządzenia",
        "mycarlos_instruction": (
            "W myCarlos wybierz opcję połączenia z portalem swojej przychodni, a "
            "następnie wpisz ten kod."
        ),
        "mycarlos_code_label": "Kod jednorazowy",
        "mycarlos_lifetime": (
            "Kod jest jednorazowy i ważny przez 10 minut. Nie wylogowuj się z tego portalu."
        ),
        "mycarlos_approval": (
            "Urządzenie musi też zostać zatwierdzone, zanim będzie mogło odbierać dokumenty."
        ),
        "mycarlos_create": "Utwórz kod",
        "mycarlos_another": "Utwórz kolejny kod",
        "mycarlos_linked": "Połączono",
        "mycarlos_last_seen": "Ostatnia aktywność",
        "mycarlos_empty": (
            "Brak połączonych urządzeń. Wybierz Połącz myCarlos, aby dodać urządzenie."
        ),
        "mycarlos_remove_question": "Usunąć to urządzenie?",
        "mycarlos_remove_effect": (
            "To urządzenie przestanie otrzymywać nowe dokumenty. Aby użyć go ponownie, "
            "połącz je jeszcze raz. Dokumenty już zapisane w myCarlos pozostaną w "
            "aplikacji."
        ),
        "mycarlos_remove": "Usuń urządzenie",
        "mycarlos_keep": "Zachowaj urządzenie",
        "mycarlos_paused": (
            "Łączenie zostało wstrzymane z powodu zbyt wielu nieprawidłowych kodów. "
            "Spróbuj ponownie później."
        ),
        "mycarlos_unavailable": "Łączenie jest niedostępne. Skontaktuj się z przychodnią.",
        "mycarlos_removed": "Urządzenie usunięte z listy.",
        "mycarlos_not_seen": "Brak aktywności",
        "mycarlos_mfa_required": "Potwierdź logowanie przed połączeniem lub usunięciem urządzenia.",
        "mycarlos_verify": "Potwierdź logowanie",
        "mycarlos_portal_address": "Adres portalu",
        "mycarlos_qr_label": "Zeskanuj w myCarlos",
        "mycarlos_qr_alt": "Kod QR do połączenia myCarlos z tym portalem.",
        "mycarlos_qr_unavailable": (
            "Kod QR jest niedostępny. Skontaktuj się ze swoją przychodnią, jeśli nie możesz "
            "użyć tego adresu portalu."
        ),
    },
    "pt-BR": {
        "mycarlos_mfa_rate_limited": (
            "Um código de acesso foi enviado há pouco. Aguarde antes de solicitar outro."
        ),
        "mycarlos_link": "Vincular o myCarlos",
        "mycarlos_devices": "Dispositivos vinculados",
        "mycarlos_instruction": (
            "No myCarlos, escolha a opção de vincular o portal da sua clínica e digite este código."
        ),
        "mycarlos_code_label": "Código de uso único",
        "mycarlos_lifetime": (
            "Este código funciona uma única vez, por 10 minutos. Mantenha a sessão "
            "iniciada neste portal."
        ),
        "mycarlos_approval": (
            "O dispositivo também precisa ser aprovado antes de poder receber documentos."
        ),
        "mycarlos_create": "Criar um código",
        "mycarlos_another": "Criar outro código",
        "mycarlos_linked": "Vinculado em",
        "mycarlos_last_seen": "Última atividade",
        "mycarlos_empty": (
            "Nenhum dispositivo vinculado. Escolha Vincular o myCarlos para adicionar um."
        ),
        "mycarlos_remove_question": "Remover este dispositivo?",
        "mycarlos_remove_effect": (
            "Este dispositivo deixará de receber novos documentos. Para usá-lo "
            "novamente, vincule-o de novo. Os documentos já salvos no myCarlos "
            "permanecem lá."
        ),
        "mycarlos_remove": "Remover dispositivo",
        "mycarlos_keep": "Manter dispositivo",
        "mycarlos_paused": (
            "A vinculação está pausada devido ao excesso de códigos incorretos. Tente "
            "novamente mais tarde."
        ),
        "mycarlos_unavailable": "A vinculação está indisponível. Entre em contato com sua clínica.",
        "mycarlos_removed": "Dispositivo removido.",
        "mycarlos_not_seen": "Ainda sem atividade",
        "mycarlos_mfa_required": (
            "Verifique seu acesso antes de vincular ou remover um dispositivo."
        ),
        "mycarlos_verify": "Verificar acesso",
        "mycarlos_portal_address": "Endereço do portal",
        "mycarlos_qr_label": "Escanear no myCarlos",
        "mycarlos_qr_alt": "Código QR para vincular o myCarlos a este portal.",
        "mycarlos_qr_unavailable": (
            "Código QR indisponível. Entre em contato com sua clínica se não conseguir usar "
            "este endereço do portal."
        ),
    },
}

for _mycarlos_locale, _mycarlos_strings in MYCARLOS_TEXT_CATALOG.items():
    TEXT_CATALOG.setdefault(_mycarlos_locale, {}).update(_mycarlos_strings)


def portal_text(locale: str = DEFAULT_LOCALE) -> dict[str, str]:
    """The text catalog for `locale`, with English filling any key it has not translated."""
    text = TEXT_CATALOG[DEFAULT_LOCALE].copy()
    if locale != DEFAULT_LOCALE:
        text.update(TEXT_CATALOG.get(locale, {}))
    return text


def supported_locale_options(current_locale: str = DEFAULT_LOCALE) -> tuple[dict[str, object], ...]:
    return tuple(
        {
            "code": locale.code,
            "short_label": locale.short_label,
            "label": locale.label,
            "is_selected": locale.code == current_locale,
        }
        for locale in SUPPORTED_LOCALES
    )


def format_booking_time(
    value: datetime,
    locale: str = DEFAULT_LOCALE,
    timezone_name: str = "UTC",
) -> tuple[str, str]:
    """An appointment time as the patient reads it: ("Tuesday 14 October", "10:30").

    Weekday and month names come from the catalog, not the process locale, so they follow the
    patient's language; the time is shown in the clinic's time zone.
    """
    text = portal_text(locale)
    utc_value = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    local_value = utc_value.astimezone(ZoneInfo(timezone_name))
    date_text = text["booking_slot_date"].format(
        weekday=text[f"booking_weekday_{local_value.weekday()}"],
        day=local_value.day,
        month=text[f"booking_month_{local_value.month}"],
    )
    time_text = text["booking_slot_time"].format(
        hour=local_value.hour,
        minute=local_value.minute,
    )
    return date_text, time_text


def format_portal_datetime(
    value: datetime,
    locale: str = DEFAULT_LOCALE,
    timezone_name: str = "UTC",
) -> str:
    date_format = DATETIME_FORMATS.get(locale, DATETIME_FORMATS[DEFAULT_LOCALE])
    utc_value = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return utc_value.astimezone(ZoneInfo(timezone_name)).strftime(date_format)
