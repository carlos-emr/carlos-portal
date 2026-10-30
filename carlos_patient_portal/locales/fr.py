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

"""French (fr) text for the patient portal.

Translate keys from `locales/en.py`, keeping each `{placeholder}` exactly. A key left out
falls back to English (`i18n.portal_text`). Once every key is in, list this locale as
complete in tests/test_i18n_catalog.py so the parity test keeps it complete.
"""

TEXT: dict[str, str] = {
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

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
    "mycarlos_mfa_rate_limited": (
        "Un code de connexion vient d’être envoyé. Veuillez patienter avant d’en demander un autre."
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
    "mycarlos_empty": "Aucun appareil associé. Choisissez Associer myCarlos pour en ajouter un.",
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
}
