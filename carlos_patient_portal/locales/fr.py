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
    "account": "Compte",
    "account_change_error": "La modification du compte n’a pas pu être effectuée.",
    "account_help": "Aide pour le compte",
    "account_status_contact_notice_failed": (
        "Coordonnées du portail mises à jour, mais le courriel de confirmation n’a pas pu être "
        "envoyé. Contactez la clinique si vous ne vous attendiez pas à ce changement."
    ),
    "account_status_contact_updated": (
        "Coordonnées du portail mises à jour. Le personnel vérifiera les données démographiques "
        "correspondantes dans CARLOS."
    ),
    "account_status_contact_confirmation_required": (
        "Confirmez la nouvelle adresse courriel et saisissez le code envoyé au nouveau numéro de "
        "téléphone. Vos coordonnées actuelles restent actives jusqu’à ce que les deux soient "
        "confirmés."
    ),
    "account_status_email_confirmation_required": (
        "Consultez la nouvelle adresse courriel pour y trouver un lien de confirmation. Votre "
        "adresse actuelle continue de recevoir les codes de vérification et les liens de "
        "réinitialisation du mot de passe jusqu’à ce que vous l’utilisiez."
    ),
    "account_status_email_confirmation_notice_failed": (
        "La confirmation n’a pas pu être envoyée par courriel à la nouvelle adresse. Vos "
        "coordonnées n’ont pas été modifiées. Réessayez ou contactez la clinique."
    ),
    "account_status_phone_confirmation_required": (
        "Saisissez le code de confirmation envoyé au nouveau numéro de téléphone. Votre numéro de "
        "téléphone actuel reste actif jusqu’à ce que le nouveau soit confirmé."
    ),
    "account_status_phone_confirmation_invalid": (
        "Le code de confirmation du téléphone est invalide ou expiré. Demandez un autre code et "
        "réessayez."
    ),
    "account_status_phone_confirmation_notice_failed": (
        "Un code de confirmation n’a pas pu être envoyé au nouveau numéro de téléphone. Vos "
        "coordonnées n’ont pas été modifiées. Réessayez ou contactez la clinique."
    ),
    "account_status_phone_confirmation_rate_limited": (
        "Un code de confirmation par téléphone a été envoyé récemment. Veuillez patienter avant "
        "d’en demander un autre."
    ),
    "account_status_mfa_updated": "Paramètres de l’AMF mis à jour.",
    "account_status_no_change": "Aucune modification du compte.",
    "account_status_password_updated": "Mot de passe mis à jour.",
    "all_providers": "Tous les professionnels",
    "activate_account": "Activer le compte",
    "activation_details": (
        "Saisissez les renseignements d’invitation fournis par votre clinique et créez vos "
        "identifiants de connexion au portail."
    ),
    "activation_date_of_birth_invalid": (
        "Vérifiez la date de naissance : entrez une date réelle, par exemple 15 juin 1985."
    ),
    "activation_error": "Les renseignements d’activation n’ont pas pu être vérifiés.",
    "activation_password_rejected": (
        "Choisissez un autre mot de passe : utilisez au moins 12 caractères, évitez les mots ou "
        "les suites courants, et n’y mettez pas votre nom d’utilisateur, votre courriel, votre "
        "date de naissance ni votre numéro de carte santé."
    ),
    "activation_reenter_password": (
        "Vos autres renseignements sont conservés : saisissez de nouveau votre mot de passe."
    ),
    "activation_heading": "Activez votre compte",
    "activation_rate_limited": (
        "Trop de tentatives d’activation ont été faites. Veuillez patienter avant de réessayer."
    ),
    "activation_success": "Votre compte du portail est prêt.",
    "activation_success_heading": "Compte activé",
    "back_to_sign_in": "Retour à la connexion",
    "booking_prompt_contact": "Pour prendre rendez-vous, contactez {clinic_name}.",
    "booking_prompt_contact_phone": "Pour prendre rendez-vous, appelez {clinic_name} au {phone}.",
    "booking_prompt_no_online_booking": "Les rendez-vous ne peuvent pas être pris dans ce portail.",
    "booking_prompt_suggested_by": "{provider} a suggéré ce rendez-vous.",
    "booking_prompt_suggested_by_clinic": "Votre clinique a suggéré ce rendez-vous.",
    "booking_prompt_title_annual_exam": "Prenez rendez-vous pour votre examen annuel",
    "booking_prompt_title_follow_up": "Prenez un rendez-vous de suivi",
    "booking_prompt_title_lab_review": (
        "Prenez rendez-vous pour revoir vos résultats de laboratoire"
    ),
    "booking_prompt_urgency_as_soon_as_possible": "Veuillez prendre rendez-vous dès que possible.",
    "booking_prompt_urgency_routine": "Veuillez prendre rendez-vous au moment qui vous convient.",
    "booking_prompt_urgency_soon": "Veuillez prendre rendez-vous au cours des prochaines semaines.",
    "booking_booked": "Rendez-vous pris le {date} à {time}.",
    "booking_choice_error": (
        "Cette plage horaire n’a pas pu être choisie. Lisez le message ci-dessous et réessayez."
    ),
    "booking_choice_pending": "Nous confirmons votre plage horaire auprès de la clinique.",
    "booking_choice_pending_overdue": (
        "La clinique confirmera votre plage horaire. Si c’est urgent, appelez la clinique."
    ),
    "booking_choice_pending_overdue_phone": (
        "La clinique confirmera votre plage horaire. Si c’est urgent, appelez la clinique au "
        "{phone}."
    ),
    "booking_choice_expired": (
        "Cette plage horaire est passée avant que la clinique puisse la confirmer. Veuillez en "
        "choisir une autre."
    ),
    "booking_choice_expired_contact": (
        "Cette plage horaire est passée avant que la clinique puisse la confirmer. Veuillez "
        "contacter la clinique."
    ),
    "booking_choose": "Choisir cette plage",
    "booking_decline": "Aucune ne me convient",
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
    "booking_offer_intro": (
        "La clinique vous propose ces plages horaires. Choisissez-en une et la clinique la "
        "confirmera."
    ),
    "booking_slot_date": "{weekday} {day} {month}",
    "booking_slot_detail_separator": " · ",
    "booking_slot_duration_one": "{minutes} minute",
    "booking_slot_duration_other": "{minutes} minutes",
    "booking_slot_taken": "Cette plage horaire vient d’être prise. Veuillez en choisir une autre.",
    "booking_slot_taken_contact": (
        "Cette plage horaire vient d’être prise. Veuillez contacter la clinique."
    ),
    "booking_slot_time": "{hour:02d} h {minute:02d}",
    "booking_slot_when": "{date} à {time}",
    "booking_slots_legend": "Plages horaires disponibles",
    "booking_visit_mode_in_person": "En personne",
    "booking_visit_mode_phone": "Par téléphone",
    "booking_visit_mode_video": "Par vidéo",
    "booking_weekday_0": "Lundi",
    "booking_weekday_1": "Mardi",
    "booking_weekday_2": "Mercredi",
    "booking_weekday_3": "Jeudi",
    "booking_weekday_4": "Vendredi",
    "booking_weekday_5": "Samedi",
    "booking_weekday_6": "Dimanche",
    "email_change_confirm": "Confirmer l’adresse courriel",
    "email_change_complete_error": (
        "Ce lien de confirmation n’est plus valide. Demandez de nouveau le changement à partir de "
        "la page de votre compte."
    ),
    "email_change_complete_heading": "Confirmez votre nouvelle adresse courriel",
    "email_change_complete_intro": (
        "La confirmation met à jour l’adresse courriel utilisée pour les codes de vérification de "
        "connexion et les liens de réinitialisation du mot de passe."
    ),
    "email_change_success": (
        "Votre adresse courriel est mise à jour. Le personnel de la clinique vérifiera les "
        "renseignements correspondants du dossier CARLOS."
    ),
    "email_change_success_heading": "Adresse courriel confirmée",
    "email_change_phone_confirmation_pending": (
        "Votre nouvelle adresse courriel est confirmée. Connectez-vous et saisissez le code envoyé "
        "au nouveau numéro de téléphone pour terminer le changement de coordonnées."
    ),
    "change_password": "Changer le mot de passe",
    "clinic": "Clinique",
    "clinic_help": "Aide de la clinique",
    "clinic_help_message": (
        "Contactez la clinique si vous ne pouvez pas accéder à votre compte ou à votre méthode de "
        "vérification."
    ),
    "contact_info": "Coordonnées",
    "contact_change_notice_failed": (
        "Vos coordonnées sont mises à jour et vous avez été déconnecté, mais un avis de sécurité "
        "n’a pas pu être envoyé. Contactez la clinique si vous n’êtes pas à l’origine de ce "
        "changement."
    ),
    "contact_change_success": (
        "Vos coordonnées sont mises à jour. Par mesure de sécurité, vous avez été déconnecté; "
        "reconnectez-vous avec votre méthode de vérification mise à jour. Le personnel de la "
        "clinique vérifiera les renseignements correspondants du dossier CARLOS."
    ),
    "contact_change_success_heading": "Coordonnées mises à jour",
    "contact_the_clinic": "Contactez la clinique",
    "copy": "Copier",
    "copy_failed": "Sélectionnez et copiez manuellement",
    "copied": "Copié",
    "current_password": "Mot de passe actuel",
    "dashboard": "Tableau de bord",
    "dashboard_account_description": "Gérez votre mot de passe et vos coordonnées.",
    "dashboard_documents_description": (
        "Les documents pourraient être offerts dans une version future."
    ),
    "dashboard_email_passwords_description": (
        "Récupérez les mots de passe des courriels chiffrés envoyés par votre clinique."
    ),
    "dashboard_greeting": "Portail patient",
    "dashboard_help_description": (
        "Trouvez les renseignements d’aide sur la clinique et votre compte."
    ),
    "dashboard_messages_description": (
        "Demandes de votre clinique, par exemple un rappel de prendre rendez-vous."
    ),
    "date_from": "Date de début",
    "date_format_error": "Saisissez des dates de début et de fin valides.",
    "filter_error": "Saisissez des filtres valides.",
    "date_range_error": "La date de début ne doit pas être postérieure à la date de fin.",
    "date_of_birth": "Date de naissance",
    "date_of_birth_day": "Jour",
    "date_of_birth_hint": "Par exemple, 15 juin 1985.",
    "date_of_birth_month": "Mois",
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
    "date_of_birth_month_choose": "Choisissez un mois",
    "date_of_birth_year": "Année",
    "date_to": "Date de fin",
    "development_mfa_code": (
        "Code d’AMF de développement (le même code que celui envoyé par courriel, pour accélérer "
        "les tests; sera retiré plus tard) :"
    ),
    "development_reset_link": (
        "Lien de réinitialisation du mot de passe de développement (aussi envoyé par courriel "
        "lorsque le courriel est configuré) :"
    ),
    "documents": "Documents",
    "email": "Courriel",
    "email_codes_rate": "Les codes par courriel peuvent être renvoyés une fois par minute.",
    "email_password": "Mot de passe de courriel",
    "email_password_page_indicator": "Page {page} de {total_pages}",
    "email_password_pages": "Pages des mots de passe de courriel",
    "email_passwords": "Mots de passe de courriel",
    "email_passwords_region": "Mots de passe de courriel",
    "forgot_username_password": "Nom d’utilisateur ou mot de passe oublié?",
    "forgot_username_help": (
        "Si vous ne connaissez pas votre nom d’utilisateur, contactez la clinique."
    ),
    "future": "À venir",
    "health_card_number": "Numéro de carte santé (assurance maladie)",
    "help": "Aide",
    "hide_password": "Masquer le mot de passe",
    "incorrect_mfa_code": "Le code n’a pas été accepté. Réessayez ou demandez un nouveau code.",
    "incorrect_username_or_password": "Nom d’utilisateur ou mot de passe incorrect",
    "invite_code": "Code d’invitation",
    "language_aria_label": "Langue",
    "logo_alt": "CARLOS",
    "logout": "Déconnexion",
    "message_back": "Retour aux messages",
    "message_new": "Nouveau",
    "message_not_found": "Ce message n’est plus disponible.",
    "message_sent_at": "Envoyé le {sent_at}",
    "messages": "Messages",
    "messages_empty": "Vous n’avez aucun message de votre clinique.",
    "messages_new_count_one": "{count} nouveau",
    "messages_new_count_other": "{count} nouveaux",
    "mfa": "AMF",
    "mfa_code": "Code",
    "mfa_code_sent_email": "Code envoyé à {destination} par courriel.",
    "mfa_code_sent_email_unmasked": "Code envoyé à votre adresse courriel.",
    "mfa_code_sent_sms": "Code envoyé à {destination} par SMS.",
    "mfa_code_sent_sms_unmasked": "Code envoyé à votre numéro de cellulaire.",
    "mfa_delivery_unavailable": "Ce mode d’envoi n’est pas disponible.",
    "mfa_email": "Courriel",
    "mfa_heading": "Code de vérification",
    "mfa_help_message": (
        "Contactez {clinic_name} si vous ne pouvez pas recevoir ou utiliser votre code de "
        "vérification."
    ),
    "mfa_new_code_sent_email": "Un nouveau code a été envoyé par courriel.",
    "mfa_new_code_sent_sms": "Un nouveau code a été envoyé par SMS.",
    "mfa_rate_limited_one": "Un code a été envoyé récemment. Réessayez dans {seconds} seconde.",
    "mfa_rate_limited_other": "Un code a été envoyé récemment. Réessayez dans {seconds} secondes.",
    "mfa_resend": "Renvoyer le code",
    "mfa_sign_in_again": "Reconnectez-vous pour demander un nouveau code de vérification.",
    "mfa_send_by": "Envoyer le code par",
    "mfa_settings": "Paramètres de l’AMF",
    "mfa_sms": "SMS",
    "mfa_sms_rate": "Les codes par SMS peuvent être renvoyés une fois toutes les cinq minutes.",
    "mfa_verify": "Vérifier",
    "mfa_verification_failed": "L’AMF n’a pas pu être vérifiée.",
    "modal_close": "OK",
    "module_navigation": "Modules du portail",
    "mfa_method": "Méthode",
    "new_password": "Nouveau mot de passe",
    "new_password_confirmation": "Confirmer le nouveau mot de passe",
    "next": "Suivant",
    "no_email_passwords": "Aucun mot de passe de courriel",
    "no_matching_email_passwords": "Aucun mot de passe de courriel correspondant",
    "open_reset_page": "Ouvrir la page de réinitialisation",
    "password_label": "Mot de passe",
    "password_hidden": "Masqué",
    "password_for": "Mot de passe pour {subject}",
    "password_confirmation": "Confirmer le mot de passe",
    "password_invalid": (
        "Le nouveau mot de passe ne respecte pas les exigences relatives aux mots de passe."
    ),
    "password_mismatch": "La confirmation du mot de passe ne correspond pas.",
    "password_placeholder": "mot de passe",
    "password_requirements": (
        "Utilisez au moins 12 caractères. Évitez les mots de passe courants ainsi que les "
        "renseignements sur votre compte, votre clinique ou vous-même (renseignements personnels); "
        "plusieurs mots sans lien entre eux sont un bon choix."
    ),
    "password_reset_complete_error": (
        "Le lien de réinitialisation du mot de passe est invalide ou a expiré."
    ),
    "password_reset_complete_heading": "Choisissez un nouveau mot de passe",
    "password_reset_forced": "Vous devez réinitialiser votre mot de passe avant de vous connecter.",
    "password_reset_link_sent": (
        "Si les renseignements du compte correspondent, un lien de réinitialisation du mot de "
        "passe a été envoyé par courriel."
    ),
    "password_reset_request_details": (
        "Saisissez votre nom d’utilisateur du portail et l’adresse courriel inscrite auprès de "
        "votre clinique."
    ),
    "password_reset_request_heading": "Réinitialisez votre mot de passe",
    "password_reset_send": "Envoyer le lien de réinitialisation",
    "password_reset_success": (
        "Votre mot de passe a été réinitialisé. Connectez-vous avec le nouveau mot de passe."
    ),
    "password_reset_success_heading": "Mot de passe réinitialisé",
    "password_reset_update": "Mettre à jour le mot de passe",
    "password_updated": "Mot de passe mis à jour",
    "patient_dashboard": "Tableau de bord du patient",
    "phone": "Téléphone",
    "phone_required_for_sms": "Obligatoire lorsque SMS est sélectionné.",
    "phone_confirmation_code": "Code de confirmation du téléphone",
    "confirm_phone": "Confirmer le numéro de téléphone",
    "resend_phone_confirmation": "Envoyer un autre code",
    "previous": "Précédent",
    "provider": "Professionnel",
    "provider_options_truncated": (
        "Seuls les professionnels les plus récents sont affichés. Utilisez la zone de recherche "
        "pour affiner vos résultats."
    ),
    "reveal": "Afficher",
    "reveal_failed": "Le mot de passe n’a pas pu être affiché. Réessayez.",
    "reveal_password_hint": (
        "Saisissez votre mot de passe actuel avant d’afficher une phrase de passe."
    ),
    "password_reset_temporarily_unavailable": (
        "La réinitialisation du mot de passe est temporairement indisponible. Veuillez réessayer "
        "sous peu."
    ),
    "revealing": "Affichage en cours...",
    "reset_filters": "Effacer les filtres",
    "search": "Rechercher",
    "sent": "Envoyé",
    "session_locked_details": (
        "Le personnel de la clinique doit déverrouiller ce compte avant toute nouvelle connexion "
        "ou réinitialisation du mot de passe. Contactez la clinique pour obtenir de l’aide."
    ),
    "request_failed_heading": "La demande n’a pas pu être traitée",
    "request_failed_details": (
        "Le portail n’a pas pu traiter cette demande. Cela signifie généralement que la page est "
        "restée ouverte un certain temps : retournez au portail et réessayez."
    ),
    "service_busy_heading": "Trop de demandes",
    "service_busy_details": (
        "Le portail a reçu trop de demandes de cette connexion. Attendez un moment et réessayez."
    ),
    "service_maintenance_heading": "Portail indisponible",
    "service_maintenance_details": (
        "Le portail est temporairement indisponible pour cause d’entretien. Réessayez sous peu ou "
        "contactez la clinique si vous avez besoin d’aide maintenant."
    ),
    "service_name_default": "Portail patient CARLOS",
    "service_unavailable_heading": "Portail temporairement indisponible",
    "service_unavailable_details": (
        "Le portail est inaccessible pour le moment. Réessayez dans quelques minutes ou contactez "
        "la clinique si vous avez besoin d’aide maintenant."
    ),
    "session_locked_heading": "Compte verrouillé",
    "sign_in_aria_label": "Connexion",
    "sign_in_button": "Connexion",
    "sign_in_heading": "Connexion",
    "show_password": "Afficher le mot de passe",
    "source_code": "Code source",
    "subject": "Objet",
    "unavailable": "Indisponible",
    "update_contact": "Mettre à jour les coordonnées",
    "update_mfa": "Mettre à jour l’AMF",
    "update_password": "Mettre à jour le mot de passe",
    "username": "Nom d’utilisateur",
    "username_label": "Nom d’utilisateur",
    "username_placeholder": "nom d’utilisateur",
    "username_unavailable": "Ce nom d’utilisateur n’est pas disponible.",
    "verification_delivery_failed": (
        "Le code de vérification n’a pas pu être envoyé. Veuillez réessayer."
    ),
    "view_module": "Ouvrir",
}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
    "mycarlos_mfa_rate_limited": (
        "Un code de connexion vient d’être envoyé. Veuillez patienter avant d’en demander un autre."
    ),
    "mycarlos_link": "Associer myCarlos",
    "mycarlos_devices": "Appareils associés",
    "mycarlos_instruction": (
        "Dans myCarlos, choisissez l’option permettant d’associer le portail de votre clinique, "
        "puis saisissez ce code."
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
        "Cet appareil ne recevra plus de nouveaux documents. Pour le réutiliser, associez-le à "
        "nouveau. Les documents déjà enregistrés dans myCarlos y restent."
    ),
    "mycarlos_remove": "Retirer l’appareil",
    "mycarlos_remove_named": "Retirer l’appareil : {name}",
    "mycarlos_keep": "Garder l’appareil",
    "mycarlos_paused": (
        "L’association est suspendue en raison d’un trop grand nombre de codes incorrects. "
        "Réessayez plus tard."
    ),
    "mycarlos_unavailable": "L’association est indisponible. Contactez votre clinique.",
    "mycarlos_removed": "Appareil retiré.",
    "mycarlos_not_seen": "Aucune activité",
    "mycarlos_mfa_required": "Vérifiez votre connexion avant d’associer ou de retirer un appareil.",
    "mycarlos_verify": "Vérifier la connexion",
    "mycarlos_portal_address": "Adresse du portail",
    "mycarlos_qr_label": "Scanner dans myCarlos",
    "mycarlos_qr_alt": "Code QR pour lier myCarlos à ce portail.",
    "mycarlos_qr_unavailable": (
        "Code QR indisponible. Contactez votre clinique si vous ne pouvez pas utiliser cette "
        "adresse du portail."
    ),
}
