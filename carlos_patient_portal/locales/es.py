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

"""Spanish (es) text for the patient portal.

Translate keys from `locales/en.py`, keeping each `{placeholder}` exactly. A key left out
falls back to English (`i18n.portal_text`). Once every key is in, list this locale as
complete in tests/test_i18n_catalog.py so the parity test keeps it complete.
"""

TEXT: dict[str, str] = {
    "account": "Cuenta",
    "account_change_error": "No se pudo completar el cambio de la cuenta.",
    "account_help": "Ayuda con la cuenta",
    "account_status_contact_notice_failed": (
        "Se actualizaron los datos de contacto del portal, pero no se pudo enviar el correo "
        "electrónico de confirmación. Contacte con la clínica si no esperaba este cambio."
    ),
    "account_status_contact_updated": (
        "Datos de contacto del portal actualizados. El personal revisará los datos demográficos "
        "correspondientes en CARLOS."
    ),
    "account_status_contact_confirmation_required": (
        "Confirme la nueva dirección de correo electrónico e introduzca el código enviado al nuevo "
        "número de teléfono. Sus datos de contacto actuales seguirán activos hasta que se "
        "confirmen ambos."
    ),
    "account_status_email_confirmation_required": (
        "Busque el enlace de confirmación en la nueva dirección de correo electrónico. Su "
        "dirección actual seguirá recibiendo los códigos de acceso y los enlaces de "
        "restablecimiento de contraseña hasta que use ese enlace."
    ),
    "account_status_email_confirmation_notice_failed": (
        "No se pudo enviar la confirmación a la nueva dirección de correo electrónico. Sus datos "
        "de contacto no se modificaron. Inténtelo de nuevo o contacte con la clínica."
    ),
    "account_status_phone_confirmation_required": (
        "Introduzca el código de confirmación enviado al nuevo número de teléfono. Su número de "
        "teléfono actual seguirá activo hasta que se confirme."
    ),
    "account_status_phone_confirmation_invalid": (
        "El código de confirmación del teléfono no es válido o ha caducado. Solicite otro código e "
        "inténtelo de nuevo."
    ),
    "account_status_phone_confirmation_notice_failed": (
        "No se pudo enviar un código de confirmación al nuevo número de teléfono. Sus datos de "
        "contacto no se modificaron. Inténtelo de nuevo o contacte con la clínica."
    ),
    "account_status_phone_confirmation_rate_limited": (
        "Se envió un código de confirmación al teléfono hace poco. Espere antes de solicitar otro."
    ),
    "account_status_mfa_updated": "Configuración de la verificación en dos pasos actualizada.",
    "account_status_no_change": "No hay cambios en la cuenta.",
    "account_status_password_updated": "Contraseña actualizada.",
    "all_providers": "Todos los profesionales",
    "activate_account": "Activar cuenta",
    "activation_details": (
        "Introduzca los datos de la invitación que le proporcionó su clínica y cree su acceso al "
        "portal."
    ),
    "activation_date_of_birth_invalid": (
        "Revise la fecha de nacimiento: introduzca una fecha real, por ejemplo, 15 de junio de "
        "1985."
    ),
    "activation_error": "No se pudieron verificar los datos de activación.",
    "activation_password_rejected": (
        "Elija otra contraseña: use al menos 12 caracteres, evite palabras o patrones comunes y no "
        "incluya su nombre de usuario, correo electrónico, fecha de nacimiento ni número de "
        "tarjeta de salud."
    ),
    "activation_reenter_password": "Sus demás datos se conservan: vuelva a escribir su contraseña.",
    "activation_heading": "Active su cuenta",
    "activation_rate_limited": (
        "Se realizaron demasiados intentos de activación. Espere antes de volver a intentarlo."
    ),
    "activation_success": "Su cuenta del portal está lista.",
    "activation_success_heading": "Cuenta activada",
    "back_to_sign_in": "Volver al inicio de sesión",
    "booking_prompt_contact": "Para reservar una cita, contacte con {clinic_name}.",
    "booking_prompt_contact_phone": "Para reservar una cita, llame a {clinic_name} al {phone}.",
    "booking_prompt_no_online_booking": "Las citas no se pueden reservar en este portal.",
    "booking_prompt_suggested_by": "{provider} sugirió esta cita.",
    "booking_prompt_suggested_by_clinic": "Su clínica sugirió esta cita.",
    "booking_prompt_title_annual_exam": "Reserve su examen anual",
    "booking_prompt_title_follow_up": "Reserve una cita de seguimiento",
    "booking_prompt_title_lab_review": (
        "Reserve una cita para revisar sus resultados de laboratorio"
    ),
    "booking_prompt_urgency_as_soon_as_possible": "Reserve lo antes posible.",
    "booking_prompt_urgency_routine": "Reserve en el horario que más le convenga.",
    "booking_prompt_urgency_soon": "Reserve dentro de las próximas semanas.",
    "booking_booked": "Cita reservada para el {date} a las {time}.",
    "booking_choice_error": (
        "No se pudo elegir esa hora. Revise el mensaje siguiente e inténtelo de nuevo."
    ),
    "booking_choice_pending": "Estamos confirmando su hora con la clínica.",
    "booking_choice_pending_overdue": (
        "La clínica confirmará su hora. Si es urgente, llame a la clínica."
    ),
    "booking_choice_pending_overdue_phone": (
        "La clínica confirmará su hora. Si es urgente, llame a la clínica al {phone}."
    ),
    "booking_choice_expired": (
        "Esa hora pasó antes de que la clínica pudiera confirmarla. Elija otra."
    ),
    "booking_choice_expired_contact": (
        "Esa hora pasó antes de que la clínica pudiera confirmarla. Contacte con la clínica."
    ),
    "booking_choose": "Elegir esta hora",
    "booking_decline": "Ninguna me sirve",
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
    "booking_offer_intro": (
        "La clínica le ofrece estas horas. Elija una y la clínica la confirmará."
    ),
    "booking_slot_date": "{weekday} {day} de {month}",
    "booking_slot_detail_separator": " · ",
    "booking_slot_duration_one": "{minutes} minuto",
    "booking_slot_duration_other": "{minutes} minutos",
    "booking_slot_taken": "Esa hora acaba de ser ocupada. Elija otra.",
    "booking_slot_taken_contact": "Esa hora acaba de ser ocupada. Contacte con la clínica.",
    "booking_slot_time": "{hour:02d}:{minute:02d}",
    "booking_slot_when": "{date} a las {time}",
    "booking_slots_legend": "Horas disponibles",
    "booking_visit_mode_in_person": "Presencial",
    "booking_visit_mode_phone": "Por teléfono",
    "booking_visit_mode_video": "Por video",
    "booking_weekday_0": "Lunes",
    "booking_weekday_1": "Martes",
    "booking_weekday_2": "Miércoles",
    "booking_weekday_3": "Jueves",
    "booking_weekday_4": "Viernes",
    "booking_weekday_5": "Sábado",
    "booking_weekday_6": "Domingo",
    "email_change_confirm": "Confirmar dirección de correo electrónico",
    "email_change_complete_error": (
        "Este enlace de confirmación ya no es válido. Solicite el cambio de nuevo desde la página "
        "de su cuenta."
    ),
    "email_change_complete_heading": "Confirme su nueva dirección de correo electrónico",
    "email_change_complete_intro": (
        "Al confirmar, se actualiza la dirección de correo electrónico que recibe los códigos "
        "de acceso y los enlaces de restablecimiento de contraseña."
    ),
    "email_change_success": (
        "Su dirección de correo electrónico se ha actualizado. El personal de la clínica revisará "
        "los datos correspondientes de su historia clínica en CARLOS."
    ),
    "email_change_success_heading": "Dirección de correo electrónico confirmada",
    "email_change_phone_confirmation_pending": (
        "Su nueva dirección de correo electrónico está confirmada. Inicie sesión e introduzca el "
        "código enviado al nuevo número de teléfono para terminar el cambio de datos de contacto."
    ),
    "change_password": "Cambiar contraseña",
    "clinic": "Clínica",
    "clinic_help": "Ayuda de la clínica",
    "clinic_help_message": (
        "Contacte con la clínica si no puede acceder a su cuenta o a su método de verificación."
    ),
    "contact_info": "Datos de contacto",
    "contact_change_notice_failed": (
        "Sus datos de contacto se han actualizado y se ha cerrado su sesión, pero no se pudo "
        "enviar un aviso de seguridad. Contacte con la clínica si usted no realizó este cambio."
    ),
    "contact_change_success": (
        "Sus datos de contacto se han actualizado. Por seguridad, se ha cerrado su sesión; inicie "
        "sesión de nuevo con su método de verificación actualizado. El personal de la clínica "
        "revisará los datos correspondientes de su historia clínica en CARLOS."
    ),
    "contact_change_success_heading": "Datos de contacto actualizados",
    "contact_the_clinic": "Contactar con la clínica",
    "copy": "Copiar",
    "copy_failed": "Seleccione y copie manualmente",
    "copied": "Copiado",
    "current_password": "Contraseña actual",
    "dashboard": "Panel principal",
    "dashboard_account_description": "Gestione su contraseña y sus datos de contacto.",
    "dashboard_documents_description": (
        "Los documentos podrían estar disponibles en una versión futura."
    ),
    "dashboard_email_passwords_description": (
        "Obtenga las contraseñas de los documentos cifrados que le envía su clínica."
    ),
    "dashboard_greeting": "Portal del paciente",
    "dashboard_help_description": "Encuentre información de ayuda sobre la clínica y su cuenta.",
    "dashboard_messages_description": (
        "Solicitudes de su clínica, como un recordatorio para reservar una cita."
    ),
    "date_from": "Fecha desde",
    "date_format_error": "Introduzca fechas válidas en «desde» y «hasta».",
    "filter_error": "Introduzca filtros válidos.",
    "date_range_error": "La fecha «desde» no puede ser posterior a la fecha «hasta».",
    "date_of_birth": "Fecha de nacimiento",
    "date_of_birth_day": "Día",
    "date_of_birth_hint": "Por ejemplo, 15 de junio de 1985.",
    "date_of_birth_month": "Mes",
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
    "date_of_birth_month_choose": "Elija un mes",
    "date_of_birth_year": "Año",
    "date_to": "Fecha hasta",
    "development_mfa_code": (
        "Código de acceso de desarrollo (el mismo código que se envía por correo electrónico, "
        "para agilizar las pruebas; se eliminará más adelante):"
    ),
    "development_reset_link": (
        "Enlace de desarrollo para restablecer la contraseña (también se envía por correo "
        "electrónico cuando el correo está configurado):"
    ),
    "documents": "Documentos",
    "email": "Correo electrónico",
    "email_codes_rate": "Los códigos por correo electrónico se pueden reenviar una vez por minuto.",
    "email_password": "Contraseña del documento",
    "email_password_page_indicator": "Página {page} de {total_pages}",
    "email_password_pages": "Páginas de contraseñas de los documentos",
    "email_passwords": "Contraseñas de los documentos",
    "email_passwords_region": "Contraseñas de los documentos",
    "forgot_username_password": "¿Olvidó su nombre de usuario o su contraseña?",
    "forgot_username_help": "Si no conoce su nombre de usuario, contacte con la clínica.",
    "future": "En el futuro",
    "health_card_number": "Número de tarjeta de salud (HCN/HIN)",
    "help": "Ayuda",
    "hide_password": "Ocultar contraseña",
    "incorrect_mfa_code": (
        "El código no fue aceptado. Inténtelo de nuevo o solicite un código nuevo."
    ),
    "incorrect_username_or_password": "Nombre de usuario o contraseña incorrectos",
    "invite_code": "Código de invitación",
    "language_aria_label": "Idioma",
    "logo_alt": "CARLOS",
    "logout": "Cerrar sesión",
    "message_back": "Volver a los mensajes",
    "message_new": "Nuevo",
    "message_not_found": "Ese mensaje ya no está disponible.",
    "message_sent_at": "Enviado el {sent_at}",
    "messages": "Mensajes",
    "messages_empty": "No tiene mensajes de su clínica.",
    "messages_new_count_one": "{count} nuevo",
    "messages_new_count_other": "{count} nuevos",
    "mfa": "Verificación en dos pasos",
    "mfa_code": "Código",
    "mfa_code_sent_email": "Código enviado a {destination} por correo electrónico.",
    "mfa_code_sent_email_unmasked": "Código enviado a su dirección de correo electrónico.",
    "mfa_code_sent_sms": "Código enviado a {destination} por SMS.",
    "mfa_code_sent_sms_unmasked": "Código enviado a su número de móvil.",
    "mfa_delivery_unavailable": "Ese método de envío no está disponible.",
    "mfa_email": "Correo electrónico",
    "mfa_heading": "Código de acceso",
    "mfa_help_message": (
        "Contacte con {clinic_name} si no puede recibir o usar su código de acceso."
    ),
    "mfa_new_code_sent_email": "Se envió un código nuevo por correo electrónico.",
    "mfa_new_code_sent_sms": "Se envió un código nuevo por SMS.",
    "mfa_rate_limited_one": (
        "Se envió un código hace poco. Inténtelo de nuevo en {seconds} segundo."
    ),
    "mfa_rate_limited_other": (
        "Se envió un código hace poco. Inténtelo de nuevo en {seconds} segundos."
    ),
    "mfa_resend": "Reenviar código",
    "mfa_sign_in_again": "Inicie sesión de nuevo para solicitar un nuevo código de acceso.",
    "mfa_send_by": "Enviar código por",
    "mfa_settings": "Configuración de la verificación en dos pasos",
    "mfa_sms": "SMS",
    "mfa_sms_rate": "Los códigos por SMS se pueden reenviar una vez cada cinco minutos.",
    "mfa_verify": "Verificar",
    "mfa_verification_failed": "No se pudo completar la verificación en dos pasos.",
    "modal_close": "Aceptar",
    "module_navigation": "Módulos del portal",
    "mfa_method": "Método",
    "new_password": "Nueva contraseña",
    "new_password_confirmation": "Confirmar nueva contraseña",
    "next": "Siguiente",
    "no_email_passwords": "No hay contraseñas de documentos",
    "no_matching_email_passwords": "No hay contraseñas de documentos que coincidan",
    "open_reset_page": "Abrir la página de restablecimiento",
    "password_label": "Contraseña",
    "password_hidden": "Oculta",
    "password_for": "Contraseña para {subject}",
    "password_confirmation": "Confirmar contraseña",
    "password_invalid": "La nueva contraseña no cumple los requisitos de contraseña.",
    "password_mismatch": "La confirmación de la contraseña no coincide.",
    "password_placeholder": "contraseña",
    "password_requirements": (
        "Use al menos 12 caracteres. Evite contraseñas comunes y datos de la cuenta, de la clínica "
        "o personales; varias palabras sin relación entre sí son una buena opción."
    ),
    "password_reset_complete_error": (
        "El enlace de restablecimiento de contraseña no es válido o ha caducado."
    ),
    "password_reset_complete_heading": "Elija una nueva contraseña",
    "password_reset_forced": "Debe restablecer su contraseña antes de iniciar sesión.",
    "password_reset_link_sent": (
        "Si los datos de la cuenta coinciden, se ha enviado un enlace de restablecimiento de "
        "contraseña por correo electrónico."
    ),
    "password_reset_request_details": (
        "Introduzca su nombre de usuario del portal y la dirección de correo electrónico "
        "registrada en su clínica."
    ),
    "password_reset_request_heading": "Restablezca su contraseña",
    "password_reset_send": "Enviar enlace de restablecimiento",
    "password_reset_success": (
        "Su contraseña se ha restablecido. Inicie sesión con la nueva contraseña."
    ),
    "password_reset_success_heading": "Contraseña restablecida",
    "password_reset_update": "Actualizar contraseña",
    "password_updated": "Contraseña actualizada",
    "patient_dashboard": "Panel del paciente",
    "phone": "Teléfono",
    "phone_required_for_sms": "Obligatorio si se selecciona SMS.",
    "phone_confirmation_code": "Código de confirmación del teléfono",
    "confirm_phone": "Confirmar número de teléfono",
    "resend_phone_confirmation": "Enviar otro código",
    "previous": "Anterior",
    "provider": "Profesional",
    "provider_options_truncated": (
        "Solo se muestran los profesionales más recientes. Use el cuadro de búsqueda para acotar "
        "los resultados."
    ),
    "reveal": "Mostrar",
    "reveal_failed": "No se pudo mostrar la contraseña. Inténtelo de nuevo.",
    "reveal_password_hint": (
        "Introduzca su contraseña actual antes de mostrar la contraseña del documento."
    ),
    "password_reset_temporarily_unavailable": (
        "El restablecimiento de contraseña no está disponible temporalmente. Inténtelo de nuevo en "
        "unos momentos."
    ),
    "revealing": "Mostrando...",
    "reset_filters": "Borrar filtros",
    "search": "Buscar",
    "sent": "Enviado",
    "session_locked_details": (
        "El personal de la clínica debe desbloquear esta cuenta antes de que pueda iniciar sesión "
        "o restablecer la contraseña de nuevo. Contacte con la clínica para obtener ayuda."
    ),
    "request_failed_heading": "No se pudo completar la solicitud",
    "request_failed_details": (
        "El portal no pudo completar esa solicitud. Esto suele ocurrir cuando la página ha estado "
        "abierta durante un tiempo: vuelva al portal e inténtelo de nuevo."
    ),
    "service_busy_heading": "Demasiadas solicitudes",
    "service_busy_details": (
        "El portal recibió demasiadas solicitudes desde esta conexión. Espere un momento e "
        "inténtelo de nuevo."
    ),
    "service_maintenance_heading": "Portal no disponible",
    "service_maintenance_details": (
        "El portal no está disponible temporalmente por mantenimiento. Inténtelo de nuevo en unos "
        "momentos o contacte con la clínica si necesita ayuda ahora."
    ),
    "service_name_default": "Portal del paciente CARLOS",
    "service_unavailable_heading": "Portal temporalmente no disponible",
    "service_unavailable_details": (
        "No se puede acceder al portal en este momento. Inténtelo de nuevo en unos minutos o "
        "contacte con la clínica si necesita ayuda ahora."
    ),
    "session_locked_heading": "Cuenta bloqueada",
    "sign_in_aria_label": "Iniciar sesión",
    "sign_in_button": "Iniciar sesión",
    "sign_in_heading": "Iniciar sesión",
    "show_password": "Mostrar contraseña",
    "source_code": "Código fuente",
    "subject": "Asunto",
    "unavailable": "No disponible",
    "update_contact": "Actualizar contacto",
    "update_mfa": "Actualizar verificación en dos pasos",
    "update_password": "Actualizar contraseña",
    "username": "Nombre de usuario",
    "username_label": "Nombre de usuario",
    "username_placeholder": "nombre de usuario",
    "username_unavailable": "Ese nombre de usuario no está disponible.",
    "verification_delivery_failed": ("No se pudo enviar el código de acceso. Inténtelo de nuevo."),
    "view_module": "Abrir",
}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
    "mycarlos_mfa_rate_limited": (
        "Se ha enviado un código de acceso hace poco. Espere antes de pedir otro."
    ),
    "mycarlos_link": "Vincular myCarlos",
    "mycarlos_devices": "Dispositivos vinculados",
    "mycarlos_instruction": (
        "En myCarlos, elija la opción para vincular el portal de su clínica y luego introduzca "
        "este código."
    ),
    "mycarlos_code_label": "Código de vinculación",
    "mycarlos_lifetime": (
        "Este código sirve una sola vez, durante 10 minutos. Mantenga la sesión iniciada en este "
        "portal."
    ),
    "mycarlos_approval": (
        "El dispositivo también debe ser aprobado antes de poder recibir documentos."
    ),
    "mycarlos_create": "Crear un código",
    "mycarlos_another": "Crear otro código",
    "mycarlos_linked": "Vinculado",
    "mycarlos_last_seen": "Última actividad",
    "mycarlos_empty": "No hay dispositivos vinculados. Elija Vincular myCarlos para añadir uno.",
    "mycarlos_remove_question": "¿Quitar este dispositivo?",
    "mycarlos_remove_effect": (
        "Este dispositivo dejará de recibir documentos nuevos. Para volver a usarlo, vincúlelo de "
        "nuevo. Los documentos ya guardados en myCarlos permanecen allí."
    ),
    "mycarlos_remove": "Quitar dispositivo",
    "mycarlos_remove_named": "Quitar dispositivo: {name}",
    "mycarlos_keep": "Conservar dispositivo",
    "mycarlos_paused": (
        "La vinculación está pausada porque se introdujeron demasiados códigos incorrectos. "
        "Inténtelo más tarde."
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
        "Código QR no disponible. Contacte con su clínica si no puede usar esta dirección del "
        "portal."
    ),
}
