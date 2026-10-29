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

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
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
    "mycarlos_empty": "No hay dispositivos vinculados. Elija Vincular myCarlos para añadir uno.",
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
}
