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

"""Portuguese (Brazil) (pt-BR) text for the patient portal.

Translate keys from `locales/en.py`, keeping each `{placeholder}` exactly. A key left out
falls back to English (`i18n.portal_text`). Once every key is in, list this locale as
complete in tests/test_i18n_catalog.py so the parity test keeps it complete.
"""

TEXT: dict[str, str] = {
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

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
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
    "mycarlos_mfa_required": "Verifique seu acesso antes de vincular ou remover um dispositivo.",
    "mycarlos_verify": "Verificar acesso",
    "mycarlos_portal_address": "Endereço do portal",
    "mycarlos_qr_label": "Escanear no myCarlos",
    "mycarlos_qr_alt": "Código QR para vincular o myCarlos a este portal.",
    "mycarlos_qr_unavailable": (
        "Código QR indisponível. Entre em contato com sua clínica se não conseguir usar "
        "este endereço do portal."
    ),
}
