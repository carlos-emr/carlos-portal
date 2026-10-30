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
    "account": "Conta",
    "account_change_error": "Não foi possível concluir a alteração da conta.",
    "account_help": "Ajuda com a conta",
    "account_status_contact_notice_failed": (
        "Contato do portal atualizado, mas não foi possível enviar o e-mail de confirmação. Entre "
        "em contato com a clínica se você não esperava esta alteração."
    ),
    "account_status_contact_updated": (
        "Contato do portal atualizado. A equipe revisará os dados demográficos correspondentes no "
        "CARLOS."
    ),
    "account_status_contact_confirmation_required": (
        "Confirme o novo endereço de e-mail e digite o código enviado ao novo número de telefone. "
        "Seus dados de contato atuais permanecem ativos até que ambos sejam confirmados."
    ),
    "account_status_email_confirmation_required": (
        "Verifique o novo endereço de e-mail para encontrar o link de confirmação. Seu endereço "
        "atual continua recebendo códigos de verificação e links de redefinição de senha até que "
        "você use o link."
    ),
    "account_status_email_confirmation_notice_failed": (
        "Não foi possível enviar a confirmação por e-mail ao novo endereço. Seus dados de contato "
        "não foram alterados. Tente novamente ou entre em contato com a clínica."
    ),
    "account_status_phone_confirmation_required": (
        "Digite o código de confirmação enviado ao novo número de telefone. Seu número de telefone "
        "atual permanece ativo até que o novo seja confirmado."
    ),
    "account_status_phone_confirmation_invalid": (
        "O código de confirmação do telefone é inválido ou expirou. Solicite outro código e tente "
        "novamente."
    ),
    "account_status_phone_confirmation_notice_failed": (
        "Não foi possível enviar um código de confirmação ao novo número de telefone. Seus dados "
        "de contato não foram alterados. Tente novamente ou entre em contato com a clínica."
    ),
    "account_status_phone_confirmation_rate_limited": (
        "Um código de confirmação do telefone foi enviado há pouco. Aguarde antes de solicitar "
        "outro."
    ),
    "account_status_mfa_updated": "Configurações de MFA atualizadas.",
    "account_status_no_change": "Nenhuma alteração na conta.",
    "account_status_password_updated": "Senha atualizada.",
    "all_providers": "Todos os profissionais",
    "activate_account": "Ativar conta",
    "activation_details": (
        "Digite os dados do convite fornecidos pela sua clínica e crie seu acesso ao portal."
    ),
    "activation_date_of_birth_invalid": (
        "Verifique a data de nascimento: informe uma data real, por exemplo, 15 de junho de 1985."
    ),
    "activation_error": "Não foi possível verificar os dados de ativação.",
    "activation_password_rejected": (
        "Escolha outra senha: use pelo menos 12 caracteres, evite palavras ou padrões comuns e não "
        "inclua seu nome de usuário, e-mail, data de nascimento nem número do cartão de saúde."
    ),
    "activation_reenter_password": "Seus outros dados foram mantidos: digite sua senha novamente.",
    "activation_heading": "Ative sua conta",
    "activation_rate_limited": (
        "Foram feitas muitas tentativas de ativação. Aguarde antes de tentar novamente."
    ),
    "activation_success": "Sua conta do portal está pronta.",
    "activation_success_heading": "Conta ativada",
    "back_to_sign_in": "Voltar para o login",
    "booking_prompt_contact": "Para agendar, entre em contato com {clinic_name}.",
    "booking_prompt_contact_phone": "Para agendar, ligue para {clinic_name} pelo telefone {phone}.",
    "booking_prompt_no_online_booking": "Não é possível agendar consultas neste portal.",
    "booking_prompt_suggested_by": "{provider} sugeriu esta consulta.",
    "booking_prompt_suggested_by_clinic": "Sua clínica sugeriu esta consulta.",
    "booking_prompt_title_annual_exam": "Agende seu exame anual",
    "booking_prompt_title_follow_up": "Agende uma consulta de retorno",
    "booking_prompt_title_lab_review": (
        "Agende uma consulta para revisar seus resultados de exames laboratoriais"
    ),
    "booking_prompt_urgency_as_soon_as_possible": "Por favor, agende o mais rápido possível.",
    "booking_prompt_urgency_routine": "Por favor, agende em um horário conveniente para você.",
    "booking_prompt_urgency_soon": "Por favor, agende nas próximas semanas.",
    "booking_booked": "Agendado para {date} às {time}.",
    "booking_choice_error": (
        "Não foi possível escolher esse horário. Leia a mensagem abaixo e tente novamente."
    ),
    "booking_choice_pending": "Estamos confirmando seu horário com a clínica.",
    "booking_choice_pending_overdue": (
        "A clínica confirmará seu horário. Se for urgente, ligue para a clínica."
    ),
    "booking_choice_pending_overdue_phone": (
        "A clínica confirmará seu horário. Se for urgente, ligue para a clínica pelo telefone "
        "{phone}."
    ),
    "booking_choice_expired": (
        "Esse horário passou antes que a clínica pudesse confirmá-lo. Por favor, escolha outro."
    ),
    "booking_choice_expired_contact": (
        "Esse horário passou antes que a clínica pudesse confirmá-lo. Por favor, entre em contato "
        "com a clínica."
    ),
    "booking_choose": "Escolher este horário",
    "booking_decline": "Nenhum destes serve",
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
    "booking_offer_intro": (
        "A clínica ofereceu estes horários. Escolha um e a clínica o confirmará."
    ),
    "booking_slot_date": "{weekday}, {day} de {month}",
    "booking_slot_detail_separator": " · ",
    "booking_slot_duration_one": "{minutes} minuto",
    "booking_slot_duration_other": "{minutes} minutos",
    "booking_slot_taken": "Esse horário acabou de ser ocupado. Por favor, escolha outro.",
    "booking_slot_taken_contact": (
        "Esse horário acabou de ser ocupado. Por favor, entre em contato com a clínica."
    ),
    "booking_slot_time": "{hour:02d}:{minute:02d}",
    "booking_slot_when": "{date} às {time}",
    "booking_slots_legend": "Horários disponíveis",
    "booking_visit_mode_in_person": "Presencial",
    "booking_visit_mode_phone": "Por telefone",
    "booking_visit_mode_video": "Por vídeo",
    "booking_weekday_0": "Segunda-feira",
    "booking_weekday_1": "Terça-feira",
    "booking_weekday_2": "Quarta-feira",
    "booking_weekday_3": "Quinta-feira",
    "booking_weekday_4": "Sexta-feira",
    "booking_weekday_5": "Sábado",
    "booking_weekday_6": "Domingo",
    "email_change_confirm": "Confirmar endereço de e-mail",
    "email_change_complete_error": (
        "Este link de confirmação não é mais válido. Solicite a alteração novamente na página da "
        "sua conta."
    ),
    "email_change_complete_heading": "Confirme seu novo endereço de e-mail",
    "email_change_complete_intro": (
        "Ao confirmar, você atualiza o endereço de e-mail usado para os códigos de verificação de "
        "acesso e os links de redefinição de senha."
    ),
    "email_change_success": (
        "Seu endereço de e-mail foi atualizado. A equipe da clínica revisará os dados "
        "correspondentes do prontuário no CARLOS."
    ),
    "email_change_success_heading": "Endereço de e-mail confirmado",
    "email_change_phone_confirmation_pending": (
        "Seu novo endereço de e-mail foi confirmado. Entre e digite o código enviado ao novo "
        "número de telefone para concluir a alteração de contato."
    ),
    "change_password": "Alterar senha",
    "clinic": "Clínica",
    "clinic_help": "Ajuda da clínica",
    "clinic_help_message": (
        "Entre em contato com a clínica se você não conseguir acessar sua conta ou seu método de "
        "verificação."
    ),
    "contact_info": "Dados de contato",
    "contact_change_notice_failed": (
        "Seus dados de contato foram atualizados e sua sessão foi encerrada, mas não foi possível "
        "enviar um aviso de segurança. Entre em contato com a clínica se você não fez esta "
        "alteração."
    ),
    "contact_change_success": (
        "Seus dados de contato foram atualizados. Por segurança, sua sessão foi encerrada; entre "
        "novamente com seu método de verificação atualizado. A equipe da clínica revisará os dados "
        "correspondentes do prontuário no CARLOS."
    ),
    "contact_change_success_heading": "Dados de contato atualizados",
    "contact_the_clinic": "Entrar em contato com a clínica",
    "copy": "Copiar",
    "copy_failed": "Selecione e copie manualmente",
    "copied": "Copiado",
    "current_password": "Senha atual",
    "dashboard": "Painel",
    "dashboard_account_description": "Gerencie sua senha e seus dados de contato.",
    "dashboard_documents_description": (
        "Os documentos poderão ficar disponíveis em uma versão futura."
    ),
    "dashboard_email_passwords_description": (
        "Obtenha as senhas das mensagens criptografadas enviadas pela sua clínica."
    ),
    "dashboard_greeting": "Portal do paciente",
    "dashboard_help_description": "Encontre informações de suporte da clínica e da conta.",
    "dashboard_messages_description": (
        "Solicitações da sua clínica, como um lembrete para agendar uma consulta."
    ),
    "date_from": "Data inicial",
    "date_format_error": "Informe uma data inicial e uma data final válidas.",
    "filter_error": "Informe filtros válidos.",
    "date_range_error": "A data inicial não pode ser posterior à data final.",
    "date_of_birth": "Data de nascimento",
    "date_of_birth_day": "Dia",
    "date_of_birth_hint": "Por exemplo, 15 de junho de 1985.",
    "date_of_birth_month": "Mês",
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
    "date_of_birth_month_choose": "Escolha um mês",
    "date_of_birth_year": "Ano",
    "date_to": "Data final",
    "development_mfa_code": (
        "Código MFA de desenvolvimento (o mesmo código enviado por e-mail, para agilizar os "
        "testes; será removido depois):"
    ),
    "development_reset_link": (
        "Link de redefinição de senha de desenvolvimento (também enviado por e-mail quando o "
        "e-mail está configurado):"
    ),
    "documents": "Documentos",
    "email": "E-mail",
    "email_codes_rate": "Os códigos por e-mail podem ser reenviados uma vez por minuto.",
    "email_password": "Senha de e-mail",
    "email_password_page_indicator": "Página {page} de {total_pages}",
    "email_password_pages": "Páginas de senhas de e-mail",
    "email_passwords": "Senhas de e-mail",
    "email_passwords_region": "Senhas de e-mail",
    "forgot_username_password": "Esqueceu o nome de usuário ou a senha?",
    "forgot_username_help": (
        "Se você não souber seu nome de usuário, entre em contato com a clínica."
    ),
    "future": "Em breve",
    "health_card_number": "Número do cartão de saúde (HCN/HIN)",
    "help": "Ajuda",
    "hide_password": "Ocultar senha",
    "incorrect_mfa_code": "O código não foi aceito. Tente novamente ou solicite um novo código.",
    "incorrect_username_or_password": "Nome de usuário ou senha incorretos",
    "invite_code": "Código do convite",
    "language_aria_label": "Idioma",
    "logo_alt": "CARLOS",
    "logout": "Sair",
    "message_back": "Voltar para as mensagens",
    "message_new": "Nova",
    "message_not_found": "Essa mensagem não está mais disponível.",
    "message_sent_at": "Enviada em {sent_at}",
    "messages": "Mensagens",
    "messages_empty": "Você não tem mensagens da sua clínica.",
    "messages_new_count_one": "{count} nova",
    "messages_new_count_other": "{count} novas",
    "mfa": "MFA",
    "mfa_code": "Código",
    "mfa_code_sent_email": "Código enviado para {destination} por e-mail.",
    "mfa_code_sent_email_unmasked": "Código enviado para seu endereço de e-mail.",
    "mfa_code_sent_sms": "Código enviado para {destination} por SMS.",
    "mfa_code_sent_sms_unmasked": "Código enviado para seu número de celular.",
    "mfa_delivery_unavailable": "Esse método de envio está indisponível.",
    "mfa_email": "E-mail",
    "mfa_heading": "Código de verificação",
    "mfa_help_message": (
        "Entre em contato com {clinic_name} se você não conseguir receber ou usar seu código de "
        "verificação."
    ),
    "mfa_new_code_sent_email": "Um novo código foi enviado por e-mail.",
    "mfa_new_code_sent_sms": "Um novo código foi enviado por SMS.",
    "mfa_rate_limited_one": "Um código foi enviado há pouco. Tente novamente em {seconds} segundo.",
    "mfa_rate_limited_other": (
        "Um código foi enviado há pouco. Tente novamente em {seconds} segundos."
    ),
    "mfa_resend": "Reenviar código",
    "mfa_sign_in_again": "Entre novamente para solicitar um novo código de verificação.",
    "mfa_send_by": "Enviar código por",
    "mfa_settings": "Configurações de MFA",
    "mfa_sms": "SMS",
    "mfa_sms_rate": "Os códigos por SMS podem ser reenviados uma vez a cada cinco minutos.",
    "mfa_verify": "Verificar",
    "mfa_verification_failed": "Não foi possível verificar a MFA.",
    "modal_close": "OK",
    "module_navigation": "Módulos do portal",
    "mfa_method": "Método",
    "new_password": "Nova senha",
    "new_password_confirmation": "Confirmar nova senha",
    "next": "Próxima",
    "no_email_passwords": "Nenhuma senha de e-mail",
    "no_matching_email_passwords": "Nenhuma senha de e-mail correspondente",
    "open_reset_page": "Abrir página de redefinição",
    "password_label": "Senha",
    "password_hidden": "Oculta",
    "password_for": "Senha de {subject}",
    "password_confirmation": "Confirmar senha",
    "password_invalid": "A nova senha não atende aos requisitos de senha.",
    "password_mismatch": "A confirmação da senha não corresponde.",
    "password_placeholder": "senha",
    "password_requirements": (
        "Use pelo menos 12 caracteres. Evite senhas comuns e informações da conta, da clínica ou "
        "pessoais; várias palavras sem relação entre si são uma boa escolha."
    ),
    "password_reset_complete_error": "O link de redefinição de senha é inválido ou expirou.",
    "password_reset_complete_heading": "Escolha uma nova senha",
    "password_reset_forced": "Você precisa redefinir sua senha antes de entrar.",
    "password_reset_link_sent": (
        "Se os dados da conta corresponderem, um link de redefinição de senha foi enviado por "
        "e-mail."
    ),
    "password_reset_request_details": (
        "Digite seu nome de usuário do portal e o endereço de e-mail cadastrado na sua clínica."
    ),
    "password_reset_request_heading": "Redefina sua senha",
    "password_reset_send": "Enviar link de redefinição",
    "password_reset_success": "Sua senha foi redefinida. Entre com a nova senha.",
    "password_reset_success_heading": "Senha redefinida",
    "password_reset_update": "Atualizar senha",
    "password_updated": "Senha atualizada",
    "patient_dashboard": "Painel do paciente",
    "phone": "Telefone",
    "phone_required_for_sms": "Obrigatório quando SMS está selecionado.",
    "phone_confirmation_code": "Código de confirmação do telefone",
    "confirm_phone": "Confirmar número de telefone",
    "resend_phone_confirmation": "Enviar outro código",
    "previous": "Anterior",
    "provider": "Profissional",
    "provider_options_truncated": (
        "Apenas os profissionais mais recentes estão listados. Use a caixa de busca para refinar "
        "os resultados."
    ),
    "reveal": "Revelar",
    "reveal_failed": "Não foi possível revelar a senha. Tente novamente.",
    "reveal_password_hint": "Digite sua senha atual antes de revelar uma frase-senha.",
    "password_reset_temporarily_unavailable": (
        "A redefinição de senha está temporariamente indisponível. Tente novamente em instantes."
    ),
    "revealing": "Revelando...",
    "reset_filters": "Limpar filtros",
    "search": "Buscar",
    "sent": "Envio",
    "session_locked_details": (
        "A equipe da clínica precisa desbloquear esta conta antes de um novo acesso ou redefinição "
        "de senha. Entre em contato com a clínica para obter ajuda."
    ),
    "request_failed_heading": "Não foi possível concluir a solicitação",
    "request_failed_details": (
        "O portal não conseguiu concluir essa solicitação. Isso geralmente significa que a página "
        "ficou aberta por muito tempo. Volte ao portal e tente novamente."
    ),
    "service_busy_heading": "Excesso de solicitações",
    "service_busy_details": (
        "O portal recebeu solicitações demais desta conexão. Aguarde um momento e tente novamente."
    ),
    "service_maintenance_heading": "Portal indisponível",
    "service_maintenance_details": (
        "O portal está temporariamente indisponível para manutenção. Tente novamente em instantes "
        "ou entre em contato com a clínica se precisar de ajuda agora."
    ),
    "service_name_default": "Portal do Paciente CARLOS",
    "service_unavailable_heading": "Portal temporariamente indisponível",
    "service_unavailable_details": (
        "Não é possível acessar o portal no momento. Tente novamente em alguns minutos ou entre em "
        "contato com a clínica se precisar de ajuda agora."
    ),
    "session_locked_heading": "Conta bloqueada",
    "sign_in_aria_label": "Entrar",
    "sign_in_button": "Entrar",
    "sign_in_heading": "Entrar",
    "show_password": "Mostrar senha",
    "source_code": "Código-fonte",
    "subject": "Assunto",
    "unavailable": "Indisponível",
    "update_contact": "Atualizar contato",
    "update_mfa": "Atualizar MFA",
    "update_password": "Atualizar senha",
    "username": "Nome de usuário",
    "username_label": "Nome de usuário",
    "username_placeholder": "nome de usuário",
    "username_unavailable": "Esse nome de usuário não está disponível.",
    "verification_delivery_failed": (
        "Não foi possível enviar o código de verificação. Por favor, tente novamente."
    ),
    "view_module": "Abrir",
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
        "Este código funciona uma única vez, por 10 minutos. Mantenha a sessão iniciada neste "
        "portal."
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
        "Este dispositivo deixará de receber novos documentos. Para usá-lo novamente, vincule-o de "
        "novo. Os documentos já salvos no myCarlos permanecem lá."
    ),
    "mycarlos_remove": "Remover dispositivo",
    "mycarlos_remove_named": "Remover dispositivo: {name}",
    "mycarlos_keep": "Manter dispositivo",
    "mycarlos_paused": (
        "A vinculação está pausada devido ao excesso de códigos incorretos. Tente novamente mais "
        "tarde."
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
        "Código QR indisponível. Entre em contato com sua clínica se não conseguir usar este "
        "endereço do portal."
    ),
}
