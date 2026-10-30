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

"""Simplified Chinese (zh-CN, 简体中文) text for the patient portal.

Translate keys from `locales/en.py`, keeping each `{placeholder}` exactly; a key left out falls
back to English (`i18n.portal_text`). Once every key is in, list this locale as complete in
tests/test_i18n_catalog.py so the parity test keeps it complete.

Chinese conventions, shared with myCarlos so a patient meets the same words in both:
- full-width punctuation in sentences (，。：（）); ASCII digits, codes, addresses and placeholders;
- one plural form: counted text uses the `_other` key only;
- terms already chosen in myCarlos:
  诊所门户网站 (clinic portal),
  关联码 (linking code),
  验证码 (emailed code),
  批准 (approve),
  「安全」 (Security);
- zh-CN and zh-TW are separate translations, not a character conversion: Taiwan wording differs
  (帳戶, 資訊, 設定 rather than 账户, 信息, 设置).
"""

TEXT: dict[str, str] = {
    "account": "账户",
    "account_change_error": "无法完成账户更改。",
    "account_help": "账户帮助",
    "account_status_contact_notice_failed": (
        "门户网站联系方式已更新，但无法发送确认邮件。如果您没有预期此更改，请联系诊所。"
    ),
    "account_status_contact_updated": (
        "门户网站联系方式已更新。诊所工作人员将核对 CARLOS 中相应的患者信息。"
    ),
    "account_status_contact_confirmation_required": (
        "请确认新的电子邮件地址，并输入发送至新电话号码的验证码。在两者都确认之前，"
        "您当前的联系方式仍然有效。"
    ),
    "account_status_email_confirmation_required": (
        "请查看新电子邮件地址中的确认链接。在您使用该链接之前，"
        "您当前的地址仍会继续接收验证码和密码重置链接。"
    ),
    "account_status_email_confirmation_notice_failed": (
        "无法向新地址发送确认邮件。您的联系方式未更改。请重试，或联系诊所。"
    ),
    "account_status_phone_confirmation_required": (
        "请输入发送至新电话号码的验证码。在确认之前，您当前的电话号码仍然有效。"
    ),
    "account_status_phone_confirmation_invalid": "电话验证码无效或已过期。请重新获取验证码后再试。",
    "account_status_phone_confirmation_notice_failed": (
        "无法向新电话号码发送验证码。您的联系方式未更改。请重试，或联系诊所。"
    ),
    "account_status_phone_confirmation_rate_limited": "电话验证码刚刚已发送。请稍候再重新获取。",
    "account_status_mfa_updated": "多因素验证设置已更新。",
    "account_status_no_change": "账户没有任何更改。",
    "account_status_password_updated": "密码已更新。",
    "all_providers": "所有医疗人员",
    "activate_account": "激活账户",
    "activation_details": "请输入诊所提供的邀请信息，并创建您的门户网站登录信息。",
    "activation_date_of_birth_invalid": "请检查出生日期：输入真实的日期，例如 1985年6月15日。",
    "activation_error": "无法验证激活信息。",
    "activation_password_rejected": (
        "请选择其他密码：至少 12 "
        "个字符，避免常见单词或规律，且不要包含您的用户名、电子邮件、出生日期或健康卡号。"
    ),
    "activation_reenter_password": "您的其他输入内容已保留：请重新输入密码。",
    "activation_heading": "激活您的账户",
    "activation_rate_limited": "激活尝试次数过多。请稍候再试。",
    "activation_success": "您的门户网站账户已准备就绪。",
    "activation_success_heading": "账户已激活",
    "back_to_sign_in": "返回登录",
    "booking_prompt_contact": "如需预约，请联系 {clinic_name}。",
    "booking_prompt_contact_phone": "如需预约，请致电 {clinic_name}：{phone}。",
    "booking_prompt_no_online_booking": "无法在此门户网站预约。",
    "booking_prompt_suggested_by": "{provider} 建议您进行此次预约。",
    "booking_prompt_suggested_by_clinic": "您的诊所建议您进行此次预约。",
    "booking_prompt_title_annual_exam": "预约年度体检",
    "booking_prompt_title_follow_up": "预约复诊",
    "booking_prompt_title_lab_review": "预约查看化验结果",
    "booking_prompt_urgency_as_soon_as_possible": "请尽快预约。",
    "booking_prompt_urgency_routine": "请选择方便的时间预约。",
    "booking_prompt_urgency_soon": "请在接下来几周内预约。",
    "booking_booked": "已预约 {date} {time}。",
    "booking_choice_error": "无法选择该时间。请查看下方信息后重试。",
    "booking_choice_pending": "我们正在与诊所确认您的时间。",
    "booking_choice_pending_overdue": "诊所将确认您的时间。如情况紧急，请致电诊所。",
    "booking_choice_pending_overdue_phone": "诊所将确认您的时间。如情况紧急，请致电诊所：{phone}。",
    "booking_choice_expired": "该时间在诊所确认之前已过。请另选一个时间。",
    "booking_choice_expired_contact": "该时间在诊所确认之前已过。请联系诊所。",
    "booking_choose": "选择此时间",
    "booking_decline": "这些时间都不合适",
    "booking_month_1": "1月",
    "booking_month_2": "2月",
    "booking_month_3": "3月",
    "booking_month_4": "4月",
    "booking_month_5": "5月",
    "booking_month_6": "6月",
    "booking_month_7": "7月",
    "booking_month_8": "8月",
    "booking_month_9": "9月",
    "booking_month_10": "10月",
    "booking_month_11": "11月",
    "booking_month_12": "12月",
    "booking_offer_intro": "诊所提供了以下时间。请选择一个，诊所随后会进行确认。",
    "booking_slot_date": "{month}{day}日 {weekday}",
    "booking_slot_detail_separator": " · ",
    "booking_slot_duration_other": "{minutes} 分钟",
    "booking_slot_taken": "该时间刚刚被预约。请另选一个时间。",
    "booking_slot_taken_contact": "该时间刚刚被预约。请联系诊所。",
    "booking_slot_time": "{hour:02d}:{minute:02d}",
    "booking_slot_when": "{date} {time}",
    "booking_slots_legend": "可选时间",
    "booking_visit_mode_in_person": "到诊所就诊",
    "booking_visit_mode_phone": "电话就诊",
    "booking_visit_mode_video": "视频就诊",
    "booking_weekday_0": "星期一",
    "booking_weekday_1": "星期二",
    "booking_weekday_2": "星期三",
    "booking_weekday_3": "星期四",
    "booking_weekday_4": "星期五",
    "booking_weekday_5": "星期六",
    "booking_weekday_6": "星期日",
    "email_change_confirm": "确认电子邮件地址",
    "email_change_complete_error": "此确认链接已失效。请在您的账户页面重新申请更改。",
    "email_change_complete_heading": "确认您的新电子邮件地址",
    "email_change_complete_intro": "确认后，将更新用于接收登录验证码和密码重置链接的电子邮件地址。",
    "email_change_success": "您的电子邮件地址已更新。诊所工作人员将核对 CARLOS 中相应的病历信息。",
    "email_change_success_heading": "电子邮件地址已确认",
    "email_change_phone_confirmation_pending": (
        "您的新电子邮件地址已确认。请登录并输入发送至新电话号码的验证码，以完成联系方式更改。"
    ),
    "change_password": "更改密码",
    "clinic": "诊所",
    "clinic_help": "诊所帮助",
    "clinic_help_message": "如果您无法访问账户或无法使用验证方式，请联系诊所。",
    "contact_info": "联系信息",
    "contact_change_notice_failed": (
        "您的联系信息已更新，并且您已退出登录，但无法发送安全通知。如果此更改不是您本人所做，"
        "请联系诊所。"
    ),
    "contact_change_success": (
        "您的联系信息已更新。为了安全起见，您已退出登录；请使用更新后的验证方式重新登录。诊所工作人"
        "员将核对 CARLOS 中相应的病历信息。"
    ),
    "contact_change_success_heading": "联系信息已更新",
    "contact_the_clinic": "联系诊所",
    "copy": "复制",
    "copy_failed": "请手动选择并复制",
    "copied": "已复制",
    "current_password": "当前密码",
    "dashboard": "主页",
    "dashboard_account_description": "管理您的密码和联系信息。",
    "dashboard_documents_description": "文档功能可能在未来版本中提供。",
    "dashboard_email_passwords_description": "获取诊所发送的加密邮件的密码。",
    "dashboard_greeting": "患者门户网站",
    "dashboard_help_description": "查找诊所和账户支持信息。",
    "dashboard_messages_description": "来自诊所的请求，例如预约提醒。",
    "date_from": "开始日期",
    "date_format_error": "请输入有效的开始日期和结束日期。",
    "filter_error": "请输入有效的筛选条件。",
    "date_range_error": "开始日期不能晚于结束日期。",
    "date_of_birth": "出生日期",
    "date_of_birth_day": "日",
    "date_of_birth_hint": "例如：1985年6月15日。",
    "date_of_birth_month": "月",
    "date_of_birth_month_1": "1月",
    "date_of_birth_month_2": "2月",
    "date_of_birth_month_3": "3月",
    "date_of_birth_month_4": "4月",
    "date_of_birth_month_5": "5月",
    "date_of_birth_month_6": "6月",
    "date_of_birth_month_7": "7月",
    "date_of_birth_month_8": "8月",
    "date_of_birth_month_9": "9月",
    "date_of_birth_month_10": "10月",
    "date_of_birth_month_11": "11月",
    "date_of_birth_month_12": "12月",
    "date_of_birth_month_choose": "请选择月份",
    "date_of_birth_year": "年",
    "date_to": "结束日期",
    "development_mfa_code": (
        "开发环境多因素验证码（与邮件中发送的验证码相同，用于加快测试，之后将移除）："
    ),
    "development_reset_link": "开发环境密码重置链接（配置了电子邮件时也会通过邮件发送）：",
    "documents": "文档",
    "email": "电子邮件",
    "email_codes_rate": "电子邮件验证码每分钟最多可重新发送一次。",
    "email_password": "邮件密码",
    "email_password_page_indicator": "第 {page} 页，共 {total_pages} 页",
    "email_password_pages": "邮件密码页面",
    "email_passwords": "邮件密码",
    "email_passwords_region": "邮件密码",
    "forgot_username_password": "忘记用户名或密码？",
    "forgot_username_help": "如果您不知道自己的用户名，请联系诊所。",
    "future": "即将推出",
    "health_card_number": "健康卡号（HCN/HIN）",
    "help": "帮助",
    "hide_password": "隐藏密码",
    "incorrect_mfa_code": "验证码未被接受。请重试或重新获取验证码。",
    "incorrect_username_or_password": "用户名或密码不正确",
    "invite_code": "邀请码",
    "language_aria_label": "语言",
    "logo_alt": "CARLOS",
    "logout": "退出登录",
    "message_back": "返回消息列表",
    "message_new": "新",
    "message_not_found": "该消息已不可用。",
    "message_sent_at": "发送于 {sent_at}",
    "messages": "消息",
    "messages_empty": "您没有来自诊所的消息。",
    "messages_new_count_other": "{count} 条新消息",
    "mfa": "多因素验证",
    "mfa_code": "验证码",
    "mfa_code_sent_email": "验证码已通过电子邮件发送至 {destination}。",
    "mfa_code_sent_email_unmasked": "验证码已发送至您的电子邮件地址。",
    "mfa_code_sent_sms": "验证码已通过短信发送至 {destination}。",
    "mfa_code_sent_sms_unmasked": "验证码已发送至您的手机号码。",
    "mfa_delivery_unavailable": "该发送方式不可用。",
    "mfa_email": "电子邮件",
    "mfa_heading": "验证码",
    "mfa_help_message": "如果您无法收到或使用验证码，请联系 {clinic_name}。",
    "mfa_new_code_sent_email": "新的验证码已通过电子邮件发送。",
    "mfa_new_code_sent_sms": "新的验证码已通过短信发送。",
    "mfa_rate_limited_other": "验证码刚刚已发送。请在 {seconds} 秒后重试。",
    "mfa_resend": "重新发送验证码",
    "mfa_sign_in_again": "请重新登录以获取新的验证码。",
    "mfa_send_by": "验证码发送方式",
    "mfa_settings": "多因素验证设置",
    "mfa_sms": "短信",
    "mfa_sms_rate": "短信验证码每五分钟最多可重新发送一次。",
    "mfa_verify": "验证",
    "mfa_verification_failed": "无法完成多因素验证。",
    "modal_close": "确定",
    "module_navigation": "门户网站模块",
    "mfa_method": "验证方式",
    "new_password": "新密码",
    "new_password_confirmation": "确认新密码",
    "next": "下一页",
    "no_email_passwords": "没有邮件密码",
    "no_matching_email_passwords": "没有符合条件的邮件密码",
    "open_reset_page": "打开重置页面",
    "password_label": "密码",
    "password_hidden": "已隐藏",
    "password_for": "{subject} 的密码",
    "password_confirmation": "确认密码",
    "password_invalid": "新密码不符合密码要求。",
    "password_mismatch": "两次输入的密码不一致。",
    "password_placeholder": "密码",
    "password_requirements": (
        "请使用至少 12 个字符。避免常见密码以及账户、诊所或个人信息；几个互不相关的词是不错的选择。"
    ),
    "password_reset_complete_error": "密码重置链接无效或已过期。",
    "password_reset_complete_heading": "设置新密码",
    "password_reset_forced": "您必须先重置密码才能登录。",
    "password_reset_link_sent": "如果账户信息相符，密码重置链接已通过电子邮件发送。",
    "password_reset_request_details": "请输入您的门户网站用户名以及在诊所登记的电子邮件地址。",
    "password_reset_request_heading": "重置您的密码",
    "password_reset_send": "发送重置链接",
    "password_reset_success": "您的密码已重置。请使用新密码登录。",
    "password_reset_success_heading": "密码已重置",
    "password_reset_update": "更新密码",
    "password_updated": "密码已更新",
    "patient_dashboard": "患者主页",
    "phone": "电话",
    "phone_required_for_sms": "选择短信时必填。",
    "phone_confirmation_code": "电话验证码",
    "confirm_phone": "确认电话号码",
    "resend_phone_confirmation": "重新发送验证码",
    "previous": "上一页",
    "provider": "医疗人员",
    "provider_options_truncated": "仅列出最近的医疗人员。请使用搜索框缩小结果范围。",
    "reveal": "显示",
    "reveal_failed": "无法显示密码。请重试。",
    "reveal_password_hint": "显示密码短语前，请输入您的当前密码。",
    "password_reset_temporarily_unavailable": "密码重置功能暂时不可用。请稍后再试。",
    "revealing": "正在显示…",
    "reset_filters": "清除筛选条件",
    "search": "搜索",
    "sent": "发送时间",
    "session_locked_details": (
        "诊所工作人员必须先解锁此账户，才能再次登录或重置密码。请联系诊所寻求帮助。"
    ),
    "request_failed_heading": "无法完成请求",
    "request_failed_details": (
        "门户网站无法完成该请求。这通常是因为页面打开时间过长，请返回门户网站后重试。"
    ),
    "service_busy_heading": "请求过多",
    "service_busy_details": "门户网站从此连接收到的请求过多。请稍等片刻后重试。",
    "service_maintenance_heading": "门户网站不可用",
    "service_maintenance_details": (
        "门户网站正在维护，暂时不可用。请稍后再试；如果您现在需要帮助，请联系诊所。"
    ),
    "service_name_default": "CARLOS 患者门户网站",
    "service_unavailable_heading": "门户网站暂时不可用",
    "service_unavailable_details": (
        "目前无法连接到门户网站。请几分钟后重试；如果您现在需要帮助，请联系诊所。"
    ),
    "session_locked_heading": "账户已锁定",
    "sign_in_aria_label": "登录",
    "sign_in_button": "登录",
    "sign_in_heading": "登录",
    "show_password": "显示密码",
    "source_code": "源代码",
    "subject": "主题",
    "unavailable": "不可用",
    "update_contact": "更新联系方式",
    "update_mfa": "更新多因素验证",
    "update_password": "更新密码",
    "username": "用户名",
    "username_label": "用户名",
    "username_placeholder": "用户名",
    "username_unavailable": "该用户名不可用。",
    "verification_delivery_failed": "无法发送验证码。请重试。",
    "view_module": "打开",
}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
    "mycarlos_mfa_rate_limited": "登录验证码刚刚已发送。请稍候再重新获取。",
    "mycarlos_link": "关联 myCarlos",
    "mycarlos_devices": "已关联的设备",
    "mycarlos_instruction": (
        "请在 myCarlos 中选择「关联诊所」以关联到您的诊所门户网站，然后输入此关联码。"
    ),
    "mycarlos_code_label": "一次性关联码",
    "mycarlos_lifetime": "此关联码仅可使用一次，有效期 10 分钟。请保持登录此门户网站。",
    "mycarlos_approval": "该设备还必须获得批准，才能接收文档。",
    "mycarlos_create": "创建关联码",
    "mycarlos_another": "再创建一个关联码",
    "mycarlos_linked": "关联时间",
    "mycarlos_last_seen": "上次连接",
    "mycarlos_empty": "没有已关联的设备。请选择「关联 myCarlos」添加设备。",
    "mycarlos_remove_question": "要移除此设备吗？",
    "mycarlos_remove_effect": (
        "此设备将不再接收新文档。如需再次使用，请重新关联。已保存在 myCarlos 中的文档会保留在那里。"
    ),
    "mycarlos_remove": "移除设备",
    "mycarlos_remove_named": "移除设备：{name}",
    "mycarlos_keep": "保留设备",
    "mycarlos_paused": "由于错误关联码次数过多，关联已暂停。请稍后再试。",
    "mycarlos_unavailable": "关联功能不可用。请联系您的诊所。",
    "mycarlos_removed": "设备已移除。",
    "mycarlos_not_seen": "尚未连接",
    "mycarlos_mfa_required": "关联或移除设备前，请先验证您的登录。",
    "mycarlos_verify": "验证登录",
    "mycarlos_portal_address": "门户网站网址",
    "mycarlos_qr_label": "在 myCarlos 中扫描",
    "mycarlos_qr_alt": "用于将 myCarlos 关联到此门户网站的二维码。",
    "mycarlos_qr_unavailable": "二维码不可用。如果您无法使用此门户网站网址，请联系您的诊所。",
}
