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

"""Traditional Chinese (zh-TW, 繁體中文) text for the patient portal.

Translate keys from `locales/en.py`, keeping each `{placeholder}` exactly; a key left out falls
back to English (`i18n.portal_text`). Once every key is in, list this locale as complete in
tests/test_i18n_catalog.py so the parity test keeps it complete.

Chinese conventions, shared with myCarlos so a patient meets the same words in both:
- full-width punctuation in sentences (，。：（）); ASCII digits, codes, addresses and placeholders;
- one plural form: counted text uses the `_other` key only;
- terms already chosen in myCarlos:
  診所入口網站 (clinic portal),
  連結碼 (linking code),
  驗證碼 (emailed code),
  核准 (approve),
  「安全性」 (Security);
- zh-CN and zh-TW are separate translations, not a character conversion: Taiwan wording differs
  (帳戶, 資訊, 設定 rather than 账户, 信息, 设置).
"""

TEXT: dict[str, str] = {
    "account": "帳戶",
    "account_change_error": "無法完成帳戶變更。",
    "account_help": "帳戶說明",
    "account_status_contact_notice_failed": (
        "入口網站聯絡資料已更新，但無法傳送確認電子郵件。如果您並未預期這項變更，請聯絡診所。"
    ),
    "account_status_contact_updated": (
        "入口網站聯絡資料已更新。診所人員將審核 CARLOS 中相符的病患基本資料。"
    ),
    "account_status_contact_confirmation_required": (
        "請確認新的電子郵件地址，並輸入傳送至新電話號碼的確認碼。在兩者都確認之前，"
        "您目前的聯絡資料仍然有效。"
    ),
    "account_status_email_confirmation_required": (
        "請到新的電子郵件信箱查收確認連結。在您使用該連結之前，"
        "您目前的電子郵件地址仍會繼續收到驗證碼和密碼重設連結。"
    ),
    "account_status_email_confirmation_notice_failed": (
        "無法將確認郵件傳送至新的電子郵件地址。您的聯絡資料未變更。請再試一次，或聯絡診所。"
    ),
    "account_status_phone_confirmation_required": (
        "請輸入傳送至新電話號碼的確認碼。在確認之前，您目前的電話號碼仍然有效。"
    ),
    "account_status_phone_confirmation_invalid": (
        "電話確認碼無效或已過期。請重新申請確認碼後再試一次。"
    ),
    "account_status_phone_confirmation_notice_failed": (
        "無法將確認碼傳送至新的電話號碼。您的聯絡資料未變更。請再試一次，或聯絡診所。"
    ),
    "account_status_phone_confirmation_rate_limited": "最近已傳送過電話確認碼。請稍候再重新申請。",
    "account_status_mfa_updated": "兩步驟驗證設定已更新。",
    "account_status_no_change": "帳戶沒有任何變更。",
    "account_status_password_updated": "密碼已更新。",
    "all_providers": "所有醫師",
    "activate_account": "啟用帳戶",
    "activation_details": "請輸入診所提供的邀請資料，並建立您的入口網站登入資訊。",
    "activation_date_of_birth_invalid": "請檢查出生日期：輸入真實的日期，例如 1985 年 6 月 15 日。",
    "activation_error": "無法驗證啟用資料。",
    "activation_password_rejected": (
        "請選擇其他密碼：至少使用 12 "
        "個字元，避免常見字詞或規律，且不要包含您的使用者名稱、電子郵件、出生日期或健康卡號碼。"
    ),
    "activation_reenter_password": "您的其他輸入內容已保留：請再次輸入密碼。",
    "activation_heading": "啟用您的帳戶",
    "activation_rate_limited": "啟用嘗試次數過多。請稍候再試。",
    "activation_success": "您的入口網站帳戶已準備就緒。",
    "activation_success_heading": "帳戶已啟用",
    "back_to_sign_in": "返回登入",
    "booking_prompt_contact": "如需預約，請聯絡 {clinic_name}。",
    "booking_prompt_contact_phone": "如需預約，請致電 {clinic_name}，電話 {phone}。",
    "booking_prompt_no_online_booking": "無法在此入口網站預約門診。",
    "booking_prompt_suggested_by": "{provider} 建議您安排這次預約。",
    "booking_prompt_suggested_by_clinic": "您的診所建議您安排這次預約。",
    "booking_prompt_title_annual_exam": "預約您的年度健康檢查",
    "booking_prompt_title_follow_up": "預約回診",
    "booking_prompt_title_lab_review": "預約門診以討論您的檢驗結果",
    "booking_prompt_urgency_as_soon_as_possible": "請儘快預約。",
    "booking_prompt_urgency_routine": "請在方便的時間預約。",
    "booking_prompt_urgency_soon": "請在接下來幾週內預約。",
    "booking_booked": "已預約 {date} {time}。",
    "booking_choice_error": "無法選擇該時段。請查看下方訊息後再試一次。",
    "booking_choice_pending": "我們正在與診所確認您的時段。",
    "booking_choice_pending_overdue": "診所將確認您的時段。如有緊急狀況，請致電診所。",
    "booking_choice_pending_overdue_phone": (
        "診所將確認您的時段。如有緊急狀況，請致電診所：{phone}。"
    ),
    "booking_choice_expired": "該時段在診所確認前已過。請另選一個時段。",
    "booking_choice_expired_contact": "該時段在診所確認前已過。請聯絡診所。",
    "booking_choose": "選擇此時段",
    "booking_decline": "這些時段都不方便",
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
    "booking_offer_intro": "診所提供了以下時段。請選擇一個，診所將為您確認。",
    "booking_slot_date": "{month}{day}日 {weekday}",
    "booking_slot_detail_separator": " · ",
    "booking_slot_duration_other": "{minutes} 分鐘",
    "booking_slot_taken": "該時段剛被預約。請另選一個時段。",
    "booking_slot_taken_contact": "該時段剛被預約。請聯絡診所。",
    "booking_slot_time": "{hour:02d}:{minute:02d}",
    "booking_slot_when": "{date} {time}",
    "booking_slots_legend": "可預約的時段",
    "booking_visit_mode_in_person": "親自就診",
    "booking_visit_mode_phone": "電話看診",
    "booking_visit_mode_video": "視訊看診",
    "booking_weekday_0": "星期一",
    "booking_weekday_1": "星期二",
    "booking_weekday_2": "星期三",
    "booking_weekday_3": "星期四",
    "booking_weekday_4": "星期五",
    "booking_weekday_5": "星期六",
    "booking_weekday_6": "星期日",
    "email_change_confirm": "確認電子郵件地址",
    "email_change_complete_error": "此確認連結已失效。請從您的帳戶頁面重新申請變更。",
    "email_change_complete_heading": "確認您的新電子郵件地址",
    "email_change_complete_intro": "確認後，將更新用於接收登入驗證碼和密碼重設連結的電子郵件地址。",
    "email_change_success": "您的電子郵件地址已更新。診所人員將審核 CARLOS 中相符的病歷資料。",
    "email_change_success_heading": "電子郵件地址已確認",
    "email_change_phone_confirmation_pending": (
        "您的新電子郵件地址已確認。請登入並輸入傳送至新電話號碼的確認碼，以完成聯絡資料變更。"
    ),
    "change_password": "變更密碼",
    "clinic": "診所",
    "clinic_help": "診所說明",
    "clinic_help_message": "如果您無法存取帳戶或驗證方式，請聯絡診所。",
    "contact_info": "聯絡資訊",
    "contact_change_notice_failed": (
        "您的聯絡資訊已更新並已登出，但無法傳送安全性通知。如果這項變更並非由您進行，請聯絡診所。"
    ),
    "contact_change_success": (
        "您的聯絡資訊已更新。為了安全起見，您已被登出；請使用更新後的驗證方式重新登入。診所人員將審"
        "核 CARLOS 中相符的病歷資料。"
    ),
    "contact_change_success_heading": "聯絡資訊已更新",
    "contact_the_clinic": "聯絡診所",
    "copy": "複製",
    "copy_failed": "請手動選取並複製",
    "copied": "已複製",
    "current_password": "目前的密碼",
    "dashboard": "首頁",
    "dashboard_account_description": "管理您的密碼和聯絡資訊。",
    "dashboard_documents_description": "文件功能可能在未來版本提供。",
    "dashboard_email_passwords_description": "取得診所寄給您的加密文件密碼。",
    "dashboard_greeting": "病患入口網站",
    "dashboard_help_description": "查詢診所和帳戶支援資訊。",
    "dashboard_messages_description": "來自診所的請求，例如提醒您預約門診。",
    "date_from": "起始日期",
    "date_format_error": "請輸入有效的起始和結束日期。",
    "filter_error": "請輸入有效的篩選條件。",
    "date_range_error": "起始日期不得晚於結束日期。",
    "date_of_birth": "出生日期",
    "date_of_birth_day": "日",
    "date_of_birth_hint": "例如：1985 年 6 月 15 日。",
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
    "date_of_birth_month_choose": "請選擇月份",
    "date_of_birth_year": "年",
    "date_to": "結束日期",
    "development_mfa_code": (
        "開發用登入驗證碼（與電子郵件傳送的驗證碼相同，用於加快測試，日後將移除）："
    ),
    "development_reset_link": "開發用密碼重設連結（設定電子郵件後也會以電子郵件傳送）：",
    "documents": "文件",
    "email": "電子郵件",
    "email_codes_rate": "電子郵件驗證碼每分鐘最多可重新傳送一次。",
    "email_password": "文件密碼",
    "email_password_page_indicator": "第 {page} 頁，共 {total_pages} 頁",
    "email_password_pages": "文件密碼頁面",
    "email_passwords": "文件密碼",
    "email_passwords_region": "文件密碼",
    "forgot_username_password": "忘記使用者名稱或密碼？",
    "forgot_username_help": "如果您不知道自己的使用者名稱，請聯絡診所。",
    "future": "未來功能",
    "health_card_number": "健康卡號碼（HCN/HIN）",
    "help": "說明",
    "hide_password": "隱藏密碼",
    "incorrect_mfa_code": "驗證碼未被接受。請再試一次或申請新的驗證碼。",
    "incorrect_username_or_password": "使用者名稱或密碼錯誤",
    "invite_code": "邀請碼",
    "language_aria_label": "語言",
    "logo_alt": "CARLOS",
    "logout": "登出",
    "message_back": "返回訊息",
    "message_new": "新",
    "message_not_found": "該訊息已無法使用。",
    "message_sent_at": "傳送時間：{sent_at}",
    "messages": "訊息",
    "messages_empty": "您沒有來自診所的訊息。",
    "messages_new_count_other": "{count} 則新訊息",
    "mfa": "兩步驟驗證",
    "mfa_code": "登入驗證碼",
    "mfa_code_sent_email": "驗證碼已以電子郵件傳送至 {destination}。",
    "mfa_code_sent_email_unmasked": "驗證碼已傳送至您的電子郵件地址。",
    "mfa_code_sent_sms": "驗證碼已以簡訊傳送至 {destination}。",
    "mfa_code_sent_sms_unmasked": "驗證碼已傳送至您的手機號碼。",
    "mfa_delivery_unavailable": "無法使用該傳送方式。",
    "mfa_email": "電子郵件",
    "mfa_heading": "登入驗證碼",
    "mfa_help_message": "如果您無法接收或使用驗證碼，請聯絡 {clinic_name}。",
    "mfa_new_code_sent_email": "新的驗證碼已以電子郵件傳送。",
    "mfa_new_code_sent_sms": "新的驗證碼已以簡訊傳送。",
    "mfa_rate_limited_other": "最近已傳送過驗證碼。請在 {seconds} 秒後再試。",
    "mfa_resend": "重新傳送驗證碼",
    "mfa_sign_in_again": "請重新登入以申請新的驗證碼。",
    "mfa_send_by": "驗證碼傳送方式",
    "mfa_settings": "兩步驟驗證設定",
    "mfa_sms": "簡訊",
    "mfa_sms_rate": "簡訊驗證碼每五分鐘最多可重新傳送一次。",
    "mfa_verify": "驗證",
    "mfa_verification_failed": "無法完成兩步驟驗證。",
    "modal_close": "確定",
    "module_navigation": "入口網站功能",
    "mfa_method": "驗證方式",
    "new_password": "新密碼",
    "new_password_confirmation": "確認新密碼",
    "next": "下一頁",
    "no_email_passwords": "沒有文件密碼",
    "no_matching_email_passwords": "沒有符合條件的文件密碼",
    "open_reset_page": "開啟重設頁面",
    "password_label": "密碼",
    "password_hidden": "已隱藏",
    "password_for": "{subject} 的密碼",
    "password_confirmation": "確認密碼",
    "password_invalid": "新密碼不符合密碼要求。",
    "password_mismatch": "確認密碼與密碼不相符。",
    "password_placeholder": "密碼",
    "password_requirements": (
        "請至少使用 12 個字元。避免常見密碼以及帳戶、診所或個人資訊；多個不相關的字詞是不錯的選擇。"
    ),
    "password_reset_complete_error": "密碼重設連結無效或已過期。",
    "password_reset_complete_heading": "選擇新密碼",
    "password_reset_forced": "您必須先重設密碼才能登入。",
    "password_reset_link_sent": "如果帳戶資料相符，密碼重設連結已以電子郵件傳送。",
    "password_reset_request_details": (
        "請輸入您的入口網站使用者名稱，以及在診所登記的電子郵件地址。"
    ),
    "password_reset_request_heading": "重設您的密碼",
    "password_reset_send": "傳送重設連結",
    "password_reset_success": "您的密碼已重設。請使用新密碼登入。",
    "password_reset_success_heading": "密碼已重設",
    "password_reset_update": "更新密碼",
    "password_updated": "密碼已更新",
    "patient_dashboard": "病患首頁",
    "phone": "電話",
    "phone_required_for_sms": "選擇簡訊時必須填寫。",
    "phone_confirmation_code": "電話確認碼",
    "confirm_phone": "確認電話號碼",
    "resend_phone_confirmation": "再傳送一組確認碼",
    "previous": "上一頁",
    "provider": "醫師",
    "provider_options_truncated": "僅列出最近的醫師。請使用搜尋框縮小結果範圍。",
    "reveal": "顯示",
    "reveal_failed": "無法顯示密碼。請再試一次。",
    "reveal_password_hint": "顯示文件密碼之前，請先輸入您目前的帳戶密碼。",
    "password_reset_temporarily_unavailable": "密碼重設功能暫時無法使用。請稍後再試。",
    "revealing": "顯示中…",
    "reset_filters": "清除篩選條件",
    "search": "搜尋",
    "sent": "傳送時間",
    "session_locked_details": (
        "診所人員必須先解鎖此帳戶，才能再次登入或重設密碼。請聯絡診所尋求協助。"
    ),
    "request_failed_heading": "無法完成請求",
    "request_failed_details": (
        "入口網站無法完成該請求。這通常是因為頁面開啟太久，請返回入口網站後再試一次。"
    ),
    "service_busy_heading": "請求次數過多",
    "service_busy_details": "入口網站從此連線收到過多請求。請稍候再試。",
    "service_maintenance_heading": "入口網站無法使用",
    "service_maintenance_details": (
        "入口網站正在維護，暫時無法使用。請稍後再試；如果您現在需要協助，請聯絡診所。"
    ),
    "service_name_default": "CARLOS 病患入口網站",
    "service_unavailable_heading": "入口網站暫時無法使用",
    "service_unavailable_details": (
        "目前無法連線至入口網站。請在幾分鐘後再試；如果您現在需要協助，請聯絡診所。"
    ),
    "session_locked_heading": "帳戶已鎖定",
    "sign_in_aria_label": "登入",
    "sign_in_button": "登入",
    "sign_in_heading": "登入",
    "show_password": "顯示密碼",
    "source_code": "原始碼",
    "subject": "主旨",
    "unavailable": "無法使用",
    "update_contact": "更新聯絡資料",
    "update_mfa": "更新兩步驟驗證",
    "update_password": "更新密碼",
    "username": "使用者名稱",
    "username_label": "使用者名稱",
    "username_placeholder": "使用者名稱",
    "username_unavailable": "該使用者名稱無法使用。",
    "verification_delivery_failed": "無法傳送驗證碼。請再試一次。",
    "view_module": "開啟",
}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
    "mycarlos_mfa_rate_limited": "最近已傳送過登入驗證碼。請稍候再重新申請。",
    "mycarlos_link": "連結 myCarlos",
    "mycarlos_devices": "已連結的裝置",
    "mycarlos_instruction": (
        "在 myCarlos 中選擇「連結診所」以連結您的診所入口網站，然後輸入此連結碼。"
    ),
    "mycarlos_code_label": "連結碼",
    "mycarlos_lifetime": "此連結碼只能使用一次，有效期限 10 分鐘。請保持登入此入口網站。",
    "mycarlos_approval": "裝置還必須經過核准，才能接收文件。",
    "mycarlos_create": "建立連結碼",
    "mycarlos_another": "建立另一組連結碼",
    "mycarlos_linked": "連結時間",
    "mycarlos_last_seen": "最後連線時間",
    "mycarlos_empty": "沒有已連結的裝置。請選擇「連結 myCarlos」來新增裝置。",
    "mycarlos_remove_question": "要移除此裝置嗎？",
    "mycarlos_remove_effect": (
        "此裝置將不再接收新文件。若要再次使用，請重新連結。已儲存在 myCarlos 中的文件會保留。"
    ),
    "mycarlos_remove": "移除裝置",
    "mycarlos_remove_named": "移除裝置：{name}",
    "mycarlos_keep": "保留裝置",
    "mycarlos_paused": "由於輸入錯誤的連結碼次數過多，連結功能已暫停。請稍後再試。",
    "mycarlos_unavailable": "無法使用連結功能。請聯絡您的診所。",
    "mycarlos_removed": "裝置已移除。",
    "mycarlos_not_seen": "尚未連線",
    "mycarlos_mfa_required": "連結或移除裝置之前，請先驗證您的登入。",
    "mycarlos_verify": "驗證登入",
    "mycarlos_portal_address": "入口網站網址",
    "mycarlos_qr_label": "在 myCarlos 中掃描",
    "mycarlos_qr_alt": "用於將 myCarlos 連結至此入口網站的 QR 碼。",
    "mycarlos_qr_unavailable": "無法提供 QR 碼。如果您無法使用此入口網站網址，請聯絡您的診所。",
}
