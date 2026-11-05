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
    # Self sign-up (carlos-portal#15).
    "sign_up_contact_clinic": (
        "如果診所沒有您的電子郵件地址，或登記的是舊地址，請先聯絡診所，再申請帳戶。"
    ),
    "sign_up_details_invalid": (
        "請檢查您的資訊：輸入健康卡號碼、真實的出生日期和有效的電子郵件地址。"
    ),
    "sign_up_email": "診所登記的電子郵件地址",
    "sign_up_email_hint": "僅用於核對您的資訊。連結只會寄到診所紀錄中已有的電子郵件地址。",
    "sign_up_heading": "申請入口網站帳戶",
    "sign_up_intro": (
        "請輸入您的健康卡號碼、出生日期，以及診所登記的電子郵件地址。如果這些資訊與診所的紀錄相符，"
        "您會收到一封電子郵件，內含完成帳戶設定的連結。"
    ),
    "sign_up_result": (
        "如果您的資訊與我們的紀錄相符，我們已寄給您一封電子郵件，內含完成帳戶設定的連結。"
        "如果沒有收到，請聯絡診所。"
    ),
    "sign_up_result_heading": "已收到申請",
    "sign_up_submit": "申請帳戶",
    "sign_up_unavailable": "帳戶申請暫時無法使用。請稍後再試，或聯絡診所。",
}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {}
