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
    # Self sign-up (carlos-portal#15).
    "sign_up_contact_clinic": (
        "如果诊所没有您的电子邮件地址，或登记的是旧地址，请先联系诊所，再申请账户。"
    ),
    "sign_up_details_invalid": (
        "请检查您的信息：输入健康卡号码、真实的出生日期和有效的电子邮件地址。"
    ),
    "sign_up_email": "诊所登记的电子邮件地址",
    "sign_up_email_hint": "仅用于核对您的信息。链接只会发送到诊所记录中已有的电子邮件地址。",
    "sign_up_heading": "申请门户网站账户",
    "sign_up_intro": (
        "请输入您的健康卡号码、出生日期以及诊所登记的电子邮件地址。如果这些信息与诊所的记录相符，"
        "您将收到一封电子邮件，其中包含完成账户设置的链接。"
    ),
    "sign_up_result": (
        "如果您的信息与我们的记录相符，我们已向您发送一封电子邮件，其中包含完成账户设置的链接。"
        "如果没有收到，请联系诊所。"
    ),
    "sign_up_result_heading": "已收到申请",
    "sign_up_submit": "申请账户",
    "sign_up_unavailable": "账户申请暂时无法使用。请稍后再试，或联系诊所。",
}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {}
