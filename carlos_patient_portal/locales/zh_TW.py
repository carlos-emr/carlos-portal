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

TEXT: dict[str, str] = {}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {}
