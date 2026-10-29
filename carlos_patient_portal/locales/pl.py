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

"""Polish (pl) text for the patient portal.

Translate keys from `locales/en.py`, keeping each `{placeholder}` exactly. A key left out
falls back to English (`i18n.portal_text`). Once every key is in, list this locale as
complete in tests/test_i18n_catalog.py so the parity test keeps it complete.
"""

TEXT: dict[str, str] = {
    "hide_password": "Ukryj hasło",
    "show_password": "Pokaż hasło",
    "booking_month_1": "stycznia",
    "booking_month_2": "lutego",
    "booking_month_3": "marca",
    "booking_month_4": "kwietnia",
    "booking_month_5": "maja",
    "booking_month_6": "czerwca",
    "booking_month_7": "lipca",
    "booking_month_8": "sierpnia",
    "booking_month_9": "września",
    "booking_month_10": "października",
    "booking_month_11": "listopada",
    "booking_month_12": "grudnia",
    "booking_slot_date": "{weekday}, {day} {month}",
    "booking_weekday_0": "Poniedziałek",
    "booking_weekday_1": "Wtorek",
    "booking_weekday_2": "Środa",
    "booking_weekday_3": "Czwartek",
    "booking_weekday_4": "Piątek",
    "booking_weekday_5": "Sobota",
    "booking_weekday_6": "Niedziela",
    "date_of_birth_month_1": "Styczeń",
    "date_of_birth_month_2": "Luty",
    "date_of_birth_month_3": "Marzec",
    "date_of_birth_month_4": "Kwiecień",
    "date_of_birth_month_5": "Maj",
    "date_of_birth_month_6": "Czerwiec",
    "date_of_birth_month_7": "Lipiec",
    "date_of_birth_month_8": "Sierpień",
    "date_of_birth_month_9": "Wrzesień",
    "date_of_birth_month_10": "Październik",
    "date_of_birth_month_11": "Listopad",
    "date_of_birth_month_12": "Grudzień",
    "activation_date_of_birth_invalid": (
        "Sprawdź datę urodzenia: wpisz prawdziwą datę, na przykład 15 czerwca 1985."
    ),
    "date_of_birth": "Data urodzenia",
    "date_of_birth_day": "Dzień",
    "date_of_birth_hint": "Na przykład 15 czerwca 1985.",
    "date_of_birth_month": "Miesiąc",
    "date_of_birth_month_choose": "Wybierz miesiąc",
    "date_of_birth_year": "Rok",
    "activation_password_rejected": (
        "Wybierz inne hasło: użyj co najmniej 12 znaków, unikaj popularnych słów i schematów "
        "oraz nie umieszczaj w nim nazwy użytkownika, adresu e-mail, daty urodzenia ani numeru "
        "karty zdrowia."
    ),
    "activation_reenter_password": "Pozostałe dane zostały zachowane: wpisz ponownie hasło.",
}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
    "mycarlos_mfa_rate_limited": (
        "Kod logowania został niedawno wysłany. Poczekaj, zanim poprosisz o kolejny."
    ),
    "mycarlos_link": "Połącz myCarlos",
    "mycarlos_devices": "Połączone urządzenia",
    "mycarlos_instruction": (
        "W myCarlos wybierz opcję połączenia z portalem swojej przychodni, a "
        "następnie wpisz ten kod."
    ),
    "mycarlos_code_label": "Kod jednorazowy",
    "mycarlos_lifetime": (
        "Kod jest jednorazowy i ważny przez 10 minut. Nie wylogowuj się z tego portalu."
    ),
    "mycarlos_approval": (
        "Urządzenie musi też zostać zatwierdzone, zanim będzie mogło odbierać dokumenty."
    ),
    "mycarlos_create": "Utwórz kod",
    "mycarlos_another": "Utwórz kolejny kod",
    "mycarlos_linked": "Połączono",
    "mycarlos_last_seen": "Ostatnia aktywność",
    "mycarlos_empty": "Brak połączonych urządzeń. Wybierz Połącz myCarlos, aby dodać urządzenie.",
    "mycarlos_remove_question": "Usunąć to urządzenie?",
    "mycarlos_remove_effect": (
        "To urządzenie przestanie otrzymywać nowe dokumenty. Aby użyć go ponownie, "
        "połącz je jeszcze raz. Dokumenty już zapisane w myCarlos pozostaną w "
        "aplikacji."
    ),
    "mycarlos_remove": "Usuń urządzenie",
    "mycarlos_keep": "Zachowaj urządzenie",
    "mycarlos_paused": (
        "Łączenie zostało wstrzymane z powodu zbyt wielu nieprawidłowych kodów. "
        "Spróbuj ponownie później."
    ),
    "mycarlos_unavailable": "Łączenie jest niedostępne. Skontaktuj się z przychodnią.",
    "mycarlos_removed": "Urządzenie usunięte z listy.",
    "mycarlos_not_seen": "Brak aktywności",
    "mycarlos_mfa_required": "Potwierdź logowanie przed połączeniem lub usunięciem urządzenia.",
    "mycarlos_verify": "Potwierdź logowanie",
    "mycarlos_portal_address": "Adres portalu",
    "mycarlos_qr_label": "Zeskanuj w myCarlos",
    "mycarlos_qr_alt": "Kod QR do połączenia myCarlos z tym portalem.",
    "mycarlos_qr_unavailable": (
        "Kod QR jest niedostępny. Skontaktuj się ze swoją przychodnią, jeśli nie możesz "
        "użyć tego adresu portalu."
    ),
}
