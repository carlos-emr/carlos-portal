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
    "account": "Konto",
    "account_change_error": "Nie udało się wprowadzić zmiany konta.",
    "account_help": "Pomoc dotycząca konta",
    "account_status_contact_notice_failed": (
        "Dane kontaktowe portalu zostały zaktualizowane, ale nie udało się wysłać wiadomości "
        "e-mail z potwierdzeniem. Jeśli ta zmiana była nieoczekiwana, proszę skontaktować się "
        "z przychodnią."
    ),
    "account_status_contact_updated": (
        "Dane kontaktowe portalu zostały zaktualizowane. Personel sprawdzi odpowiadające im dane "
        "demograficzne w CARLOS."
    ),
    "account_status_contact_confirmation_required": (
        "Proszę potwierdzić nowy adres e-mail i wpisać kod wysłany na nowy numer telefonu. "
        "Dotychczasowe dane kontaktowe pozostają aktywne do czasu potwierdzenia obu nowych."
    ),
    "account_status_email_confirmation_required": (
        "Proszę sprawdzić nową skrzynkę e-mail w poszukiwaniu linku potwierdzającego. Do czasu"
        " użycia tego linku dotychczasowy adres nadal będzie otrzymywać kody logowania i linki"
        " do resetowania hasła."
    ),
    "account_status_email_confirmation_notice_failed": (
        "Nie udało się wysłać potwierdzenia na nowy adres e-mail. Dane kontaktowe nie zostały "
        "zmienione. Proszę spróbować ponownie lub skontaktować się z przychodnią."
    ),
    "account_status_phone_confirmation_required": (
        "Proszę wpisać kod potwierdzający wysłany na nowy numer telefonu. Dotychczasowy numer "
        "telefonu pozostaje aktywny do czasu potwierdzenia nowego."
    ),
    "account_status_phone_confirmation_invalid": (
        "Kod potwierdzający numer telefonu jest nieprawidłowy lub wygasł. Proszę poprosić o "
        "kolejny kod i spróbować ponownie."
    ),
    "account_status_phone_confirmation_notice_failed": (
        "Nie udało się wysłać kodu potwierdzającego na nowy numer telefonu. Dane kontaktowe "
        "nie zostały zmienione. Proszę spróbować ponownie lub skontaktować się z przychodnią."
    ),
    "account_status_phone_confirmation_rate_limited": (
        "Kod potwierdzający numer telefonu został niedawno wysłany. Proszę odczekać przed "
        "poproszeniem o kolejny."
    ),
    "account_status_mfa_updated": "Ustawienia weryfikacji dwuetapowej zostały zaktualizowane.",
    "account_status_no_change": "Brak zmian na koncie.",
    "account_status_password_updated": "Hasło zostało zaktualizowane.",
    "all_providers": "Wszyscy lekarze",
    "activate_account": "Aktywacja konta",
    "activation_details": (
        "Proszę wpisać dane z zaproszenia otrzymanego od przychodni i utworzyć dane logowania "
        "do portalu."
    ),
    "activation_date_of_birth_invalid": (
        "Proszę sprawdzić datę urodzenia: proszę wpisać prawdziwą datę, na przykład 15 czerwca"
        " 1985."
    ),
    "activation_error": "Nie udało się zweryfikować danych aktywacyjnych.",
    "activation_password_rejected": (
        "Proszę wybrać inne hasło: użyć co najmniej 12 znaków, proszę unikać popularnych słów "
        "i schematów oraz nie umieszczać w nim nazwy użytkownika, adresu e-mail, daty "
        "urodzenia ani numeru karty zdrowia."
    ),
    "activation_reenter_password": (
        "Pozostałe dane zostały zachowane: proszę wpisać ponownie hasło."
    ),
    "activation_heading": "Aktywacja konta",
    "activation_rate_limited": (
        "Wykonano zbyt wiele prób aktywacji. Proszę odczekać przed kolejną próbą."
    ),
    "activation_success": "Konto w portalu jest gotowe.",
    "activation_success_heading": "Konto aktywowane",
    "back_to_sign_in": "Powrót do logowania",
    "booking_prompt_contact": "Aby umówić wizytę, proszę skontaktować się z {clinic_name}.",
    "booking_prompt_contact_phone": (
        "Aby umówić wizytę, proszę zadzwonić do {clinic_name} pod numer {phone}."
    ),
    "booking_prompt_no_online_booking": "W tym portalu nie można umawiać wizyt.",
    "booking_prompt_suggested_by": "{provider} proponuje tę wizytę.",
    "booking_prompt_suggested_by_clinic": "Przychodnia proponuje tę wizytę.",
    "booking_prompt_title_annual_exam": "Proszę umówić coroczne badanie",
    "booking_prompt_title_follow_up": "Proszę umówić wizytę kontrolną",
    "booking_prompt_title_lab_review": (
        "Proszę umówić wizytę w celu omówienia wyników badań laboratoryjnych"
    ),
    "booking_prompt_urgency_as_soon_as_possible": "Proszę umówić wizytę jak najszybciej.",
    "booking_prompt_urgency_routine": "Proszę umówić wizytę w dogodnym dla siebie terminie.",
    "booking_prompt_urgency_soon": "Proszę umówić wizytę w ciągu najbliższych kilku tygodni.",
    "booking_booked": "Termin wizyty: {date}, godz. {time}.",
    "booking_choice_error": (
        "Nie udało się wybrać tego terminu. Proszę zapoznać się z komunikatem poniżej i "
        "spróbować ponownie."
    ),
    "booking_choice_pending": "Termin jest potwierdzany z przychodnią.",
    "booking_choice_pending_overdue": (
        "Przychodnia potwierdzi termin. Jeśli sprawa jest pilna, proszę zadzwonić do przychodni."
    ),
    "booking_choice_pending_overdue_phone": (
        "Przychodnia potwierdzi termin. Jeśli sprawa jest pilna, proszę zadzwonić do "
        "przychodni pod numer {phone}."
    ),
    "booking_choice_expired": (
        "Ten termin minął przed potwierdzeniem przez przychodnię. Proszę wybrać inny termin."
    ),
    "booking_choice_expired_contact": (
        "Ten termin minął przed potwierdzeniem przez przychodnię. Proszę skontaktować się z "
        "przychodnią."
    ),
    "booking_choose": "Proszę wybrać ten termin",
    "booking_decline": "Żaden z tych terminów mi nie odpowiada",
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
    "booking_offer_intro": (
        "Przychodnia zaproponowała poniższe terminy. Proszę wybrać jeden, a przychodnia go "
        "potwierdzi."
    ),
    "booking_slot_date": "{weekday}, {day} {month}",
    "booking_slot_detail_separator": " · ",
    "booking_slot_duration_few": "{minutes} minuty",
    "booking_slot_duration_many": "{minutes} minut",
    "booking_slot_duration_one": "{minutes} minuta",
    "booking_slot_taken": "Ten termin został właśnie zajęty. Proszę wybrać inny termin.",
    "booking_slot_taken_contact": (
        "Ten termin został właśnie zajęty. Proszę skontaktować się z przychodnią."
    ),
    "booking_slot_time": "{hour:02d}:{minute:02d}",
    "booking_slot_when": "{date} o {time}",
    "booking_slots_legend": "Dostępne terminy",
    "booking_visit_mode_in_person": "Osobiście",
    "booking_visit_mode_phone": "Telefonicznie",
    "booking_visit_mode_video": "Przez wideo",
    "booking_weekday_0": "Poniedziałek",
    "booking_weekday_1": "Wtorek",
    "booking_weekday_2": "Środa",
    "booking_weekday_3": "Czwartek",
    "booking_weekday_4": "Piątek",
    "booking_weekday_5": "Sobota",
    "booking_weekday_6": "Niedziela",
    "email_change_confirm": "Proszę potwierdzić adres e-mail",
    "email_change_complete_error": (
        "Ten link potwierdzający jest już nieważny. Proszę ponownie poprosić o zmianę na "
        "stronie swojego konta."
    ),
    "email_change_complete_heading": "Proszę potwierdzić nowy adres e-mail",
    "email_change_complete_intro": (
        "Potwierdzenie zmienia adres e-mail używany do wysyłania kodów weryfikacyjnych logowania i "
        "linków do resetowania hasła."
    ),
    "email_change_success": (
        "Adres e-mail został zaktualizowany. Personel przychodni sprawdzi odpowiadające mu dane w "
        "kartotece CARLOS."
    ),
    "email_change_success_heading": "Adres e-mail potwierdzony",
    "email_change_phone_confirmation_pending": (
        "Nowy adres e-mail został potwierdzony. Proszę zalogować się i wpisać kod wysłany na "
        "nowy numer telefonu, aby dokończyć zmianę danych kontaktowych."
    ),
    "change_password": "Proszę zmienić hasło",
    "clinic": "Przychodnia",
    "clinic_help": "Pomoc przychodni",
    "clinic_help_message": (
        "W razie braku dostępu do konta lub metody weryfikacji proszę skontaktować się z "
        "przychodnią."
    ),
    "contact_info": "Dane kontaktowe",
    "contact_change_notice_failed": (
        "Dane kontaktowe zostały zaktualizowane i nastąpiło wylogowanie, ale nie udało się "
        "wysłać powiadomienia o bezpieczeństwie. Proszę skontaktować się z przychodnią, jeśli "
        "ta zmiana nie była zamierzona."
    ),
    "contact_change_success": (
        "Dane kontaktowe zostały zaktualizowane. Ze względów bezpieczeństwa nastąpiło "
        "wylogowanie; proszę zalogować się ponownie, używając zaktualizowanej metody "
        "weryfikacji. Personel przychodni sprawdzi odpowiadające im dane w kartotece CARLOS."
    ),
    "contact_change_success_heading": "Dane kontaktowe zaktualizowane",
    "contact_the_clinic": "Proszę skontaktować się z przychodnią",
    "copy": "Proszę skopiować",
    "copy_failed": "Proszę zaznaczyć i skopiować ręcznie",
    "copied": "Skopiowano",
    "current_password": "Obecne hasło",
    "dashboard": "Panel główny",
    "dashboard_account_description": "Proszę zarządzać hasłem i danymi kontaktowymi.",
    "dashboard_documents_description": "Dokumenty mogą być dostępne w przyszłej wersji.",
    "dashboard_email_passwords_description": ("Hasła do zaszyfrowanych dokumentów od przychodni."),
    "dashboard_greeting": "Portal pacjenta",
    "dashboard_help_description": (
        "Proszę znaleźć informacje o pomocy dotyczącej przychodni i konta."
    ),
    "dashboard_messages_description": (
        "Prośby z przychodni, na przykład przypomnienie o umówieniu wizyty."
    ),
    "date_from": "Data od",
    "date_format_error": "Proszę wpisać prawidłowe daty „od” i „do”.",
    "filter_error": "Proszę wpisać prawidłowe filtry.",
    "date_range_error": "Data „od” nie może być późniejsza niż data „do”.",
    "date_of_birth": "Data urodzenia",
    "date_of_birth_day": "Dzień",
    "date_of_birth_hint": "Na przykład 15 czerwca 1985.",
    "date_of_birth_month": "Miesiąc",
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
    "date_of_birth_month_choose": "Proszę wybrać miesiąc",
    "date_of_birth_year": "Rok",
    "date_to": "Data do",
    "development_mfa_code": (
        "Deweloperski kod logowania (ten sam kod, który wysłano e-mailem; przyspiesza "
        "testowanie i zostanie później usunięty):"
    ),
    "development_reset_link": (
        "Deweloperski link do resetowania hasła (wysyłany także e-mailem, gdy poczta jest "
        "skonfigurowana):"
    ),
    "documents": "Dokumenty",
    "email": "E-mail",
    "email_codes_rate": "Kody e-mail można wysłać ponownie raz na minutę.",
    "email_password": "Hasło dokumentu",
    "email_password_page_indicator": "Strona {page} z {total_pages}",
    "email_password_pages": "Strony haseł dokumentów",
    "email_passwords": "Hasła dokumentów",
    "email_passwords_region": "Hasła dokumentów",
    "forgot_username_password": "Problem z nazwą użytkownika lub hasłem?",
    "forgot_username_help": (
        "W razie nieznajomości nazwy użytkownika proszę skontaktować się z przychodnią."
    ),
    "future": "W przyszłości",
    "health_card_number": "Numer karty zdrowia (HCN/HIN)",
    "help": "Pomoc",
    "hide_password": "Proszę ukryć hasło",
    "incorrect_mfa_code": (
        "Kod nie został przyjęty. Proszę spróbować ponownie lub poprosić o nowy kod."
    ),
    "incorrect_username_or_password": "Nieprawidłowa nazwa użytkownika lub hasło",
    "invite_code": "Kod zaproszenia",
    "language_aria_label": "Język",
    "logo_alt": "CARLOS",
    "logout": "Wylogowanie",
    "message_back": "Powrót do wiadomości",
    "message_new": "Nowa",
    "message_not_found": "Ta wiadomość nie jest już dostępna.",
    "message_sent_at": "Wysłano {sent_at}",
    "messages": "Wiadomości",
    "messages_empty": "Brak wiadomości z przychodni.",
    "messages_new_count_few": "{count} nowe",
    "messages_new_count_many": "{count} nowych",
    "messages_new_count_one": "{count} nowa",
    "mfa": "Weryfikacja dwuetapowa",
    "mfa_code": "Kod logowania",
    "mfa_code_sent_email": "Kod wysłano e-mailem na adres {destination}.",
    "mfa_code_sent_email_unmasked": "Kod wysłano na zarejestrowany adres e-mail.",
    "mfa_code_sent_sms": "Kod wysłano SMS-em na numer {destination}.",
    "mfa_code_sent_sms_unmasked": "Kod wysłano na zarejestrowany numer telefonu komórkowego.",
    "mfa_delivery_unavailable": "Ta metoda dostarczania jest niedostępna.",
    "mfa_email": "E-mail",
    "mfa_heading": "Kod logowania",
    "mfa_help_message": (
        "W razie problemów z odebraniem lub użyciem kodu logowania proszę skontaktować się z "
        "{clinic_name}."
    ),
    "mfa_new_code_sent_email": "Nowy kod został wysłany e-mailem.",
    "mfa_new_code_sent_sms": "Nowy kod został wysłany SMS-em.",
    "mfa_rate_limited_few": (
        "Kod został niedawno wysłany. Proszę spróbować ponownie za {seconds} sekundy."
    ),
    "mfa_rate_limited_many": (
        "Kod został niedawno wysłany. Proszę spróbować ponownie za {seconds} sekund."
    ),
    "mfa_rate_limited_one": (
        "Kod został niedawno wysłany. Proszę spróbować ponownie za {seconds} sekundę."
    ),
    "mfa_resend": "Proszę wysłać kod ponownie",
    "mfa_sign_in_again": "Proszę zalogować się ponownie, aby poprosić o nowy kod weryfikacyjny.",
    "mfa_send_by": "Proszę wysłać kod przez",
    "mfa_settings": "Ustawienia weryfikacji dwuetapowej",
    "mfa_sms": "SMS",
    "mfa_sms_rate": "Kody SMS można wysłać ponownie raz na pięć minut.",
    "mfa_verify": "Proszę zweryfikować",
    "mfa_verification_failed": "Nie udało się ukończyć weryfikacji dwuetapowej.",
    "modal_close": "OK",
    "module_navigation": "Moduły portalu",
    "mfa_method": "Metoda",
    "new_password": "Nowe hasło",
    "new_password_confirmation": "Proszę potwierdzić nowe hasło",
    "next": "Następna",
    "no_email_passwords": "Brak haseł dokumentów",
    "no_matching_email_passwords": "Brak pasujących haseł dokumentów",
    "open_reset_page": "Proszę otworzyć stronę resetowania",
    "password_label": "Hasło",
    "password_hidden": "Ukryte",
    "password_for": "Hasło do: {subject}",
    "password_confirmation": "Proszę potwierdzić hasło",
    "password_invalid": "Nowe hasło nie spełnia wymagań dotyczących haseł.",
    "password_mismatch": "Potwierdzenie hasła nie jest zgodne.",
    "password_placeholder": "hasło",
    "password_requirements": (
        "Proszę użyć co najmniej 12 znaków. Proszę unikać popularnych haseł oraz informacji o "
        "koncie, przychodni lub danych osobowych; kilka niepowiązanych ze sobą słów to dobry "
        "wybór."
    ),
    "password_reset_complete_error": "Link do resetowania hasła jest nieprawidłowy lub wygasł.",
    "password_reset_complete_heading": "Proszę wybrać nowe hasło",
    "password_reset_forced": "Przed zalogowaniem należy zresetować hasło.",
    "password_reset_link_sent": (
        "Jeśli dane konta są zgodne, link do resetowania hasła został wysłany e-mailem."
    ),
    "password_reset_request_details": (
        "Proszę wpisać swoją nazwę użytkownika w portalu oraz adres e-mail zarejestrowany w "
        "przychodni."
    ),
    "password_reset_request_heading": "Proszę zresetować hasło",
    "password_reset_send": "Proszę wysłać link do resetowania",
    "password_reset_success": (
        "Hasło zostało zresetowane. Proszę zalogować się, używając nowego hasła."
    ),
    "password_reset_success_heading": "Hasło zresetowane",
    "password_reset_update": "Proszę zaktualizować hasło",
    "password_updated": "Hasło zaktualizowane",
    "patient_dashboard": "Panel pacjenta",
    "phone": "Telefon",
    "phone_required_for_sms": "Wymagane, gdy wybrano SMS.",
    "phone_confirmation_code": "Kod potwierdzający numer telefonu",
    "confirm_phone": "Proszę potwierdzić numer telefonu",
    "resend_phone_confirmation": "Proszę wysłać kolejny kod",
    "previous": "Poprzednia",
    "provider": "Lekarz",
    "provider_options_truncated": (
        "Na liście znajdują się tylko ostatni lekarze. Proszę użyć pola wyszukiwania, aby "
        "zawęzić wyniki."
    ),
    "reveal": "Proszę pokazać",
    "reveal_failed": "Nie udało się wyświetlić hasła. Proszę spróbować ponownie.",
    "reveal_password_hint": (
        "Przed wyświetleniem hasła dokumentu proszę wpisać obecne hasło do konta."
    ),
    "password_reset_temporarily_unavailable": (
        "Resetowanie hasła jest tymczasowo niedostępne. Proszę spróbować ponownie za chwilę."
    ),
    "revealing": "Wyświetlanie...",
    "reset_filters": "Proszę wyczyścić filtry",
    "search": "Proszę szukać",
    "sent": "Wysłano",
    "session_locked_details": (
        "Personel przychodni musi odblokować to konto, zanim możliwe będzie kolejne logowanie "
        "lub resetowanie hasła. Proszę skontaktować się z przychodnią, aby uzyskać pomoc."
    ),
    "request_failed_heading": "Nie udało się wykonać żądania",
    "request_failed_details": (
        "Portal nie mógł wykonać tego żądania. Zwykle oznacza to, że strona była otwarta przez"
        " dłuższy czas – proszę wrócić do portalu i spróbować ponownie."
    ),
    "service_busy_heading": "Zbyt wiele żądań",
    "service_busy_details": (
        "Portal otrzymał zbyt wiele żądań z tego połączenia. Proszę odczekać chwilę i "
        "spróbować ponownie."
    ),
    "service_maintenance_heading": "Portal niedostępny",
    "service_maintenance_details": (
        "Portal jest tymczasowo niedostępny z powodu prac konserwacyjnych. Proszę spróbować "
        "ponownie za chwilę lub skontaktować się z przychodnią, jeśli pomoc jest potrzebna "
        "teraz."
    ),
    "service_name_default": "Portal pacjenta CARLOS",
    "service_unavailable_heading": "Portal tymczasowo niedostępny",
    "service_unavailable_details": (
        "Nie można obecnie połączyć się z portalem. Proszę spróbować ponownie za kilka minut "
        "lub skontaktować się z przychodnią, jeśli pomoc jest potrzebna teraz."
    ),
    "session_locked_heading": "Konto zablokowane",
    "sign_in_aria_label": "Proszę zalogować się",
    "sign_in_button": "Proszę zalogować się",
    "sign_in_heading": "Proszę zalogować się",
    "show_password": "Proszę pokazać hasło",
    "source_code": "Kod źródłowy",
    "subject": "Temat",
    "unavailable": "Niedostępne",
    "update_contact": "Proszę zaktualizować dane kontaktowe",
    "update_mfa": "Proszę zaktualizować weryfikację dwuetapową",
    "update_password": "Proszę zaktualizować hasło",
    "username": "Nazwa użytkownika",
    "username_label": "Nazwa użytkownika",
    "username_placeholder": "nazwa użytkownika",
    "username_unavailable": "Ta nazwa użytkownika jest niedostępna.",
    "verification_delivery_failed": (
        "Nie udało się wysłać kodu weryfikacyjnego. Proszę spróbować ponownie."
    ),
    "view_module": "Proszę otworzyć",
}

# The pages that link the myCarlos app to this portal.
MYCARLOS_TEXT: dict[str, str] = {
    "mycarlos_mfa_rate_limited": (
        "Kod logowania został niedawno wysłany. Proszę odczekać przed poproszeniem o kolejny."
    ),
    "mycarlos_link": "Proszę połączyć myCarlos",
    "mycarlos_devices": "Połączone urządzenia",
    "mycarlos_instruction": (
        "W myCarlos proszę wybrać opcję połączenia z portalem swojej przychodni, a następnie "
        "proszę wpisać ten kod."
    ),
    "mycarlos_code_label": "Kod połączenia",
    "mycarlos_lifetime": (
        "Kod jest jednorazowy i ważny przez 10 minut. Proszę nie wylogowywać się z tego portalu."
    ),
    "mycarlos_approval": (
        "Urządzenie musi też zostać zatwierdzone, zanim będzie mogło odbierać dokumenty."
    ),
    "mycarlos_create": "Proszę utworzyć kod",
    "mycarlos_another": "Proszę utworzyć kolejny kod",
    "mycarlos_linked": "Połączono",
    "mycarlos_last_seen": "Ostatnia aktywność",
    "mycarlos_empty": (
        "Brak połączonych urządzeń. Aby dodać urządzenie, proszę wybrać „Proszę połączyć myCarlos”."
    ),
    "mycarlos_remove_question": "Usunąć to urządzenie?",
    "mycarlos_remove_effect": (
        "To urządzenie przestanie otrzymywać nowe dokumenty. Aby znów z niego korzystać, "
        "proszę połączyć je ponownie. Dokumenty już zapisane w myCarlos pozostaną w aplikacji."
    ),
    "mycarlos_remove": "Proszę usunąć urządzenie",
    "mycarlos_remove_named": "Proszę usunąć urządzenie: {name}",
    "mycarlos_keep": "Proszę zachować urządzenie",
    "mycarlos_paused": (
        "Łączenie zostało wstrzymane z powodu zbyt wielu nieprawidłowych kodów. Proszę "
        "spróbować ponownie później."
    ),
    "mycarlos_unavailable": "Łączenie jest niedostępne. Proszę skontaktować się z przychodnią.",
    "mycarlos_removed": "Urządzenie usunięte z listy.",
    "mycarlos_not_seen": "Brak aktywności",
    "mycarlos_mfa_required": (
        "Proszę potwierdzić logowanie przed połączeniem lub usunięciem urządzenia."
    ),
    "mycarlos_verify": "Proszę potwierdzić logowanie",
    "mycarlos_portal_address": "Adres portalu",
    "mycarlos_qr_label": "Proszę zeskanować w myCarlos",
    "mycarlos_qr_alt": "Kod QR do połączenia myCarlos z tym portalem.",
    "mycarlos_qr_unavailable": (
        "Kod QR jest niedostępny. W razie problemów z użyciem tego adresu portalu proszę "
        "skontaktować się z przychodnią."
    ),
}
