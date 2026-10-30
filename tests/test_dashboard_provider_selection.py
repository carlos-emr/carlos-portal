from html.parser import HTMLParser

from fastapi.testclient import TestClient

from carlos_patient_portal.i18n import portal_text
from carlos_patient_portal.unlock_secrets import (
    MAX_UNLOCK_SECRET_PROVIDER_OPTIONS,
    create_unlock_secret,
)
from tests.support import (
    UNLOCK_SECRET_ENCRYPTION_SECRET,
    browser_sign_in_seeded_patient,
    migrated_development_app,
)


class ProviderOptions(HTMLParser):
    def __init__(self, markup):
        super().__init__()
        self.in_provider_select = False
        self.options = []
        self.feed(markup)

    def handle_starttag(self, tag, attributes):
        attributes = dict(attributes)
        if tag == "select":
            self.in_provider_select = attributes.get("id") == "email-password-provider"
        elif tag == "option" and self.in_provider_select:
            self.options.append(attributes)

    def handle_endtag(self, tag):
        if tag == "select":
            self.in_provider_select = False


def test_selected_provider_outside_the_capped_options_remains_selected_and_filters_rows() -> None:
    app = migrated_development_app()
    with TestClient(app) as client:
        browser_sign_in_seeded_patient(app, client)
        selected_value = "id:provider-selected"
        with app.state.session_factory() as session, session.begin():
            # These sort ahead of the selected provider and fill the bounded dropdown.
            for index in range(MAX_UNLOCK_SECRET_PROVIDER_OPTIONS):
                create_unlock_secret(
                    session,
                    clinic_id="default",
                    demographic_no=1234,
                    created_by=f"Provider {index:03d}",
                    created_by_id=f"provider-{index:03d}",
                    encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                    secret=f"FAKE other provider secret {index}",
                    label=f"Other-provider message {index}",
                )
            create_unlock_secret(
                session,
                clinic_id="default",
                demographic_no=1234,
                created_by="Zulu selected provider",
                created_by_id="provider-selected",
                encryption_secret=UNLOCK_SECRET_ENCRYPTION_SECRET,
                secret="FAKE selected provider secret",
                label="Selected-provider message",
            )

        unfiltered = client.get("/portal/email-passwords")
        assert unfiltered.status_code == 200
        ordinary_options = ProviderOptions(unfiltered.text).options
        ordinary_values = [option.get("value") for option in ordinary_options]
        assert "id:provider-000" in ordinary_values
        assert selected_value not in ordinary_values
        assert portal_text()["provider_options_truncated"] in unfiltered.text

        filtered = client.get("/portal/email-passwords", params={"provider": selected_value})
        assert filtered.status_code == 200
        filtered_options = ProviderOptions(filtered.text).options
        selected_options = [option for option in filtered_options if "selected" in option]
        assert [option.get("value") for option in selected_options] == [selected_value]
        assert sum(option.get("value") == selected_value for option in filtered_options) == 1
        assert "id:provider-000" in [option.get("value") for option in filtered_options]
        assert portal_text()["provider_options_truncated"] in filtered.text
        assert "Selected-provider message" in filtered.text
        assert "Other-provider message" not in filtered.text
        assert "FAKE selected provider secret" not in filtered.text
