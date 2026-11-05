"""Authentication errors keep useful diagnostics without returning submitted secrets."""

import pytest
from fastapi.testclient import TestClient

from carlos_patient_portal import main
from tests.support import development_settings


@pytest.mark.parametrize(
    ("path", "payload", "field", "error_type", "private_values"),
    [
        (
            "/auth/login",
            {"username": "FAKE user", "password": {"nested": "FAKE_PRIVATE_PASSWORD"}},
            "password",
            "string_type",
            ["FAKE_PRIVATE_PASSWORD"],
        ),
        (
            "/auth/mfa/verify",
            {
                "mfa_challenge_token": "FAKE_PRIVATE_CHALLENGE",
                "code": ["FAKE_PRIVATE_CODE"],
            },
            "code",
            "string_type",
            ["FAKE_PRIVATE_CHALLENGE", "FAKE_PRIVATE_CODE"],
        ),
        (
            "/auth/password-reset/complete",
            {
                "reset_token": "FAKE_PRIVATE_RESET_TOKEN",
                "new_password": {"nested": "FAKE_PRIVATE_NEW_PASSWORD"},
            },
            "new_password",
            "string_type",
            ["FAKE_PRIVATE_RESET_TOKEN", "FAKE_PRIVATE_NEW_PASSWORD"],
        ),
        (
            "/auth/login",
            {
                "username": "FAKE user",
                "password": "FAKE_PRIVATE_PASSWORD",
                "mfa_delivery_method": "FAKE_PRIVATE_FACTOR",
            },
            "mfa_delivery_method",
            "literal_error",
            ["FAKE_PRIVATE_PASSWORD", "FAKE_PRIVATE_FACTOR"],
        ),
    ],
)
def test_json_validation_does_not_echo_secrets_or_private_error_context(
    path, payload, field, error_type, private_values
):
    app = main.create_app(development_settings(database_url="sqlite+pysqlite:///:memory:"))
    client = TestClient(app)
    try:
        response = client.post(path, json=payload)

        assert response.status_code == 422
        assert response.headers["content-type"].startswith("application/json")
        errors = response.json()["detail"]
        assert len(errors) == 1
        assert errors[0]["loc"][-1] == field
        assert errors[0]["type"] == error_type
        assert errors[0]["msg"]
        assert "input" not in errors[0]
        assert "ctx" not in errors[0]
        assert all(value not in response.text for value in private_values)
    finally:
        client.close()
        app.state.database_engine.dispose()
