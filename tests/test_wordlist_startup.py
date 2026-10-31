from pathlib import Path

import pytest

from carlos_patient_portal import main, unlock_secrets
from tests.support import (
    RecordingPortalEmailSender,
    RecordingPortalSmsSender,
    development_settings,
)


@pytest.mark.parametrize("corruption", ["truncated", "duplicate"])
def test_corrupt_wordlist_stops_app_construction_before_database_initialization(
    tmp_path, monkeypatch: pytest.MonkeyPatch, corruption: str
) -> None:
    packaged = Path(unlock_secrets.__file__).parent / unlock_secrets.UNLOCK_SECRET_WORDLIST_RESOURCE
    original = packaged.read_text(encoding="utf-8")
    private_copy = tmp_path / "private-wordlist.txt"
    private_copy.write_text(original, encoding="utf-8")
    monkeypatch.setattr(unlock_secrets, "UNLOCK_SECRET_WORDLIST_RESOURCE", str(private_copy))
    real_engine_factory = main.create_portal_engine
    engines = []

    def observe_engine(*args, **kwargs):
        engine = real_engine_factory(*args, **kwargs)
        engines.append(engine)
        return engine

    monkeypatch.setattr(main, "create_portal_engine", observe_engine)
    settings = development_settings(
        database_url="sqlite+pysqlite:///:memory:",
        session_secret="FAKE-wordlist-startup-session-secret-0001",
        mycarlos_delivery_enabled=False,
        mycarlos_mailbox_enabled=False,
    )

    def construct_app():
        return main.create_app(
            settings,
            email_sender=RecordingPortalEmailSender(),
            sms_sender=RecordingPortalSmsSender(),
        )

    unlock_secrets.load_unlock_secret_words.cache_clear()
    try:
        # The unchanged corpus builds a real app and reaches the private engine factory.
        valid_app = construct_app()
        assert valid_app.state.database_engine in engines
        valid_engine_count = len(engines)
        lines = original.splitlines()
        rows = [
            index
            for index, line in enumerate(lines)
            if line.strip() and not line.strip().startswith("#")
        ]
        if corruption == "truncated":
            del lines[rows[-1]]
        else:
            first_word = lines[rows[0]].split()[-1]
            last_word = lines[rows[-1]].split()[-1]
            assert first_word != last_word
            lines[rows[-1]] = lines[rows[-1]].replace(last_word, first_word, 1)
        private_copy.write_text("\n".join(lines) + "\n", encoding="utf-8")
        # A fresh process would have a cold cache; this is not a file-monitoring promise.
        unlock_secrets.load_unlock_secret_words.cache_clear()

        with pytest.raises(RuntimeError, match="wordlist"):
            construct_app()
        assert len(engines) == valid_engine_count
    finally:
        unlock_secrets.load_unlock_secret_words.cache_clear()
        for engine in engines:
            engine.dispose()
