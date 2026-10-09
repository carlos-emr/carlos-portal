import json
import os
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime

import pytest

from carlos_patient_portal import footer_audit
from carlos_patient_portal.footer_audit import FooterAuditStore, FooterAuditUnavailableError
from tests.footer_support import fake_footer


@pytest.fixture
def store(tmp_path):
    tmp_path.chmod(0o700)
    return FooterAuditStore(str(tmp_path), "default")


def test_durable_snapshot_and_separate_outcome_exclude_message_content(store, tmp_path):
    attempt = store.prepare(fake_footer(), "password_reset")
    prepared = tmp_path / attempt.date / (attempt.attempt_id + ".prepared.json")
    original = prepared.read_bytes()
    assert prepared.stat().st_mode & 0o777 == 0o600
    assert prepared.parent.stat().st_mode & 0o777 == 0o700
    assert set(json.loads(original)) == {"schema", "attempt_id", "prepared_at", "kind", "footer"}
    first = store.list_attempts(day=attempt.date)["attempts"][0]
    assert first["status"] == "prepared"
    assert first["status_at"] is None
    store.record_outcome(attempt, "accepted")
    assert prepared.read_bytes() == original
    second = store.list_attempts(day=attempt.date)["attempts"][0]
    assert second["status"] == "accepted"
    assert second["footer_text"] == "FAKE Mandatory Clinic"
    assert "footer_html" not in second
    assert "logo" not in second
    assert not any(name.name.startswith(".tmp-") for name in prepared.parent.iterdir())


def test_prepared_and_terminal_artifacts_cannot_be_overwritten(store, tmp_path):
    attempt = store.prepare(fake_footer(), "mfa")
    store.record_outcome(attempt, "accepted")
    path = tmp_path / attempt.date / (attempt.attempt_id + ".outcome.json")
    original = path.read_bytes()
    with pytest.raises(FileExistsError):
        store.record_outcome(attempt, "failed")
    assert path.read_bytes() == original


def test_old_footer_and_logo_stay_after_new_preparation(store):
    first = store.prepare(fake_footer(text="Clinic A"), "mfa")
    second = store.prepare(fake_footer(text="Clinic B", logo=False), "mfa")
    result = store.list_attempts(day=first.date)["attempts"]
    by_id = {item["attempt_id"]: item for item in result}
    assert by_id[first.attempt_id]["footer_text"] == "Clinic A"
    assert by_id[first.attempt_id]["logo_sha256"] == fake_footer().logo.sha256
    assert by_id[second.attempt_id]["footer_text"] == "Clinic B"
    assert by_id[second.attempt_id]["logo_sha256"] is None


def _parallel_attempt(directory):
    store = FooterAuditStore(directory, "default")
    attempt = store.prepare(fake_footer(), "booking_prompt")
    store.record_outcome(attempt, "accepted")
    return attempt.attempt_id


def test_web_and_worker_processes_publish_unique_durable_attempts(store, tmp_path):
    with ProcessPoolExecutor(max_workers=2) as processes:
        identities = list(processes.map(_parallel_attempt, [str(tmp_path)] * 6))
    assert len(set(identities)) == 6
    day = datetime.now(UTC).date().isoformat()
    result = store.list_attempts(day=day)["attempts"]
    assert len(result) == 6
    assert all(item["status"] == "accepted" for item in result)


def test_reverse_cursor_pagination_has_no_duplicates_or_missing_records(store):
    attempts = [store.prepare(fake_footer(), "contact_change") for _ in range(3)]
    first = store.list_attempts(day=attempts[0].date, limit=2)
    second = store.list_attempts(day=attempts[0].date, limit=2, before=first["next_before"])
    assert len(first["attempts"]) == 2
    assert len(second["attempts"]) == 1
    assert second["next_before"] is None
    actual = [item["attempt_id"] for item in first["attempts"] + second["attempts"]]
    assert actual == sorted((a.attempt_id for a in attempts), reverse=True)


def test_listing_refuses_corrupted_snapshot_and_wrong_clinic(store, tmp_path):
    attempt = store.prepare(fake_footer(), "mfa")
    with pytest.raises(FooterAuditUnavailableError):
        FooterAuditStore(str(tmp_path), "another-clinic").list_attempts(day=attempt.date)
    path = tmp_path / attempt.date / (attempt.attempt_id + ".prepared.json")
    value = json.loads(path.read_text())
    value["footer"]["footer_text"] = "Changed without updating revision"
    path.write_text(json.dumps(value))
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day=attempt.date)


def test_root_and_snapshot_symlinks_are_refused(store, tmp_path):
    attempt = store.prepare(fake_footer(), "mfa")
    path = tmp_path / attempt.date / (attempt.attempt_id + ".prepared.json")
    outside = tmp_path / "outside"
    outside.write_text("FAKE content must never be read through a symlink")
    path.unlink()
    path.symlink_to(outside)
    with pytest.raises(OSError):
        store.list_attempts(day=attempt.date)
    root_link = tmp_path / "root-link"
    root_link.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(FooterAuditUnavailableError):
        FooterAuditStore(str(root_link), "default").list_attempts(day=attempt.date)


def test_fifo_record_is_rejected_without_waiting(store, tmp_path):
    attempt = store.prepare(fake_footer(), "mfa")
    path = tmp_path / attempt.date / (attempt.attempt_id + ".prepared.json")
    path.unlink()
    os.mkfifo(path, 0o600)
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day=attempt.date)


def test_private_storage_required_even_when_date_has_no_records(store, tmp_path):
    tmp_path.chmod(0o755)
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day="2026-01-01")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"day": "../other"},
        {"day": "2026-02-30"},
        {"day": "2026-01-01", "before": "../../other"},
        {"day": "2026-01-01", "limit": 101},
        {"day": "2026-01-01", "limit": 0},
    ],
)
def test_date_cursor_and_page_limits_are_enforced(store, kwargs):
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(**kwargs)


def test_scan_and_record_size_limits_fail_explicitly(store, tmp_path, monkeypatch):
    attempt = store.prepare(fake_footer(), "mfa")
    monkeypatch.setattr(footer_audit, "MAX_AUDIT_DIRECTORY_ENTRIES", 0)
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day=attempt.date)
    monkeypatch.setattr(footer_audit, "MAX_AUDIT_DIRECTORY_ENTRIES", 10_000)
    path = tmp_path / attempt.date / (attempt.attempt_id + ".prepared.json")
    path.write_bytes(b"x" * (footer_audit.MAX_FOOTER_PAYLOAD_BYTES + 1))
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day=attempt.date)


def test_storage_probe_is_durable_and_leaves_no_record(store, tmp_path):
    store.check_ready()
    assert list(tmp_path.iterdir()) == []
