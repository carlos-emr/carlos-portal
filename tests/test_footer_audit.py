import json
import os
from concurrent.futures import ProcessPoolExecutor
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest

from carlos_patient_portal import footer_audit
from carlos_patient_portal.footer_audit import FooterAuditStore, FooterAuditUnavailableError
from tests.footer_support import fake_footer


@pytest.fixture
def store(tmp_path):
    tmp_path.chmod(0o700)
    return FooterAuditStore(str(tmp_path), "default")


def record(tmp_path, attempt, suffix=".prepared.json"):
    """Attempts live in one folder per UTC hour: <root>/<date>/<hour>/."""
    return tmp_path / attempt.date / attempt.hour / (attempt.attempt_id + suffix)


def footer_file(tmp_path, revision):
    return tmp_path / footer_audit.FOOTERS_DIRECTORY / (revision + ".json")


def test_durable_snapshot_and_separate_outcome_exclude_message_content(store, tmp_path):
    attempt = store.prepare(fake_footer(), "password_reset")
    prepared = record(tmp_path, attempt)
    original = prepared.read_bytes()
    assert prepared.stat().st_mode & 0o777 == 0o600
    assert prepared.parent.stat().st_mode & 0o777 == 0o700
    assert prepared.parent.parent.stat().st_mode & 0o777 == 0o700
    assert json.loads(original) == {
        "schema": 2,
        "attempt_id": attempt.attempt_id,
        "prepared_at": json.loads(original)["prepared_at"],
        "kind": "password_reset",
        "footer_revision": fake_footer().revision,
        "footer_skipped": None,
    }
    stored = footer_file(tmp_path, fake_footer().revision)
    assert stored.stat().st_mode & 0o777 == 0o600
    assert stored.parent.stat().st_mode & 0o777 == 0o700
    assert json.loads(stored.read_bytes()) == {"schema": 1, "footer": fake_footer().to_dict()}
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
    path = record(tmp_path, attempt, ".outcome.json")
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
    path = footer_file(tmp_path, fake_footer().revision)
    value = json.loads(path.read_text())
    value["footer"]["footer_text"] = "Changed without updating revision"
    path.write_text(json.dumps(value))
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day=attempt.date)
    prepared = record(tmp_path, attempt)
    value = json.loads(prepared.read_text())
    value["footer_revision"] = "0" * 64  # names no stored footer
    path.write_text(json.dumps({"schema": 1, "footer": fake_footer().to_dict()}))
    prepared.write_text(json.dumps(value))
    with pytest.raises(FileNotFoundError):
        store.list_attempts(day=attempt.date)


def test_root_and_snapshot_symlinks_are_refused(store, tmp_path):
    attempt = store.prepare(fake_footer(), "mfa")
    path = record(tmp_path, attempt)
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
    path = record(tmp_path, attempt)
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
    path = record(tmp_path, attempt)
    path.write_bytes(b"x" * (footer_audit.MAX_FOOTER_PAYLOAD_BYTES + 1))
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day=attempt.date)


def test_storage_probe_is_durable_and_leaves_no_record(store, tmp_path):
    store.check_ready()
    assert list(tmp_path.iterdir()) == []


def test_each_footer_revision_is_stored_once_and_attempts_only_name_it(store, tmp_path):
    same = [store.prepare(fake_footer(), "booking_prompt") for _ in range(3)]
    other = store.prepare(fake_footer(text="Clinic B", logo=False), "mfa")
    footers = sorted(p.name for p in (tmp_path / footer_audit.FOOTERS_DIRECTORY).iterdir())
    assert footers == sorted(
        {
            fake_footer().revision + ".json",
            fake_footer(text="Clinic B", logo=False).revision + ".json",
        }
    )
    for attempt in [*same, other]:
        # No logo or footer copy per email: a prepared record stays a few hundred bytes.
        assert len(record(tmp_path, attempt).read_bytes()) < 400
    listed = {i["attempt_id"]: i for i in store.list_attempts(day=other.date)["attempts"]}
    assert {listed[a.attempt_id]["footer_text"] for a in same} == {"FAKE Mandatory Clinic"}
    assert listed[same[0].attempt_id]["logo_sha256"] == fake_footer().logo.sha256
    assert listed[other.attempt_id]["footer_text"] == "Clinic B"


def test_a_different_copy_of_a_stored_revision_is_refused_not_overwritten(store, tmp_path):
    store.prepare(fake_footer(), "mfa")
    path = footer_file(tmp_path, fake_footer().revision)
    changed = json.loads(path.read_text())
    changed["footer"]["footer_text"] = "FAKE tampered copy"
    path.write_text(json.dumps(changed))
    before = path.read_bytes()
    with pytest.raises(FooterAuditUnavailableError):
        store.prepare(fake_footer(), "mfa")
    assert path.read_bytes() == before


def _clock(monkeypatch, *instants):
    """Prepare attempts at given UTC times of one day (each also needs a unique id)."""
    values = iter(
        int(datetime(2026, 10, 28, hour, minute, tzinfo=UTC).timestamp()) * 1_000_000_000 + n
        for n, (hour, minute) in enumerate(instants)
    )
    monkeypatch.setattr(footer_audit, "time", SimpleNamespace(time_ns=lambda: next(values)))


def test_a_busy_day_is_listed_hour_by_hour_past_one_folder_limit(store, monkeypatch):
    # 3 hours x 2 attempts, each with an outcome: 12 entries in the day, 4 per hour folder.
    # Each attempt reads the clock twice: once to prepare, once for its outcome.
    _clock(monkeypatch, *[(h, m) for h in (9, 10, 11) for m in (5, 6) for _ in range(2)])
    attempts = []
    for _ in range(6):
        attempt = store.prepare(fake_footer(), "booking_prompt")
        store.record_outcome(attempt, "failed")
        attempts.append(attempt)
    assert {a.hour for a in attempts} == {"09", "10", "11"}
    monkeypatch.setattr(footer_audit, "MAX_AUDIT_DIRECTORY_ENTRIES", 4)
    newest_first = sorted((a.attempt_id for a in attempts), reverse=True)
    whole = store.list_attempts(day="2026-10-28", limit=100)
    assert [i["attempt_id"] for i in whole["attempts"]] == newest_first
    pages, before = [], None
    while True:
        page = store.list_attempts(day="2026-10-28", limit=4, before=before)
        pages.append([i["attempt_id"] for i in page["attempts"]])
        before = page["next_before"]
        if before is None:
            break
    assert pages == [newest_first[:4], newest_first[4:]]
    # An hour folder over that size (6 entries in 08) stays readable too, page by page: writing
    # never stops for the audit, so listing must not refuse a busy hour (or its whole day).
    _clock(monkeypatch, *[(8, m) for m in (1, 2, 3) for _ in range(2)])
    for _ in range(3):
        attempt = store.prepare(fake_footer(), "booking_prompt")
        store.record_outcome(attempt, "failed")
        attempts.append(attempt)
    everything = sorted((a.attempt_id for a in attempts), reverse=True)
    listed, before = [], None
    while True:
        page = store.list_attempts(day="2026-10-28", limit=2, before=before)
        listed += [i["attempt_id"] for i in page["attempts"]]
        before = page["next_before"]
        if before is None:
            break
    assert listed == everything


def test_cursor_from_another_day_and_a_misplaced_record_are_refused(store, tmp_path, monkeypatch):
    _clock(monkeypatch, (10, 0), (11, 0))
    first, second = store.prepare(fake_footer(), "mfa"), store.prepare(fake_footer(), "mfa")
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day="2026-10-27", before=first.attempt_id)
    moved = tmp_path / second.date / first.hour / (second.attempt_id + ".prepared.json")
    record(tmp_path, second).rename(moved)
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day="2026-10-28")


def test_a_skipped_footer_is_recorded_only_for_codes_and_resets(store, tmp_path):
    attempt = store.prepare_skipped("mfa", "freshness")
    value = json.loads(record(tmp_path, attempt).read_text())
    assert (value["footer_revision"], value["footer_skipped"]) == (None, "freshness")
    assert not (tmp_path / footer_audit.FOOTERS_DIRECTORY).exists()
    store.record_outcome(attempt, "accepted")
    item = store.list_attempts(day=attempt.date)["attempts"][0]
    assert item["footer_skipped"] == "freshness" and item["status"] == "accepted"
    assert (item["revision"], item["footer_text"], item["logo_sha256"]) == (None, None, None)
    for kind, reason in [
        ("contact_change", "freshness"),
        ("booking_prompt", "config"),
        ("mfa", "x"),
    ]:
        with pytest.raises(FooterAuditUnavailableError):
            store.prepare_skipped(kind, reason)
    # A stored skip for a kind that may not skip is refused when read.
    value["kind"] = "contact_change"
    record(tmp_path, attempt).write_text(json.dumps(value))
    with pytest.raises(FooterAuditUnavailableError):
        store.list_attempts(day=attempt.date)
