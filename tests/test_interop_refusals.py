# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.
"""The interoperability helpers' refusals: text that cannot go into HL7 or FHIR, and a conformance
profile that is not the one CARLOS owns.

Nothing here touches the database or a route: the helpers are pure. The conformance errors are
returned to callers and can reach a log, so each case also checks that no patient value is in them.
FAKE data only.
"""

import copy
from datetime import UTC, date, datetime, timedelta, timezone
from pathlib import Path

import pytest

from carlos_patient_portal import interop
from carlos_patient_portal.interop import (
    MAX_HL7_NAMESPACE_ID_LENGTH,
    MAX_PATIENT_NAME_LENGTH,
    Hl7ConformanceProfileError,
    PortalPatientInteroperabilityIdentity,
    build_fhir_id,
    build_fhir_r4_portal_patient,
    build_hl7_v251_patient_registration,
    format_hl7_timestamp,
    load_hl7_v251_patient_registration_profile,
    normalize_fhir_display_text,
    normalize_hl7_namespace_id,
    normalize_interop_identity,
    normalize_patient_name_part,
    validate_hl7_v251_patient_registration_profile,
)
from carlos_patient_portal.models import MAX_DEMOGRAPHIC_NO, PatientPortalAccount

IDENTITY = PortalPatientInteroperabilityIdentity(
    clinic_id="default",
    demographic_no=1234,
    email="fake.patient@example.test",
    date_of_birth=date(1980, 1, 2),
    health_card_number="ABCD12345678",
    family_name="Patient",
    given_name="Example",
)
MESSAGE = build_hl7_v251_patient_registration(
    IDENTITY,
    message_time=datetime(2026, 7, 23, 12, 0, tzinfo=UTC),
    message_control_id="MSG0001",
)
PROFILE = load_hl7_v251_patient_registration_profile()


def refused(profile: dict[str, object]) -> str:
    with pytest.raises(Hl7ConformanceProfileError) as failure:
        validate_hl7_v251_patient_registration_profile(MESSAGE, profile=profile)
    text = str(failure.value)
    # What is reported is the shape of a value, never the value (no name, birth date, email, card).
    for value in ("Patient", "Example", "19800102", "fake.patient", "ABCD12345678"):
        assert value not in text
    return text


def with_entries(key: str, *entries: object) -> dict[str, object]:
    profile = copy.deepcopy(PROFILE)
    profile[key] = list(entries)
    return profile


# --------------------------------------------------------------------------------------------
# Text that goes into a message
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize("function", [normalize_patient_name_part, normalize_fhir_display_text])
def test_a_name_that_is_blank_or_too_long_is_refused(function) -> None:
    assert function("  Ada   Lovelace ", "name") == "Ada Lovelace"
    with pytest.raises(ValueError, match="name must not be blank"):
        function(" \t ", "name")
    with pytest.raises(ValueError, match=f"{MAX_PATIENT_NAME_LENGTH} characters or fewer"):
        function("a" * (MAX_PATIENT_NAME_LENGTH + 1), "name")
    assert function("a" * MAX_PATIENT_NAME_LENGTH, "name") == "a" * MAX_PATIENT_NAME_LENGTH


@pytest.mark.parametrize("separator", ["|", "^", "~", "\\", "&"])
def test_a_name_part_may_not_contain_an_hl7_separator(separator) -> None:
    with pytest.raises(ValueError, match="HL7 separator characters"):
        normalize_patient_name_part(f"Ada{separator}Lovelace", "name")
    # A display text is not an HL7 field, so only a control character is refused there.
    assert normalize_fhir_display_text(f"Ada{separator}Lovelace", "name").startswith("Ada")


def test_a_namespace_id_is_short_plain_and_never_blank() -> None:
    assert normalize_hl7_namespace_id(" clinic.A-1_x ", "id") == "clinic.A-1_x"
    with pytest.raises(ValueError, match="id must not be blank"):
        normalize_hl7_namespace_id("   ", "id")
    with pytest.raises(ValueError, match=f"{MAX_HL7_NAMESPACE_ID_LENGTH} characters or fewer"):
        normalize_hl7_namespace_id("a" * (MAX_HL7_NAMESPACE_ID_LENGTH + 1), "id")
    for bad in ("a b", "a|b", "é", "a/b"):
        with pytest.raises(ValueError, match="letters, numbers, dots, underscores, or hyphens"):
            normalize_hl7_namespace_id(bad, "id")


def test_a_fhir_id_needs_every_part_and_is_a_stable_length_prefixed_hash() -> None:
    with pytest.raises(ValueError, match="FHIR ID components must not be blank"):
        build_fhir_id()
    for parts in (("portal", " "), ("", "x"), ("a", "b", "")):
        with pytest.raises(ValueError, match="FHIR ID components must not be blank"):
            build_fhir_id(*parts)
    same = build_fhir_id("portal", "default", 1234)
    assert same == build_fhir_id(" portal ", "default", "1234")
    assert same.startswith("portal-") and len(same) == len("portal-") + 56
    # Length-prefixed parts: moving a character between parts makes another id.
    assert build_fhir_id("ab", "c") != build_fhir_id("a", "bc")


def test_an_identity_with_an_impossible_demographic_number_is_refused() -> None:
    for number in (0, -1, MAX_DEMOGRAPHIC_NO + 1):
        bad = PortalPatientInteroperabilityIdentity(
            **{**IDENTITY.__dict__, "demographic_no": number}
        )
        with pytest.raises(ValueError, match="demographic_no must be between 1 and"):
            normalize_interop_identity(bad)
    assert normalize_interop_identity(IDENTITY).demographic_no == 1234


def test_a_portal_patient_carries_a_phone_number_only_when_the_account_has_one() -> None:
    def account(phone: str | None) -> PatientPortalAccount:
        return PatientPortalAccount(
            clinic_id="default",
            demographic_no=1234,
            username="fake.user",
            email="fake.patient@example.test",
            phone_number=phone,
        )

    without = build_fhir_r4_portal_patient(account(None))
    with_phone = build_fhir_r4_portal_patient(account("+15555550100"))
    assert [t["system"] for t in without["telecom"]] == ["email"]
    assert [(t["system"], t["value"]) for t in with_phone["telecom"]] == [
        ("email", "fake.patient@example.test"),
        ("phone", "+15555550100"),
    ]


def test_a_timestamp_is_utc_whether_it_was_given_with_a_zone_or_without() -> None:
    assert format_hl7_timestamp(datetime(2026, 7, 23, 12, 0)) == "20260723120000"
    assert format_hl7_timestamp(datetime(2026, 7, 23, 12, 0, tzinfo=UTC)) == "20260723120000"
    eastern = timezone(timedelta(hours=-5))
    assert format_hl7_timestamp(datetime(2026, 7, 23, 7, 0, tzinfo=eastern)) == "20260723120000"


# --------------------------------------------------------------------------------------------
# A profile that is not CARLOS's
# --------------------------------------------------------------------------------------------


def test_the_shipped_profile_accepts_the_message_it_was_made_for() -> None:
    assert validate_hl7_v251_patient_registration_profile(MESSAGE, profile=PROFILE) == MESSAGE


def test_a_profile_with_another_id_or_hl7_version_is_refused_with_both_reasons() -> None:
    profile = copy.deepcopy(PROFILE)
    profile["id"] = "someone-elses-profile"
    profile["hl7_version"] = "2.3"
    text = refused(profile)
    assert "profile id does not match CARLOS patient registration profile" in text
    assert "profile HL7 version does not match supported version" in text


@pytest.mark.parametrize(
    ("key", "message"),
    [
        ("segments", "segment entry must be an object"),
        ("fixed_fields", "fixed field entry must be an object"),
        ("required_fields", "required field entry must be an object"),
        ("required_identifiers", "required identifier entry must be an object"),
    ],
)
def test_a_profile_entry_that_is_not_an_object_is_reported_and_the_rest_still_run(
    key, message
) -> None:
    profile = copy.deepcopy(PROFILE)
    profile[key] = ["not an object", *profile.get(key, [])]
    text = refused(profile)
    assert message in text
    # The other rules were still checked: nothing else was wrong with the shipped entries.
    assert "must not repeat" not in text


@pytest.mark.parametrize(
    "key", ["segments", "fixed_fields", "required_fields", "required_identifiers"]
)
def test_a_profile_list_that_is_not_a_list_is_a_controlled_error(key) -> None:
    profile = copy.deepcopy(PROFILE)
    profile[key] = {"not": "a list"}
    with pytest.raises(Hl7ConformanceProfileError, match=f"profile {key} must be a list"):
        validate_hl7_v251_patient_registration_profile(MESSAGE, profile=profile)


def test_a_required_segment_the_message_lacks_and_a_required_field_it_leaves_empty_are_named() -> (
    None
):
    profile = with_entries("segments", {"id": "NK1", "usage": "R"}, {"id": "PID", "usage": "R"})
    assert "NK1 segment is required" in refused(profile)
    profile = with_entries("required_fields", {"path": "PID-18"}, {"path": "PID-5.9"})
    text = refused(profile)
    assert "PID-18 is required" in text
    assert "PID-5.9 is required" in text  # a component the field does not have


def test_a_fixed_field_the_message_lacks_reports_empty_and_its_shape_only() -> None:
    profile = with_entries("fixed_fields", {"path": "PID-18", "value": "ACCT-SECRET-1"})
    text = refused(profile)
    assert "PID-18 does not match the profile" in text
    assert "got empty" in text
    assert "ACCT-SECRET-1" not in text  # only its length is said


def test_a_field_path_without_a_field_number_is_a_controlled_error() -> None:
    for path in ("PID", "-5", "PID-"):
        profile = with_entries("required_fields", {"path": path})
        with pytest.raises(Hl7ConformanceProfileError, match="invalid HL7 field path"):
            validate_hl7_v251_patient_registration_profile(MESSAGE, profile=profile)


def test_a_profile_file_that_is_not_a_json_object_is_refused(monkeypatch) -> None:
    monkeypatch.setattr(Path, "read_text", lambda self, *args, **kwargs: "[1, 2]")
    with pytest.raises(Hl7ConformanceProfileError, match="must be a JSON object"):
        interop.load_hl7_v251_patient_registration_profile()
