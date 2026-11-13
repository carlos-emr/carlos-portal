"""Fake branding for mail tests; contains no patient message or live credential."""

from carlos_patient_portal.clinic_footer import (
    ClinicFooterLogo,
    ClinicFooterSnapshot,
    footer_revision,
)


def fake_footer(clinic_id="default", text="FAKE Mandatory Clinic", logo=True):
    image = (
        ClinicFooterLogo("clinic-logo-fake@carlos-emr", "image/png", b"FAKE-logo") if logo else None
    )
    html = "<b>" + text + "</b>"
    return ClinicFooterSnapshot(clinic_id, html, text, footer_revision(html, text, image), image)


class FakeFooterProvider:
    def __init__(self, snapshot):
        self.current = snapshot
        self.calls = 0

    def snapshot(self):
        self.calls += 1
        return self.current
