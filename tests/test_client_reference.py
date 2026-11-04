"""Forwarded client identity is usable only through a trusted direct peer."""

import pytest
from fastapi import Request

from carlos_patient_portal.audit import UNKNOWN_CLIENT_REFERENCE
from carlos_patient_portal.web_support import get_request_client_reference
from tests.support import development_settings


def client_request(peer, *, header_name="x-forwarded-for", header_value=None):
    headers = (
        []
        if header_value is None
        else [(header_name.encode("ascii"), header_value.encode("ascii"))]
    )
    return Request(
        {
            "type": "http",
            "headers": headers,
            "client": None if peer is None else (peer, 12345),
        }
    )


def test_mixed_ip_proxy_chain_uses_the_nearest_untrusted_hop_not_a_spoofed_prefix():
    settings = development_settings(
        trusted_client_ip_header="x-forwarded-for",
        trusted_proxy_cidrs="10.0.0.0/8,fd00::/8",
    )
    request = client_request(
        "fd00::20",
        header_value="198.51.100.200, 2001:db8::7, fd00::10, 10.0.0.30",
    )

    assert get_request_client_reference(request, settings) == "2001:db8::7"


def test_real_ip_header_from_a_trusted_peer_returns_a_canonical_ipv6_address():
    settings = development_settings(
        trusted_client_ip_header="x-real-ip",
        trusted_proxy_cidrs="fd00::/8",
    )
    request = client_request(
        "fd00::20",
        header_name="x-real-ip",
        header_value=" 2001:0db8:0000:0000:0000:0000:0000:0007 ",
    )

    assert get_request_client_reference(request, settings) == "2001:db8::7"


@pytest.mark.parametrize(
    "header_value",
    [None, "", " , , ", "FAKE-not-an-IP", "203.0.113.7, FAKE-invalid-hop, 10.0.0.10"],
)
def test_missing_or_invalid_forwarded_chain_falls_back_to_the_direct_peer(header_value):
    settings = development_settings(
        trusted_client_ip_header="x-forwarded-for",
        trusted_proxy_cidrs="10.0.0.0/8",
    )
    request = client_request("10.0.0.20", header_value=header_value)

    assert get_request_client_reference(request, settings) == "10.0.0.20"


def test_untrusted_peer_cannot_choose_its_client_reference_using_real_ip():
    settings = development_settings(
        trusted_client_ip_header="x-real-ip",
        trusted_proxy_cidrs="10.0.0.0/8",
    )
    request = client_request("192.0.2.10", header_name="x-real-ip", header_value="203.0.113.99")

    assert get_request_client_reference(request, settings) == "192.0.2.10"


def test_real_ip_does_not_accept_a_forwarded_chain_as_a_single_client_address():
    settings = development_settings(
        trusted_client_ip_header="x-real-ip",
        trusted_proxy_cidrs="10.0.0.0/8",
    )
    request = client_request(
        "10.0.0.20", header_name="x-real-ip", header_value="203.0.113.7, 10.0.0.10"
    )

    assert get_request_client_reference(request, settings) == "10.0.0.20"


def test_forwarded_identity_is_ignored_when_proxy_trust_is_not_configured():
    request = client_request("192.0.2.10", header_value="203.0.113.99")

    assert get_request_client_reference(request, development_settings()) == "192.0.2.10"


def test_a_header_without_a_direct_peer_cannot_create_a_trusted_client_identity():
    settings = development_settings(
        trusted_client_ip_header="x-forwarded-for",
        trusted_proxy_cidrs="10.0.0.0/8",
    )
    request = client_request(None, header_value="203.0.113.99")

    assert get_request_client_reference(request, settings) == UNKNOWN_CLIENT_REFERENCE
