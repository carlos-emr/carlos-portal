# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Request-shape and classification tests for the three provider adapters.

No network, no provider SDK, no credential: a recording client answers scripted statuses and the
tests read back the exact request each adapter would have sent.
"""

import base64
import json
import logging
import re
import unittest
from pathlib import Path
from uuid import UUID
from xml.etree import ElementTree

from carlos_patient_portal import notification_transports as nt
from carlos_patient_portal.mycarlos_availability import (
    MAX_HINT_BYTES,
    CurrentAvailability,
    DispatchLease,
    GenericNotice,
    OutboxIntent,
    Owner,
    ProviderResult,
    PushPlatform,
    ReadyHint,
    Subscription,
    TransportFailure,
    dispatch,
)
from tests import notification_transports_support as sup  # noqa: E402

NOW = 1_800_000_000
DESTINATION = UUID("00000000-0000-4000-8000-0000000000d1")
SUBSCRIPTION_ID = UUID("00000000-0000-4000-8000-0000000000a1")
EPOCH = UUID("00000000-0000-4000-8000-0000000000e1")
HINT = ReadyHint(SUBSCRIPTION_ID, EPOCH, 42)
NOTICE = GenericNotice(HINT)
COLLAPSE = "c" * 64
FCM_TOKEN = "fake-fcm-registration-token:APA91b" + "x" * 40
APNS_TOKEN = "ab" * 32
WNS_CHANNEL = "https://db5.notify.windows.com/?token=FAKECHANNEL"
OWNER = Owner(7, 11)

FCM = nt.FcmConfig("fake-project-id", Path("/nonexistent/fake-service-account.json"))
APNS = nt.ApnsConfig("FAKETEAM01", "FAKEKEYID1", Path("/nonexistent/fake.p8"), "ca.example.fake")
WNS = nt.WnsConfig("ms-app://S-1-15-2-1-2-3-4-5-6-7", "fake-client-secret")
SOURCE = Path(nt.__file__).read_text(encoding="utf-8")


def send(transport, platform, **kw):
    return transport.send(
        destination_id=kw.get("destination_id", DESTINATION), platform=platform,
        notice=NOTICE, ttl_seconds=kw.get("ttl_seconds", 600), collapse_key=COLLAPSE,
    )


def fcm(*responses, handle=FCM_TOKEN):
    return sup.RecordingFcmTransport(FCM, sup.FixedHandles({DESTINATION: handle}), *responses)


def apns(*responses, handle=APNS_TOKEN, config=APNS):
    return sup.RecordingApnsTransport(config, sup.FixedHandles({DESTINATION: handle}), *responses)


def wns(*responses, handle=WNS_CHANNEL):
    return sup.RecordingWnsTransport(WNS, sup.FixedHandles({DESTINATION: handle}), *responses)


def _hint(hint):
    return nt._hint_text(GenericNotice(hint))


def hint_from(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class RequestShapes(unittest.TestCase):
    def test_fcm_v1_message_carries_only_the_generic_notice_and_the_opaque_hint(self):
        transport = fcm(200)
        self.assertIs(send(transport, PushPlatform.ANDROID_FCM), ProviderResult.ACCEPTED)
        (request,) = transport.requests
        self.assertEqual(request.method, "POST")
        self.assertEqual(
            request.url, "https://fcm.googleapis.com/v1/projects/fake-project-id/messages:send"
        )
        self.assertEqual(request.headers["Authorization"], "Bearer fake-token")
        body = json.loads(request.body)
        self.assertEqual(set(body), {"message"})
        message = body["message"]
        self.assertEqual(set(message), {"token", "notification", "data", "android"})
        self.assertEqual(message["token"], FCM_TOKEN)
        self.assertEqual(message["notification"], {"title": "myCarlos", "body": NOTICE.body})
        self.assertEqual(set(message["data"]), {"h"})
        self.assertEqual(hint_from(message["data"]["h"]), HINT.encode())
        self.assertLessEqual(len(HINT.encode()), MAX_HINT_BYTES)
        self.assertEqual(
            message["android"], {"collapse_key": COLLAPSE, "ttl": "600s", "priority": "HIGH"}
        )

    def test_apns_token_auth_headers_and_alert_payload(self):
        transport = apns(200)
        self.assertIs(send(transport, PushPlatform.IOS_APNS), ProviderResult.ACCEPTED)
        (request,) = transport.requests
        self.assertEqual(request.method, "POST")
        self.assertEqual(request.url, f"https://api.push.apple.com/3/device/{APNS_TOKEN}")
        self.assertEqual(
            dict(request.headers),
            {
                "authorization": "bearer fake-token",
                "apns-topic": "ca.example.fake",
                "apns-push-type": "alert",
                "apns-priority": "10",
                "apns-expiration": str(NOW + 600),
                "apns-collapse-id": COLLAPSE,
                "content-type": "application/json",
            },
        )
        payload = json.loads(request.body)
        self.assertEqual(set(payload), {"aps", "h"})
        self.assertEqual(
            payload["aps"], {"alert": {"title": "myCarlos", "body": NOTICE.body}}
        )
        self.assertEqual(hint_from(payload["h"]), HINT.encode())

    def test_apns_serves_macos_too_and_uses_the_sandbox_host_only_when_configured(self):
        sandbox = nt.ApnsConfig("FAKETEAM01", "FAKEKEYID1", Path("/x.p8"), "ca.example.fake", True)
        transport = apns(200, config=sandbox)
        send(transport, PushPlatform.MACOS_APNS)
        self.assertTrue(
            transport.requests[0].url.startswith("https://api.sandbox.push.apple.com/3/device/")
        )

    def test_wns_toast_xml_is_well_formed_and_generic(self):
        transport = wns(200)
        self.assertIs(send(transport, PushPlatform.WINDOWS_WNS), ProviderResult.ACCEPTED)
        (request,) = transport.requests
        self.assertEqual(request.url, WNS_CHANNEL)
        self.assertEqual(
            dict(request.headers),
            {
                "Authorization": "Bearer fake-token",
                "Content-Type": "text/xml",
                "X-WNS-Type": "wns/toast",
                "X-WNS-TTL": "600",
                "X-WNS-Tag": COLLAPSE[:16],
                "X-WNS-Cache-Policy": "cache",
            },
        )
        toast = ElementTree.fromstring(request.body)  # noqa: S314 (our own generated XML)
        self.assertEqual(toast.tag, "toast")
        self.assertEqual(set(toast.attrib), {"launch"})
        self.assertTrue(toast.attrib["launch"].startswith("h="))
        self.assertEqual(hint_from(toast.attrib["launch"][2:]), HINT.encode())
        texts = [node.text for node in toast.iter("text")]
        self.assertEqual(texts, ["myCarlos", NOTICE.body])
        self.assertEqual(len(list(toast.iter())), 5)  # toast, visual, binding, two texts


class NoPhiAndNoDocumentContent(unittest.TestCase):
    """Whatever the notice or hint, a message holds only fixed words and the opaque hint."""

    def requests(self):
        pairs = (
            (fcm(200), PushPlatform.ANDROID_FCM),
            (apns(200), PushPlatform.IOS_APNS),
            (wns(200), PushPlatform.WINDOWS_WNS),
        )
        for transport, platform in pairs:
            send(transport, platform)
            yield transport.requests[0]

    def test_no_request_carries_the_portal_destination_id(self):
        for request in self.requests():
            blob = request.body.decode("utf-8") + " ".join(
                f"{k}={v}" for k, v in request.headers.items()
            ) + request.url
            for forbidden in (str(DESTINATION), DESTINATION.hex):
                self.assertNotIn(forbidden, blob)

    def test_the_hint_is_encoded_not_hidden_and_holds_exactly_the_five_v1_fields(self):
        """A provider can decode ``h``: subscription UUID, epoch UUID and the waiting count.

        Hiding those (a per-epoch hash and an offset) is the policy module's follow-up and must
        land before the adapters are wired. This pins what is exposed today so a change is seen.
        """
        decoded = []
        for request in self.requests():
            body = request.body.decode("utf-8")
            if request.body.startswith(b"<toast"):
                encoded = ElementTree.fromstring(request.body).attrib["launch"][2:]  # noqa: S314
            else:
                encoded = json.loads(body)["message"]["data"]["h"] if "message" in body[:12] else (
                    json.loads(body)["h"]
                )
            decoded.append(json.loads(hint_from(encoded)))
        self.assertEqual(len(decoded), 3)
        for fields in decoded:
            self.assertEqual(
                fields,
                {
                    "version": 1,
                    "kind": "documents_ready",
                    "subscription_id": str(SUBSCRIPTION_ID),
                    "epoch": str(EPOCH),
                    "sequence": 42,
                },
            )

    def test_the_only_words_in_a_message_are_the_fixed_generic_notice(self):
        for request in self.requests():
            text = request.body.decode("utf-8")
            # The recipient handle, the stable collapse identity and the opaque hint are the
            # variable parts; everything else must be fixed words.
            for variable in (FCM_TOKEN, COLLAPSE, _hint(HINT)):
                text = text.replace(variable, "")
            words = set(re.findall(r"[A-Za-z]{4,}", text))
            allowed = {
                "myCarlos", "document", "available", "message", "notification", "title", "body",
                "data", "android", "collapse", "priority", "HIGH", "alert", "toast", "visual",
                "binding", "template", "ToastGeneric", "text", "launch", "version", "encoding",
                "token",
            } | set(NOTICE.body.replace(".", "").split())
            self.assertLessEqual(words - allowed, set(), words - allowed)

    def test_the_hint_is_the_only_variable_data_and_is_opaque_bytes(self):
        other = ReadyHint(UUID(int=77), UUID(int=88), 9)
        for transport, platform in (
            (fcm(200), PushPlatform.ANDROID_FCM),
            (apns(200), PushPlatform.IOS_APNS),
            (wns(200), PushPlatform.WINDOWS_WNS),
        ):
            send(transport, platform)
            transport.send(
                destination_id=DESTINATION, platform=platform, notice=GenericNotice(other),
                ttl_seconds=600, collapse_key=COLLAPSE,
            )
            first, second = (r.body.decode() for r in transport.requests)
            self.assertNotEqual(first, second)
            self.assertEqual(first.replace(_hint(HINT), "H"), second.replace(_hint(other), "H"))

    def test_configs_never_print_their_secrets(self):
        for config in (FCM, APNS, WNS):
            self.assertNotIn("fake", repr(config).lower())
            self.assertNotIn("fake", str(config).lower())
        self.assertNotIn("fake-token", repr(fcm(200).requests))
        send(apns(200), PushPlatform.IOS_APNS)
        request = apns(200)
        send(request, PushPlatform.IOS_APNS)
        self.assertEqual(repr(request.requests[0]), "HttpRequest[REDACTED]")


class RetryClassification(unittest.TestCase):
    def transports(self, status):
        return (
            (fcm(status), PushPlatform.ANDROID_FCM),
            (apns(status), PushPlatform.IOS_APNS),
            (wns(status), PushPlatform.WINDOWS_WNS),
        )

    def test_success_statuses_are_accepted(self):
        for status in (200, 201, 202, 204):
            for transport, platform in self.transports(status):
                self.assertIs(send(transport, platform), ProviderResult.ACCEPTED)

    def test_429_and_5xx_raise_transport_failure_so_dispatch_retries(self):
        for status in (429, 500, 502, 503, 504, 599):
            for transport, platform in self.transports(status):
                with self.assertRaises(TransportFailure):
                    send(transport, platform)

    def test_a_timeout_or_lost_connection_is_a_retryable_failure_with_no_provider_text(self):
        for failure in (TimeoutError("host=secret.example"), ConnectionResetError("path /x")):
            for transport, platform in (
                (fcm(failure), PushPlatform.ANDROID_FCM),
                (apns(failure), PushPlatform.IOS_APNS),
                (wns(failure), PushPlatform.WINDOWS_WNS),
            ):
                with self.assertRaises(TransportFailure) as caught:
                    send(transport, platform)
                self.assertNotIn("secret", str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertTrue(caught.exception.__suppress_context__)

    def test_a_redirect_is_permanent_and_never_followed(self):
        for status in (301, 302, 307, 308):
            for transport, platform in self.transports(status):
                self.assertIs(send(transport, platform), ProviderResult.PERMANENT_FAILURE)
                self.assertEqual(len(transport.requests), 1)

    def test_other_4xx_are_permanent_and_never_retried(self):
        for status in (400, 401, 403, 405, 413, 422):
            for transport, platform in self.transports(status):
                self.assertIs(send(transport, platform), ProviderResult.PERMANENT_FAILURE)
                self.assertEqual(len(transport.requests), 1)

    def test_a_gone_destination_is_invalid_not_a_failure(self):
        self.assertIs(send(fcm(404), PushPlatform.ANDROID_FCM), ProviderResult.INVALID_DESTINATION)
        self.assertIs(send(apns(410), PushPlatform.IOS_APNS), ProviderResult.INVALID_DESTINATION)
        for status in (404, 410):
            self.assertIs(
                send(wns(status), PushPlatform.WINDOWS_WNS), ProviderResult.INVALID_DESTINATION
            )
        # FCM 410 and APNs 404 are not that provider's "gone" signal.
        self.assertIs(send(fcm(410), PushPlatform.ANDROID_FCM), ProviderResult.PERMANENT_FAILURE)
        self.assertIs(send(apns(404), PushPlatform.IOS_APNS), ProviderResult.PERMANENT_FAILURE)

    def test_dispatch_retries_a_5xx_and_revokes_on_a_gone_destination(self):
        subscription = Subscription(
            OWNER, SUBSCRIPTION_ID, EPOCH, DESTINATION, PushPlatform.ANDROID_FCM,
            remote_enabled=True, remote_consent_version=1,
            permission_observed_for_enrollment=True,
        )
        intent = OutboxIntent(OWNER, DESTINATION, PushPlatform.ANDROID_FCM, HINT, NOW + 600)
        lease = DispatchLease(intent, UUID(int=5), NOW + 60, 1)
        current = CurrentAvailability(subscription, True, True, HINT.sequence)
        retried = dispatch(lease, current, fcm(503), now=NOW, server_enabled=True)
        self.assertEqual(retried.status, "retry")
        self.assertEqual(retried.retry_at, NOW + 30)
        gone = dispatch(lease, current, fcm(404), now=NOW, server_enabled=True)
        self.assertTrue(gone.revoke_destination)
        accepted = dispatch(lease, current, fcm(200), now=NOW, server_enabled=True)
        self.assertEqual(accepted.status, "provider_accepted")
        permanent = dispatch(lease, current, fcm(403), now=NOW, server_enabled=True)
        self.assertEqual(permanent.status, "permanent_failure")
        self.assertIsNone(permanent.retry_at)


class DestinationAndInputGuards(unittest.TestCase):
    def test_unknown_or_malformed_handles_are_invalid_destinations_and_send_nothing(self):
        cases = (
            (fcm(200, handle="short"), PushPlatform.ANDROID_FCM),
            (apns(200, handle="not-hex"), PushPlatform.IOS_APNS),
            (wns(200, handle="http://db5.notify.windows.com/x"), PushPlatform.WINDOWS_WNS),
            (wns(200, handle="https://evil.example/x"), PushPlatform.WINDOWS_WNS),
            (
                wns(200, handle="https://db5.notify.windows.com.evil.example/x"),
                PushPlatform.WINDOWS_WNS,
            ),
            (wns(200, handle="https://user:pw@db5.notify.windows.com/x"), PushPlatform.WINDOWS_WNS),
            (wns(200, handle="https://db5.notify.windows.com:8443/x"), PushPlatform.WINDOWS_WNS),
        )
        for transport, platform in cases:
            self.assertIs(send(transport, platform), ProviderResult.INVALID_DESTINATION)
            self.assertEqual(transport.requests, [])
        idn = "https://db5.notify.windows.com\u2024evil.example/x"
        for transport, platform in (
            (wns(200, handle=idn), PushPlatform.WINDOWS_WNS),
            (wns(200, handle="https://xn--db5-notify.windows.com.evil.example/x"),
             PushPlatform.WINDOWS_WNS),
        ):
            self.assertIs(send(transport, platform), ProviderResult.INVALID_DESTINATION)
            self.assertEqual(transport.requests, [])
        unknown = sup.RecordingFcmTransport(FCM, sup.FixedHandles({}))
        self.assertIs(send(unknown, PushPlatform.ANDROID_FCM), ProviderResult.INVALID_DESTINATION)

    def test_a_wrong_platform_ttl_or_collapse_key_is_a_wiring_fault_not_a_provider_outage(self):
        with self.assertRaises(TypeError):
            send(fcm(200), PushPlatform.IOS_APNS)
        with self.assertRaises(ValueError):
            send(fcm(200), PushPlatform.ANDROID_FCM, ttl_seconds=0)
        for key in ("", "x" * 65, "caf\u00e9" * 4, "\u2603"):
            with self.assertRaises(ValueError):
                fcm(200).send(
                    destination_id=DESTINATION, platform=PushPlatform.ANDROID_FCM,
                    notice=NOTICE, ttl_seconds=60, collapse_key=key,
                )

    def test_config_validation_refuses_bad_values(self):
        with self.assertRaises(ValueError):
            nt.FcmConfig("Bad Project!", Path("/x"))
        with self.assertRaises(ValueError):
            nt.ApnsConfig("TEAM", "KEY", Path("/x"), "bad bundle")
        with self.assertRaises(ValueError):
            nt.WnsConfig("not-a-sid", "fake-client-secret")
        with self.assertRaises(ValueError):
            nt.WnsConfig("ms-app://S-1-15-2-1-2-3-4-5-6-7", "short")
        with self.assertRaises(ValueError):
            nt.FcmConfig("fake-project-id", "/not/a/path/object")

    def test_dispatch_reports_a_miswired_adapter_as_a_transport_error_not_a_retry(self):
        subscription = Subscription(
            OWNER, SUBSCRIPTION_ID, EPOCH, DESTINATION, PushPlatform.WINDOWS_WNS,
            remote_enabled=True, remote_consent_version=1,
            permission_observed_for_enrollment=True,
        )
        intent = OutboxIntent(OWNER, DESTINATION, PushPlatform.WINDOWS_WNS, HINT, NOW + 600)
        decision = dispatch(
            DispatchLease(intent, UUID(int=5), NOW + 60, 1),
            CurrentAvailability(subscription, True, True, HINT.sequence),
            fcm(200), now=NOW, server_enabled=True,
        )
        self.assertEqual(decision.status, "transport_error:TypeError")
        self.assertIsNone(decision.retry_at)


class NothingIsLoggedAndNothingIsWired(unittest.TestCase):
    def test_the_module_has_no_logging_print_or_environment_access(self):
        needles = (
            "import logging", "logging.", "print(", "getLogger", "os.environ", "getenv", "open(",
            "read_text", "read_bytes", "import socket", "import urllib.request", "import requests",
            "import httpx",
        )
        for needle in needles:
            self.assertNotIn(needle, SOURCE, needle)

    def test_sending_logs_nothing_at_any_level(self):
        logger = logging.getLogger()
        previous = logger.level
        logger.setLevel(logging.DEBUG)
        try:
            with self.assertNoLogs(level=logging.DEBUG):
                send(fcm(200), PushPlatform.ANDROID_FCM)
                send(apns(410), PushPlatform.IOS_APNS)
                send(wns(404), PushPlatform.WINDOWS_WNS)
                for transport, platform in (
                    (fcm(503), PushPlatform.ANDROID_FCM), (apns(429), PushPlatform.IOS_APNS),
                ):
                    with self.assertRaises(TransportFailure):
                        send(transport, platform)
        finally:
            logger.setLevel(previous)

    def test_the_destination_id_never_reaches_an_exception_message(self):
        for transport, platform in (
            (fcm(503), PushPlatform.ANDROID_FCM), (apns(500), PushPlatform.IOS_APNS),
            (wns(TimeoutError()), PushPlatform.WINDOWS_WNS),
        ):
            with self.assertRaises(TransportFailure) as caught:
                send(transport, platform)
            self.assertNotIn(str(DESTINATION), str(caught.exception))

    def test_nothing_in_the_application_imports_the_adapters_yet(self):
        package = Path(nt.__file__).parent
        for path in package.rglob("*.py"):
            if path.name == "notification_transports.py":
                continue
            self.assertNotIn("notification_transports", path.read_text(encoding="utf-8"), path.name)
        settings = (package / "config.py").read_text(encoding="utf-8")
        self.assertNotIn("fcm", settings.lower())
        self.assertNotIn("apns", settings.lower())


if __name__ == "__main__":
    unittest.main()
