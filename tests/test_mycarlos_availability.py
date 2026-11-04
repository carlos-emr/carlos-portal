# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2026 CARLOS Contributors. All Rights Reserved.

"""Synthetic contract/transaction/provider tests; no ORM, socket, token or provider SDK.

The transaction fake proves the required adapter contract, not PostgreSQL durability/race safety.
Production route/enrollment/worker integration remains separately reviewed schema work.
"""

import json
import unittest
from dataclasses import replace
from uuid import UUID

from carlos_patient_portal.mycarlos_availability import (
    HINT_TTL_SECONDS,
    MAX_ATTEMPTS,
    MAX_HINT_BYTES,
    MAX_SEQUENCE,
    AvailabilityError,
    CurrentAvailability,
    DispatchLease,
    GenericNotice,
    MailboxReady,
    NoticeKeys,
    Owner,
    ProviderResult,
    PushPlatform,
    ReadyHint,
    Subscription,
    TransportFailure,
    coalesce_pending,
    dispatch,
    notice_token,
    queue_new_copy,
    resolve_notice_token,
)

KEYS = NoticeKeys(b"k" * 32)
NOW = 1_800_000_000
OWNER = Owner(7, 11)
SUBSCRIPTION = Subscription(
    OWNER, UUID(int=1), UUID(int=2), UUID(int=3), PushPlatform.ANDROID_FCM,
    remote_enabled=True, remote_consent_version=1, permission_observed_for_enrollment=True,
)
EVENT = MailboxReady(OWNER, 17, NOW + 3600, inserted=True)


class Transaction:
    def __init__(self, subscriptions=(SUBSCRIPTION,)):
        self.active = True
        self.enrollments = subscriptions
        self.pending = {}
        self.committed = {}
        self.mailbox_pending = False
        self.mailbox_committed = False
        self.reads = 0

    def in_transaction(self):
        return self.active

    def subscriptions(self, owner):
        self.reads += 1
        assert owner == OWNER
        return self.enrollments

    def put(self, intent):
        assert self.active
        key = intent.hint.subscription_id, intent.hint.epoch
        existing = self.pending.get(key) or self.committed.get(key)
        if existing is not None and intent.hint.sequence <= existing.hint.sequence:
            return False
        self.pending[key] = (
            coalesce_pending(existing, intent, now=NOW) if existing is not None else intent
        )
        return True

    def commit(self):
        self.committed.update(self.pending)
        self.pending.clear()
        self.mailbox_committed = self.mailbox_pending
        self.active = False

    def rollback(self):
        self.pending.clear()
        self.mailbox_pending = False
        self.active = False


class Provider:
    def __init__(self, result=ProviderResult.ACCEPTED):
        self.result = result
        self.calls = []

    def send(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def intent():
    transaction = Transaction()
    queue_new_copy(transaction, EVENT, now=NOW, server_enabled=True)
    return next(iter(transaction.pending.values()))


def lease(job=None, *, attempt=1):
    return DispatchLease(job or intent(), UUID(int=99), NOW + 120, attempt)


def current(subscription=SUBSCRIPTION, **kwargs):
    return CurrentAvailability(
        subscription, kwargs.get("account_active", True), kwargs.get("device_active", True),
        kwargs.get("latest_waiting_sequence", EVENT.sequence),
    )


class HintContractTests(unittest.TestCase):
    def test_exact_native_hint_shape_maximum_sequence_and_no_content(self):
        hint = ReadyHint(UUID(int=1), UUID(int=2), MAX_SEQUENCE)
        encoded = hint.encode()
        self.assertLessEqual(len(encoded), MAX_HINT_BYTES)
        self.assertEqual(ReadyHint.decode(encoded), hint)
        self.assertEqual(json.loads(encoded), {
            "version": 1, "kind": "documents_ready",
            "subscription_id": str(UUID(int=1)), "epoch": str(UUID(int=2)),
            "sequence": MAX_SEQUENCE,
        })

    def test_unknown_fields_phi_links_commands_and_provider_tokens_refused(self):
        value = json.loads(ReadyHint(UUID(int=1), UUID(int=2), 1).encode())
        for key in ["patient", "clinic", "document_id", "url", "command", "token", "body"]:
            with self.subTest(key=key), self.assertRaisesRegex(AvailabilityError, "^invalid_hint$"):
                ReadyHint.decode(json.dumps({**value, key: "SYNTHETIC-DO-NOT-LOG"}).encode())

    def test_duplicate_keys_bad_types_limits_and_invalid_uuid(self):
        baseline = ReadyHint(UUID(int=1), UUID(int=2), 1).encode()
        variants = [
            b"", b"[]", b"null", b"\xff", b" " * (MAX_HINT_BYTES + 1),
            baseline.replace(b'"version":1', b'"version":1,"version":1'),
        ]
        value = json.loads(baseline)
        for key, bad in [
            ("version", True), ("version", 2), ("kind", "download"),
            ("subscription_id", None), ("subscription_id", str(UUID(int=0))),
            ("epoch", "not-a-uuid"), ("sequence", True), ("sequence", 0),
            ("sequence", -1), ("sequence", 1.0), ("sequence", "1"),
            ("sequence", MAX_SEQUENCE + 1),
        ]:
            variants.append(json.dumps({**value, key: bad}).encode())
        for raw in variants:
            with self.subTest(raw=raw), self.assertRaisesRegex(AvailabilityError, "^invalid_hint$"):
                ReadyHint.decode(raw)

    def test_refusals_and_reprs_do_not_echo_inputs(self):
        with self.assertRaises(AvailabilityError) as failure:
            ReadyHint.decode(b'{"token":"SYNTHETIC-DO-NOT-LOG"}')
        self.assertNotIn("SYNTHETIC", str(failure.exception))
        self.assertNotIn("account_id", repr(OWNER))
        self.assertNotIn("device_id", repr(OWNER))
        self.assertNotIn(str(SUBSCRIPTION.destination_id), repr(SUBSCRIPTION))


class TransactionContractTests(unittest.TestCase):
    def test_default_off_does_not_read_or_write_storage(self):
        transaction = Transaction()
        self.assertEqual(queue_new_copy(transaction, EVENT, now=NOW), 0)
        self.assertEqual(transaction.reads, 0)
        self.assertFalse(transaction.pending)

    def test_new_remote_consent_and_permission_required_no_local_flag_migration(self):
        for subscription in [
            replace(SUBSCRIPTION, remote_enabled=False),
            replace(SUBSCRIPTION, remote_consent_version=0),
            replace(SUBSCRIPTION, remote_consent_version=2),
            replace(SUBSCRIPTION, permission_observed_for_enrollment=False),
            replace(SUBSCRIPTION, revoked=True),
        ]:
            transaction = Transaction((subscription,))
            self.assertEqual(queue_new_copy(transaction, EVENT, now=NOW, server_enabled=True), 0)
        default = Subscription(OWNER, UUID(int=1), UUID(int=2), UUID(int=3), PushPlatform.IOS_APNS)
        self.assertFalse(default.permits_remote())
        with self.assertRaises(TypeError):
            replace(default, local_arrival_enabled=True)

    def test_atomic_new_copy_rollback_then_commit_and_dispatch_only_after_commit(self):
        transaction = Transaction()
        transaction.mailbox_pending = True
        self.assertEqual(queue_new_copy(transaction, EVENT, now=NOW, server_enabled=True), 1)
        self.assertFalse(transaction.committed)
        transaction.rollback()
        self.assertFalse(transaction.mailbox_committed)
        self.assertFalse(transaction.pending or transaction.committed)
        transaction = Transaction()
        transaction.mailbox_pending = True
        queue_new_copy(transaction, EVENT, now=NOW, server_enabled=True)
        transaction.commit()
        self.assertTrue(transaction.mailbox_committed)
        self.assertEqual(len(transaction.committed), 1)
        provider = Provider()
        job = next(iter(transaction.committed.values()))
        self.assertEqual(dispatch(lease(job), current(), provider, now=NOW,

                                      server_enabled=True, notice_keys=KEYS).status,
                             "provider_accepted")
        self.assertEqual(len(provider.calls), 1)

    def test_upload_200_retry_and_same_sequence_never_duplicate(self):
        transaction = Transaction()
        self.assertEqual(queue_new_copy(transaction, replace(EVENT, inserted=False), now=NOW,
                                       server_enabled=True), 0)
        self.assertEqual(transaction.reads, 0)
        self.assertEqual(queue_new_copy(transaction, EVENT, now=NOW, server_enabled=True), 1)
        self.assertEqual(queue_new_copy(transaction, EVENT, now=NOW, server_enabled=True), 0)
        self.assertEqual(len(transaction.pending), 1)

    def test_no_queue_outside_transaction_or_expired_copy(self):
        transaction = Transaction()
        transaction.active = False
        with self.assertRaisesRegex(AvailabilityError, "^transaction_required$"):
            queue_new_copy(transaction, EVENT, now=NOW, server_enabled=True)
        self.assertEqual(queue_new_copy(transaction, replace(EVENT, expires_at=NOW), now=NOW,
                                       server_enabled=True), 0)

    def test_queue_ttl_destination_capacity_and_wrong_owner_fail_closed(self):
        job = intent()
        self.assertEqual(job.expires_at, NOW + HINT_TTL_SECONDS)
        transaction = Transaction()
        queue_new_copy(transaction, replace(EVENT, expires_at=NOW + 5), now=NOW,
                       server_enabled=True)
        self.assertEqual(next(iter(transaction.pending.values())).expires_at, NOW + 5)
        for subscriptions in [
            (replace(SUBSCRIPTION, owner=Owner(8, 11)),),
            (SUBSCRIPTION, SUBSCRIPTION), (SUBSCRIPTION,) * 17,
        ]:
            with self.assertRaises(AvailabilityError):
                queue_new_copy(Transaction(subscriptions), EVENT, now=NOW, server_enabled=True)

    def test_newer_sequences_coalesce_without_extending_pending_ttl(self):
        transaction = Transaction()
        queue_new_copy(transaction, EVENT, now=NOW, server_enabled=True)
        queue_new_copy(transaction, replace(EVENT, sequence=18), now=NOW + 20,
                       server_enabled=True)
        self.assertEqual(len(transaction.pending), 1)
        job = next(iter(transaction.pending.values()))
        self.assertEqual(job.hint.sequence, 18)
        self.assertEqual(job.expires_at, NOW + HINT_TTL_SECONDS)
        self.assertEqual(queue_new_copy(transaction, EVENT, now=NOW + 21, server_enabled=True), 0)
        with self.assertRaisesRegex(AvailabilityError, "^coalescing_binding_mismatch$"):
            coalesce_pending(job, replace(job, destination_id=UUID(int=82)), now=NOW)

    def test_expired_newer_intent_never_replaces_or_shortens_a_live_slot(self):
        live = intent()
        dead = replace(live, hint=replace(live.hint, sequence=18), expires_at=NOW)
        self.assertIs(coalesce_pending(live, dead, now=NOW), live)
        self.assertIs(coalesce_pending(replace(live, expires_at=NOW), dead, now=NOW).hint,
                      live.hint)
        fresh = replace(live, hint=replace(live.hint, sequence=18), expires_at=NOW + 5)
        self.assertEqual(coalesce_pending(live, fresh, now=NOW).expires_at, NOW + 5)


class DispatchContractTests(unittest.TestCase):
    def test_default_off_and_revocation_owner_rotation_or_no_waiting_content_suppress(self):
        provider = Provider()
        self.assertEqual(dispatch(lease(), current(), provider, now=NOW).status, "suppressed")
        snapshots = [
            current(None), current(account_active=False), current(device_active=False),
            current(latest_waiting_sequence=EVENT.sequence - 1),
            current(replace(SUBSCRIPTION, remote_enabled=False)),
            current(replace(SUBSCRIPTION, revoked=True)),
            current(replace(SUBSCRIPTION, remote_consent_version=0)),
            current(replace(SUBSCRIPTION, permission_observed_for_enrollment=False)),
            current(replace(SUBSCRIPTION, owner=Owner(8, 11))),
            current(replace(SUBSCRIPTION, subscription_id=UUID(int=40))),
            current(replace(SUBSCRIPTION, epoch=UUID(int=40))),
            current(replace(SUBSCRIPTION, destination_id=UUID(int=40))),
            current(replace(SUBSCRIPTION, platform=PushPlatform.WINDOWS_WNS)),
        ]
        for snapshot in snapshots:
            self.assertEqual(dispatch(lease(), snapshot, provider, now=NOW,
                                      server_enabled=True, notice_keys=KEYS).status, "suppressed")
        self.assertFalse(provider.calls)

    def test_no_send_after_expiry_lease_loss_or_attempt_limit(self):
        provider = Provider()
        for claim, expected in [
            (replace(lease(), lease_until=NOW), "lease_lost"),
            (replace(lease(), lease_until=NOW + 121), "invalid_lease_window"),
            (lease(replace(intent(), expires_at=NOW)), "expired"),
            (lease(replace(intent(), expires_at=NOW + 901)), "invalid_ttl"),
            (lease(attempt=MAX_ATTEMPTS + 1), "attempts_exhausted"),
        ]:
            self.assertEqual(dispatch(claim, current(), provider, now=NOW,
                                      server_enabled=True, notice_keys=KEYS).status, expected)
        self.assertFalse(provider.calls)

    def test_all_supported_platforms_receive_only_opaque_hint_and_fixed_notice(self):
        for platform in PushPlatform:
            subscription = replace(SUBSCRIPTION, platform=platform)
            job = replace(intent(), platform=platform)
            provider = Provider()
            decision = dispatch(lease(job), current(subscription), provider, now=NOW,
                                server_enabled=True, notice_keys=KEYS)
            self.assertEqual(decision.status, "provider_accepted")
            self.assertEqual(set(provider.calls[0]), {
                "destination_id", "platform", "notice", "ttl_seconds", "collapse_key"
            })
            notice = provider.calls[0]["notice"]
            self.assertEqual(notice.title, "myCarlos")
            self.assertEqual(notice.body, "A new document is available in myCarlos.")
            self.assertEqual(notice.token, notice_token(KEYS, job.hint))
            self.assertEqual(provider.calls[0]["ttl_seconds"], HINT_TTL_SECONDS)

    def test_transient_exception_retry_bounded_without_echoing_provider_data(self):
        for result in [ProviderResult.TRANSIENT_FAILURE, TransportFailure("SYNTHETIC-TOKEN")]:
            provider = Provider(result)
            decision = dispatch(lease(), current(), provider, now=NOW,
                server_enabled=True, notice_keys=KEYS)
            self.assertEqual((decision.status, decision.retry_at), ("retry", NOW + 30))
            self.assertNotIn("SYNTHETIC", repr(decision))
        self.assertEqual(dispatch(lease(attempt=MAX_ATTEMPTS), current(), provider, now=NOW,

                                      server_enabled=True, notice_keys=KEYS).status,
                             "attempts_exhausted")
        short = replace(intent(), expires_at=NOW + 30)
        self.assertEqual(dispatch(lease(short), current(), provider, now=NOW,
                                  server_enabled=True, notice_keys=KEYS).status, "expired")

    def test_mis_wired_transport_is_a_fault_not_an_outage(self):
        for failure in [TypeError("SYNTHETIC-TOKEN"), AttributeError("SYNTHETIC-TOKEN"),
                        RuntimeError("SYNTHETIC-TOKEN")]:
            provider = Provider(failure)
            decision = dispatch(lease(), current(), provider, now=NOW,
                server_enabled=True, notice_keys=KEYS)
            self.assertEqual(decision.status, "transport_error:" + type(failure).__name__)
            self.assertIsNone(decision.retry_at)
            self.assertFalse(decision.revoke_destination)
            self.assertNotIn("SYNTHETIC", repr(decision))
            self.assertEqual(len(provider.calls), 1)

        class SyntheticProviderSdkError(Exception):
            pass

        decision = dispatch(lease(), current(), Provider(SyntheticProviderSdkError("x")), now=NOW,
                            server_enabled=True, notice_keys=KEYS)
        self.assertEqual(decision.status, "transport_error:SyntheticProviderSdkError")
        self.assertLessEqual(len(decision.status), 96)

    def test_invalid_destination_and_permanent_failure_do_not_retry(self):
        for result, status, revoke in [
            (ProviderResult.INVALID_DESTINATION, "invalid_destination", True),
            (ProviderResult.PERMANENT_FAILURE, "permanent_failure", False),
        ]:
            decision = dispatch(lease(), current(), Provider(result), now=NOW,
                server_enabled=True, notice_keys=KEYS)
            self.assertEqual((decision.status, decision.revoke_destination), (status, revoke))
            self.assertIsNone(decision.retry_at)
        with self.assertRaisesRegex(AvailabilityError, "^invalid_provider_result$"):
            dispatch(lease(), current(), Provider("accepted"), now=NOW,
                server_enabled=True, notice_keys=KEYS)

    def test_retry_and_new_sequence_share_bounded_epoch_scoped_collapse_identity(self):
        job = intent()
        newer = replace(job, hint=replace(job.hint, sequence=18))
        rotated = replace(job, hint=replace(job.hint, epoch=UUID(int=70)))
        self.assertEqual(job.collapse_key, newer.collapse_key)
        self.assertNotEqual(job.idempotency_key, newer.idempotency_key)
        self.assertNotEqual(job.collapse_key, rotated.collapse_key)
        self.assertEqual(len(job.collapse_key.encode("ascii")), 64)


class OpaqueNoticeTokenTests(unittest.TestCase):
    """D23: a provider learns nothing from the notice beyond "something is waiting"."""

    hint = ReadyHint(UUID(int=1), UUID(int=2), 42)

    def test_the_token_is_22_url_safe_characters_and_deterministic(self):
        token = notice_token(KEYS, self.hint)
        self.assertEqual(len(token), 22)
        self.assertRegex(token, r"^[A-Za-z0-9_-]{22}$")
        self.assertEqual(notice_token(KEYS, self.hint), token)

    def test_it_carries_no_field_and_depends_on_every_field_and_the_key(self):
        token = notice_token(KEYS, self.hint)
        for needle in ("0000", "42", "documents_ready", str(self.hint.subscription_id)):
            self.assertNotIn(needle, token)
        other_key = NoticeKeys(b"j" * 32)
        variants = {
            notice_token(other_key, self.hint),
            notice_token(KEYS, replace(self.hint, sequence=43)),
            notice_token(KEYS, replace(self.hint, epoch=UUID(int=3))),
            notice_token(KEYS, replace(self.hint, subscription_id=UUID(int=9))),
        }
        self.assertNotIn(token, variants)
        self.assertEqual(len(variants), 4)

    def test_the_portal_resolves_its_own_recent_tokens_only(self):
        sub, epoch = self.hint.subscription_id, self.hint.epoch
        token = notice_token(KEYS, self.hint)
        self.assertEqual(resolve_notice_token(KEYS, token, sub, epoch, 42), 42)
        self.assertEqual(resolve_notice_token(KEYS, token, sub, epoch, 50), 42)
        self.assertIsNone(resolve_notice_token(KEYS, token, sub, epoch, 41))   # not sent yet
        self.assertIsNone(resolve_notice_token(KEYS, token, sub, epoch, 42 + 65))  # too old
        self.assertIsNone(resolve_notice_token(KEYS, token, UUID(int=9), epoch, 42))
        self.assertIsNone(resolve_notice_token(KEYS, token, sub, UUID(int=3), 42))
        self.assertIsNone(resolve_notice_token(NoticeKeys(b"j" * 32), token, sub, epoch, 42))
        for bad in (None, 7, "", "short", token + "A", b"x" * 22):
            self.assertIsNone(resolve_notice_token(KEYS, bad, sub, epoch, 42))

    def test_key_rotation_keeps_in_flight_tokens_resolvable(self):
        old = NoticeKeys(b"o" * 32)
        in_flight = notice_token(old, self.hint)
        rotated = NoticeKeys(b"n" * 32, previous=(b"o" * 32,))
        sub, epoch = self.hint.subscription_id, self.hint.epoch
        self.assertEqual(resolve_notice_token(rotated, in_flight, sub, epoch, 42), 42)
        self.assertNotEqual(notice_token(rotated, self.hint), in_flight)
        self.assertIsNone(resolve_notice_token(NoticeKeys(b"n" * 32), in_flight, sub, epoch, 42))

    def test_keys_are_validated_and_never_printed(self):
        for bad in (b"short", "not-bytes", None):
            with self.assertRaises(AvailabilityError):
                NoticeKeys(bad)
        with self.assertRaises(AvailabilityError):
            NoticeKeys(b"k" * 32, previous=(b"k" * 32,))
        with self.assertRaises(AvailabilityError):
            NoticeKeys(b"k" * 32, previous=(b"a" * 32, b"b" * 32, b"c" * 32, b"d" * 32))
        self.assertEqual(repr(KEYS), "NoticeKeys[REDACTED]")
        self.assertNotIn("kkkk", str(KEYS))

    def test_no_key_means_no_send_and_the_notice_holds_only_a_token(self):
        provider = Provider()
        decision = dispatch(lease(), current(), provider, now=NOW, server_enabled=True)
        self.assertEqual(decision.status, "no_notice_key")
        self.assertFalse(provider.calls)
        for bad in ("", "x" * 21, "x" * 23, "\u00e9" * 22):
            with self.assertRaises(AvailabilityError):
                GenericNotice(bad)
        self.assertFalse(hasattr(GenericNotice(notice_token(KEYS, self.hint)), "hint"))


if __name__ == "__main__":
    unittest.main()
