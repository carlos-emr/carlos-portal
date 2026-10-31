from carlos_patient_portal.runtime import InMemoryRateLimiter


def test_expired_recent_bucket_does_not_displace_a_live_clients_spent_budget() -> None:
    limiter = InMemoryRateLimiter(window_seconds=10, max_requests=1, max_buckets=3)
    assert limiter.consume("FAKE oldest window", now=100) is None
    assert limiter.consume("FAKE live client", now=101) is None
    assert limiter.consume("FAKE third client", now=102) is None
    # A denied retry makes the oldest window most recently used without extending it.
    assert limiter.consume("FAKE oldest window", now=109) == 1
    assert limiter.consume("FAKE live client", now=109.1) == 2
    assert limiter.consume("FAKE oldest window", now=109.2) == 1

    # A's window has expired, while the other two clients still have spent live budgets.
    assert limiter.consume("FAKE newcomer", now=110.1) is None

    assert limiter.consume("FAKE third client", now=110.2) == 2
    assert limiter.consume("FAKE live client", now=110.3) == 1
    assert limiter.consume("FAKE live client", now=111) is None
    assert limiter.consume("FAKE second newcomer", now=112.1) is None
    assert limiter.consume("FAKE newcomer", now=112.2) == 8
    assert limiter.consume("FAKE live client", now=112.3) == 9
