"""Observe limiter budgets across time and capacity changes without inspecting its buckets."""

from carlos_patient_portal.runtime import InMemoryRateLimiter


def test_retry_after_rounds_up_and_requests_do_not_extend_the_fixed_window():
    limiter = InMemoryRateLimiter(window_seconds=10, max_requests=2)

    assert limiter.consume("FAKE client", now=100.25) is None
    assert limiter.consume("FAKE client", now=100.5) is None
    assert limiter.consume("FAKE client", now=100.75) == 10
    assert limiter.consume("FAKE client", now=109.249) == 2
    assert limiter.consume("FAKE client", now=109.251) == 1
    assert limiter.consume("FAKE client", now=110.25) is None
    # The renewed window gets its full budget, rather than retaining the old count.
    assert limiter.consume("FAKE client", now=110.5) is None
    assert limiter.consume("FAKE client", now=110.75) == 10


def test_each_client_renews_its_budget_at_its_own_window_boundary():
    limiter = InMemoryRateLimiter(window_seconds=10, max_requests=1)

    assert limiter.consume("FAKE first", now=100) is None
    assert limiter.consume("FAKE second", now=105) is None
    assert limiter.consume("FAKE first", now=105) == 5
    assert limiter.consume("FAKE second", now=105.5) == 10
    assert limiter.consume("FAKE first", now=110) is None
    assert limiter.consume("FAKE second", now=110) == 5
    assert limiter.consume("FAKE second", now=115) is None
    assert limiter.consume("FAKE first", now=115) == 5


def test_capacity_eviction_keeps_a_recent_clients_existing_budget():
    limiter = InMemoryRateLimiter(window_seconds=10, max_requests=1, max_buckets=2)

    assert limiter.consume("FAKE active", now=100) is None
    assert limiter.consume("FAKE idle", now=101) is None
    assert limiter.consume("FAKE active", now=102) == 8
    assert limiter.consume("FAKE newcomer", now=103) is None
    # Capacity pressure must not reset the recently used client's spent budget.
    assert limiter.consume("FAKE active", now=104) == 6
    # The idle client was evicted and starts a new budget on its next request.
    assert limiter.consume("FAKE idle", now=104) is None
