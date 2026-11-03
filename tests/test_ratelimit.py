"""RateLimiter unit tests + dispatcher integration."""

from datetime import UTC, datetime, timedelta

from ai_defense.toolset.ratelimit import InMemoryRateBackend, RateLimiter

NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)


# --- unit: per-host hourly cap ------------------------------------------

def test_per_host_cap_blocks_after_limit():
    rl = RateLimiter(per_host_changes_per_hour=2)
    r1, _ = rl.try_begin(["h1"], NOW)
    rl.end(r1)
    r2, _ = rl.try_begin(["h1"], NOW)
    rl.end(r2)
    r3, reason = rl.try_begin(["h1"], NOW)
    assert r3 is None
    assert "change rate cap" in reason or "change rate" in reason


def test_per_host_cap_is_per_host():
    rl = RateLimiter(per_host_changes_per_hour=1)
    r1, _ = rl.try_begin(["h1"], NOW)
    rl.end(r1)
    # different host is unaffected
    r2, reason = rl.try_begin(["h2"], NOW)
    assert r2 is not None and reason is None


def test_per_host_window_rolls_off():
    rl = RateLimiter(per_host_changes_per_hour=1, window=timedelta(hours=1))
    r1, _ = rl.try_begin(["h1"], NOW)
    rl.end(r1)
    # still within the window -> blocked
    assert rl.try_begin(["h1"], NOW + timedelta(minutes=30))[0] is None
    # past the window -> allowed again
    ok, reason = rl.try_begin(["h1"], NOW + timedelta(hours=1, minutes=1))
    assert ok is not None and reason is None


def test_multi_target_blocked_if_any_host_over():
    rl = RateLimiter(per_host_changes_per_hour=1)
    r1, _ = rl.try_begin(["h1"], NOW)
    rl.end(r1)
    # h1 already at cap -> a batch touching h1 and h2 is refused
    r, reason = rl.try_begin(["h1", "h2"], NOW)
    assert r is None and "h1" in reason


# --- unit: fleet concurrency --------------------------------------------

def test_fleet_concurrency_cap():
    rl = RateLimiter(fleet_concurrency=2)
    a, _ = rl.try_begin(["h1"], NOW)
    b, _ = rl.try_begin(["h2"], NOW)
    assert a and b
    c, reason = rl.try_begin(["h3"], NOW)         # 3rd in-flight -> blocked
    assert c is None and "concurrency" in reason
    rl.end(a)                                     # free a slot
    d, reason = rl.try_begin(["h3"], NOW)
    assert d is not None and reason is None


def test_shared_backend_sees_others_in_flight():
    backend = InMemoryRateBackend()
    rl1 = RateLimiter(backend, fleet_concurrency=1)
    rl2 = RateLimiter(backend, fleet_concurrency=1)
    a, _ = rl1.try_begin(["h1"], NOW)
    assert a is not None
    b, reason = rl2.try_begin(["h2"], NOW)        # other limiter, same backend
    assert b is None and "concurrency" in reason


def test_no_limits_configured_is_unbounded():
    rl = RateLimiter()
    for _ in range(100):
        r, reason = rl.try_begin(["h1"], NOW)
        assert r is not None and reason is None
