from unittest.mock import patch

import app.auth_lockout as auth_lockout
from app.auth_lockout import (
    BASE_BACKOFF_SECONDS,
    MAX_ATTEMPTS,
    is_locked,
    record_failure,
    record_success,
    reset_all,
)


def test_no_lockout_before_threshold():
    reset_all()
    key = ("user-a", "1.1.1.1")
    for _ in range(MAX_ATTEMPTS - 1):
        record_failure(key)
    assert is_locked(key) == 0.0


def test_lockout_triggers_at_threshold():
    reset_all()
    key = ("user-b", "1.1.1.1")
    for _ in range(MAX_ATTEMPTS):
        record_failure(key)
    assert is_locked(key) > 0.0


def test_lockout_backoff_doubles_on_repeated_failures():
    reset_all()
    key = ("user-c", "1.1.1.1")
    with patch("app.auth_lockout._now", return_value=1000.0):
        for _ in range(MAX_ATTEMPTS):
            record_failure(key)
        first_remaining = is_locked(key)
        record_failure(key)  # one more failure while still "locked" conceptually
        second_remaining = is_locked(key)
    assert second_remaining > first_remaining


def test_lockout_caps_at_max_backoff():
    reset_all()
    key = ("user-d", "1.1.1.1")
    with patch("app.auth_lockout._now", return_value=1000.0):
        for _ in range(MAX_ATTEMPTS + 10):
            record_failure(key)
        remaining = is_locked(key)
    assert remaining <= 900.0


def test_lockout_decays_after_backoff_window():
    reset_all()
    key = ("user-e", "1.1.1.1")
    with patch("app.auth_lockout._now", return_value=1000.0):
        for _ in range(MAX_ATTEMPTS):
            record_failure(key)
        assert is_locked(key) > 0.0
    with patch("app.auth_lockout._now", return_value=1000.0 + BASE_BACKOFF_SECONDS + 1):
        assert is_locked(key) == 0.0


def test_record_success_clears_failure_count():
    reset_all()
    key = ("user-f", "1.1.1.1")
    for _ in range(MAX_ATTEMPTS - 1):
        record_failure(key)
    record_success(key)
    record_failure(key)  # single failure after reset should not lock
    assert is_locked(key) == 0.0


def test_different_keys_are_independent():
    reset_all()
    key_a = ("user-g", "1.1.1.1")
    key_b = ("user-g", "2.2.2.2")
    for _ in range(MAX_ATTEMPTS):
        record_failure(key_a)
    assert is_locked(key_a) > 0.0
    assert is_locked(key_b) == 0.0


def test_stale_subthreshold_entries_are_evicted_and_do_not_grow_unbounded(monkeypatch):
    """Regression test for a slow-burn memory-exhaustion vector: an attacker varying
    the username from one IP (or hitting many usernames) previously inserted a
    permanent dict entry per distinct failed attempt, with no eviction. After the
    fix, `_failures` must not grow to O(number of distinct attempts)."""
    reset_all()
    fake_time = [1000.0]
    monkeypatch.setattr(auth_lockout, "_now", lambda: fake_time[0])

    for i in range(300):
        record_failure((f"attacker-user-{i}", "6.6.6.6"))
        fake_time[0] += 1  # time keeps advancing past each sub-threshold entry

    # Each of these 300 attempts is a distinct key that never reached MAX_ATTEMPTS
    # on its own, so eviction should have kept the dict from growing unbounded —
    # nowhere near 300 entries should remain.
    assert len(auth_lockout._failures) < 10


def test_eviction_does_not_disturb_an_in_progress_lockout(monkeypatch):
    """A key that's actively serving (or building toward) a lockout must survive
    eviction sweeps triggered by unrelated keys failing in the meantime."""
    reset_all()
    fake_time = [1000.0]
    monkeypatch.setattr(auth_lockout, "_now", lambda: fake_time[0])

    victim_key = ("victim-user", "9.9.9.9")
    for _ in range(MAX_ATTEMPTS):
        record_failure(victim_key)
    assert is_locked(victim_key) > 0.0

    # Flood with many distinct noise keys — none of these should evict the
    # actively-locked victim entry.
    for i in range(50):
        record_failure((f"noise-user-{i}", "9.9.9.9"))
        fake_time[0] += 1

    assert is_locked(victim_key) > 0.0


def test_eviction_preserves_in_progress_count_for_the_key_being_recorded():
    """The key currently being processed by record_failure must never be evicted
    by its own sweep, even mid-count before it reaches the threshold."""
    reset_all()
    key = ("slow-user", "4.4.4.4")
    for _ in range(MAX_ATTEMPTS - 1):
        record_failure(key)
    # One more failure should still cross the threshold — proving the count
    # wasn't reset to 0 by the eviction sweep on any of the prior calls.
    record_failure(key)
    assert is_locked(key) > 0.0
