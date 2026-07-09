from unittest.mock import patch

import app.auth_lockout as auth_lockout
from app.auth_lockout import (
    BASE_BACKOFF_SECONDS,
    MAX_ATTEMPTS,
    MAX_BACKOFF_SECONDS,
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
    fix, `_failures` must not grow forever — but eviction is now time-based (an
    entry is only dropped once it's been idle longer than MAX_BACKOFF_SECONDS), so
    entries created during a short, active burst legitimately stick around until
    that idle window elapses. This test drives a burst of 300 distinct attempts,
    confirms they all still accumulate while activity is ongoing (no premature
    unconditional sweep like the old buggy logic), then simulates the attacker
    going idle for longer than MAX_BACKOFF_SECONDS and confirms the next failure
    triggers a sweep that reclaims the stale entries."""
    reset_all()
    fake_time = [1000.0]
    monkeypatch.setattr(auth_lockout, "_now", lambda: fake_time[0])

    for i in range(300):
        record_failure((f"attacker-user-{i}", "6.6.6.6"))
        fake_time[0] += 1  # only ~300s of elapsed time — nowhere near the idle window

    # None of these are stale yet (burst took far less than MAX_BACKOFF_SECONDS),
    # so they should still all be present — proving eviction is no longer an
    # unconditional per-call sweep.
    assert len(auth_lockout._failures) == 300

    # Now the attacker goes idle for longer than the staleness window. The next
    # failure (from anyone) should trigger a sweep that reclaims all the old,
    # long-untouched entries, keeping memory bounded over time.
    fake_time[0] += MAX_BACKOFF_SECONDS + 1
    record_failure(("attacker-user-new", "6.6.6.6"))
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


def test_interleaved_decoy_failures_do_not_reset_target_lockout_count(monkeypatch):
    """Regression test for the eviction-bypass exploit (the actual bug this fix
    addresses): an attacker brute-forcing a target account interleaves one cheap
    "decoy" failed login against a throwaway username between each real guess
    against the target, from the same source IP.

    Under the old (buggy) eviction predicate —
    `now >= entry["locked_until"] and entry["count"] < MAX_ATTEMPTS` — every
    sub-threshold entry has `locked_until == 0.0` and `now` (monotonic clock) is
    always >= 0.0, so that condition was trivially true for the target's entry on
    every single decoy call. Each decoy failure therefore wiped the target's
    accumulating count back to zero before it could ever reach MAX_ATTEMPTS, so
    the target account never locked no matter how many real guesses were made.

    With the fix, eviction is keyed off genuine idle time (`last_seen`), and the
    target's entry is touched (its own `last_seen` refreshed) on every real guess
    — only ~1 mocked second apart, far short of MAX_BACKOFF_SECONDS — so it
    survives the decoys' sweeps and the lockout triggers as expected.
    """
    reset_all()
    fake_time = [1000.0]
    monkeypatch.setattr(auth_lockout, "_now", lambda: fake_time[0])

    target = ("admin", "10.0.0.1")
    for i in range(MAX_ATTEMPTS):
        record_failure(target)                       # real guess against the target
        record_failure((f"decoy-{i}", "10.0.0.1"))    # cheap decoy failure, same IP
        fake_time[0] += 1

    assert is_locked(target) > 0.0
