from unittest.mock import patch

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
