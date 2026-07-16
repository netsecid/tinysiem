from unittest.mock import patch

import app.ai.rate_limit as rate_limit
from app.ai.rate_limit import check_and_record, reset_all


def test_allows_calls_under_limit():
    reset_all()
    for _ in range(5):
        assert check_and_record("user-a", limit=10) is True


def test_blocks_calls_over_limit():
    reset_all()
    for _ in range(3):
        assert check_and_record("user-b", limit=3) is True
    assert check_and_record("user-b", limit=3) is False


def test_different_users_have_independent_limits():
    reset_all()
    for _ in range(3):
        assert check_and_record("user-c", limit=3) is True
    assert check_and_record("user-d", limit=3) is True


def test_window_expiry_allows_calls_again():
    reset_all()
    with patch("app.ai.rate_limit.time.monotonic", return_value=1000.0):
        for _ in range(2):
            check_and_record("user-e", limit=2)
        assert check_and_record("user-e", limit=2) is False
    with patch("app.ai.rate_limit.time.monotonic", return_value=1000.0 + rate_limit._WINDOW_SECONDS + 1):
        assert check_and_record("user-e", limit=2) is True
