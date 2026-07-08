import pytest

from app.startup_checks import MIN_JWT_SECRET_LENGTH, validate_jwt_secret


def test_validate_jwt_secret_rejects_short_secret():
    with pytest.raises(RuntimeError, match="at least 32 characters"):
        validate_jwt_secret("too-short")


def test_validate_jwt_secret_accepts_minimum_length_secret():
    validate_jwt_secret("a" * MIN_JWT_SECRET_LENGTH)  # must not raise


def test_validate_jwt_secret_rejects_one_below_minimum():
    with pytest.raises(RuntimeError):
        validate_jwt_secret("a" * (MIN_JWT_SECRET_LENGTH - 1))
