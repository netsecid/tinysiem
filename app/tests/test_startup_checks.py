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


def test_warn_if_default_superadmin_password_logs_when_flagged(caplog):
    from app.storage import duckdb_store
    from app.password import hash_password
    from app.startup_checks import warn_if_default_superadmin_password

    duckdb_store.create_user("defaultpwwarntest", hash_password("x"), "superadmin", must_change_password=True)
    with caplog.at_level("WARNING"):
        warn_if_default_superadmin_password()
    assert any("default password" in r.message for r in caplog.records)


def test_warn_if_integrations_missing_master_key(monkeypatch, caplog):
    from app.storage import duckdb_store
    from app.config import settings
    from app.startup_checks import warn_if_integrations_missing_master_key
    import uuid
    from datetime import datetime, timezone

    monkeypatch.setattr(settings, "tinysiem_master_key", "")
    with duckdb_store._lock:
        duckdb_store._conn.execute(
            "INSERT INTO integrations (integration_id, name, integration_type, enabled, config, "
            "credentials, schedule_minutes, created_by, created_at, updated_at) "
            "VALUES (?, ?, ?, TRUE, '{}', '{}', 15, ?, ?, ?)",
            [str(uuid.uuid4()), "warntest", "aws_cloudtrail", "tester",
             datetime.now(timezone.utc), datetime.now(timezone.utc)],
        )
    with caplog.at_level("WARNING"):
        warn_if_integrations_missing_master_key()
    assert any("TINYSIEM_MASTER_KEY" in r.message for r in caplog.records)


def test_validate_jwt_secret_rejects_env_example_placeholder_even_if_padded():
    with pytest.raises(RuntimeError):
        validate_jwt_secret("replace-with-64-char-random-string-padded-to-be-64-chars-long!")
