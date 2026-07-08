import os

import duckdb


def test_users_table_migration_adds_new_columns(tmp_path):
    from app.storage import duckdb_store

    db_path = str(tmp_path / "legacy.duckdb")
    # Simulate a pre-v1.4 database: users table without the new columns
    legacy_conn = duckdb.connect(db_path)
    legacy_conn.execute(
        """
        CREATE TABLE users (
            id            VARCHAR PRIMARY KEY,
            username      VARCHAR UNIQUE NOT NULL,
            password_hash VARCHAR NOT NULL,
            role          VARCHAR NOT NULL,
            created_at    TIMESTAMP NOT NULL
        )
        """
    )
    legacy_conn.execute(
        "INSERT INTO users VALUES (?, ?, ?, ?, ?)",
        ["legacy-id", "legacyuser", "hash", "analyst", "2026-01-01 00:00:00"],
    )
    legacy_conn.close()

    duckdb_store.init_db(db_path)
    try:
        user = duckdb_store.get_user_by_username("legacyuser")
        assert user["must_change_password"] is False
        assert user["token_epoch"] == 0
    finally:
        duckdb_store.close_db()
        # Restore the real session-scoped test DB connection for subsequent tests.
        duckdb_store.init_db(os.environ["TINYSIEM_DUCKDB_PATH"])
