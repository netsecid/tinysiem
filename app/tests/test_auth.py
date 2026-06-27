import pytest
from app.password import hash_password, verify_password
from app.storage import duckdb_store


def test_hash_and_verify():
    h = hash_password("secret123")
    assert verify_password("secret123", h)
    assert not verify_password("wrong", h)


def test_create_and_get_user():
    h = hash_password("pass")
    user = duckdb_store.create_user("testuser1", h, "analyst")
    assert user["username"] == "testuser1"
    assert user["role"] == "analyst"
    assert "id" in user

    fetched = duckdb_store.get_user_by_username("testuser1")
    assert fetched is not None
    assert fetched["password_hash"] == h

    fetched_by_id = duckdb_store.get_user_by_id(user["id"])
    assert fetched_by_id["username"] == "testuser1"


def test_list_users():
    h = hash_password("pass")
    duckdb_store.create_user("listuser1", h, "admin")
    users = duckdb_store.list_users()
    assert any(u["username"] == "listuser1" for u in users)
    # password_hash not exposed in list
    assert all("password_hash" not in u for u in users)


def test_update_user():
    h = hash_password("pass")
    user = duckdb_store.create_user("updateuser", h, "analyst")
    updated = duckdb_store.update_user(user["id"], role="admin")
    assert updated["role"] == "admin"
    assert updated["username"] == "updateuser"


def test_delete_user():
    h = hash_password("pass")
    user = duckdb_store.create_user("deleteuser", h, "analyst")
    assert duckdb_store.delete_user(user["id"]) is True
    assert duckdb_store.get_user_by_id(user["id"]) is None
    assert duckdb_store.delete_user(user["id"]) is False


def test_count_superadmins():
    h = hash_password("pass")
    before = duckdb_store.count_superadmins()
    duckdb_store.create_user("sadmin_count_test", h, "superadmin")
    assert duckdb_store.count_superadmins() == before + 1


def test_ensure_superadmin_only_runs_when_empty(client):
    # DB already has users from other tests; ensure_superadmin should be a no-op
    before = duckdb_store.list_users()
    duckdb_store.ensure_superadmin(hash_password("whatever"))
    after = duckdb_store.list_users()
    assert len(after) == len(before)
