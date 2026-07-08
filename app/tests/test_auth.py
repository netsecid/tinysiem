import pytest
from app.password import hash_password, verify_password
from app.storage import duckdb_store
from app.auth import create_token, decode_token, AuthUser


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

    assert fetched["must_change_password"] is False
    assert fetched["token_epoch"] == 0


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


def test_update_user_bumps_token_epoch():
    h = hash_password("pass")
    user = duckdb_store.create_user("epochbumptest", h, "analyst")
    assert user["token_epoch"] == 0
    updated = duckdb_store.update_user(user["id"], role="admin")
    assert updated["token_epoch"] == 1


def test_bump_token_epoch_increments_and_returns_user():
    h = hash_password("pass")
    user = duckdb_store.create_user("bumpepochtest2", h, "analyst")
    result = duckdb_store.bump_token_epoch(user["id"])
    assert result["token_epoch"] == 1
    assert duckdb_store.bump_token_epoch("nonexistent-id") is None


def test_change_own_password_clears_flag_and_bumps_epoch():
    h = hash_password("pass")
    user = duckdb_store.create_user("changepwstoretest", h, "analyst", must_change_password=True)
    assert user["must_change_password"] is True
    new_h = hash_password("newpass")
    result = duckdb_store.change_own_password(user["id"], new_h)
    assert result["must_change_password"] is False
    assert result["token_epoch"] == 1
    assert result["password_hash"] == new_h


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


def test_create_and_decode_token():
    token = create_token("uid-1", "alice", "admin")
    assert isinstance(token, str)
    payload = decode_token(token)
    assert payload is not None
    assert payload["sub"] == "uid-1"
    assert payload["username"] == "alice"
    assert payload["role"] == "admin"


def test_decode_invalid_token():
    assert decode_token("not.a.token") is None
    assert decode_token("") is None


async def test_login_valid(client):
    response = await client.post(
        "/auth/login",
        json={"username": "admin", "password": "admin"},
    )
    assert response.status_code == 200
    body = response.json()
    assert "access_token" in body
    assert body["role"] == "superadmin"
    assert body["username"] == "admin"


async def test_login_invalid_password(client):
    response = await client.post(
        "/auth/login",
        json={"username": "admin", "password": "wrongpass"},
    )
    assert response.status_code == 401


async def test_login_unknown_user(client):
    response = await client.post(
        "/auth/login",
        json={"username": "nobody", "password": "x"},
    )
    assert response.status_code == 401


async def test_me_endpoint(client, auth_headers):
    response = await client.get("/auth/me", headers=auth_headers)
    assert response.status_code == 200
    body = response.json()
    assert "username" in body
    assert "role" in body


async def test_login_lockout_after_repeated_failures(client):
    from app.auth_lockout import reset_all
    h = hash_password("correctpassword1")
    duckdb_store.create_user("lockouttestuser", h, "analyst")
    reset_all()

    for _ in range(5):
        resp = await client.post(
            "/auth/login", json={"username": "lockouttestuser", "password": "wrongpass"}
        )
        assert resp.status_code == 401

    locked_resp = await client.post(
        "/auth/login", json={"username": "lockouttestuser", "password": "wrongpass"}
    )
    assert locked_resp.status_code == 429

    # Even the CORRECT password is rejected while locked out.
    still_locked = await client.post(
        "/auth/login", json={"username": "lockouttestuser", "password": "correctpassword1"}
    )
    assert still_locked.status_code == 429
