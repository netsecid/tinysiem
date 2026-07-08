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


async def test_me_endpoint(client, analyst_headers):
    response = await client.get("/auth/me", headers=analyst_headers)
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


async def test_logout_bumps_epoch_and_revokes_old_token(client):
    from app.auth import create_token

    user = duckdb_store.create_user("epochtest1", hash_password("irrelevant-pw-123"), "analyst")
    old_token = create_token(user["id"], user["username"], user["role"], epoch=user["token_epoch"])
    headers = {"Authorization": f"Bearer {old_token}"}

    me_before = await client.get("/auth/me", headers=headers)
    assert me_before.status_code == 200

    logout_resp = await client.post("/auth/logout", headers=headers)
    assert logout_resp.status_code == 200

    me_after = await client.get("/auth/me", headers=headers)
    assert me_after.status_code == 401


async def test_deleted_user_token_is_rejected(client):
    from app.auth import create_token

    user = duckdb_store.create_user("deletedtokentest", hash_password("irrelevant-pw-123"), "analyst")
    token = create_token(user["id"], user["username"], user["role"], epoch=user["token_epoch"])
    headers = {"Authorization": f"Bearer {token}"}
    duckdb_store.delete_user(user["id"])

    resp = await client.get("/auth/me", headers=headers)
    assert resp.status_code == 401


async def test_forced_password_change_blocks_other_endpoints(client):
    from app.auth import create_token

    user = duckdb_store.create_user(
        "mustchangetest", hash_password("temporarypassword1"), "analyst", must_change_password=True
    )
    token = create_token(user["id"], user["username"], user["role"], epoch=user["token_epoch"])
    headers = {"Authorization": f"Bearer {token}"}

    blocked = await client.get("/events", headers=headers)
    assert blocked.status_code == 403
    assert blocked.json()["detail"] == "password_change_required"

    me_resp = await client.get("/auth/me", headers=headers)
    assert me_resp.status_code == 200


async def test_change_password_clears_flag_and_returns_new_token(client):
    from app.auth import create_token

    user = duckdb_store.create_user(
        "changepwtest", hash_password("temporarypassword1"), "analyst", must_change_password=True
    )
    token = create_token(user["id"], user["username"], user["role"], epoch=user["token_epoch"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": "temporarypassword1", "new_password": "brandnewpassword1"},
        headers=headers,
    )
    assert resp.status_code == 200
    new_token = resp.json()["access_token"]
    new_headers = {"Authorization": f"Bearer {new_token}"}

    events_resp = await client.get("/events", headers=new_headers)
    assert events_resp.status_code == 200

    old_events_resp = await client.get("/events", headers=headers)
    assert old_events_resp.status_code == 401  # old token's epoch is now stale


async def test_change_password_rejects_wrong_current_password(client):
    from app.auth import create_token

    user = duckdb_store.create_user("changepwwrong", hash_password("correctpassword1"), "analyst")
    token = create_token(user["id"], user["username"], user["role"], epoch=user["token_epoch"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": "wrongpassword1", "new_password": "brandnewpassword1"},
        headers=headers,
    )
    assert resp.status_code == 401


async def test_change_password_enforces_min_length(client):
    from app.auth import create_token

    user = duckdb_store.create_user("changepwshort", hash_password("correctpassword1"), "analyst")
    token = create_token(user["id"], user["username"], user["role"], epoch=user["token_epoch"])
    headers = {"Authorization": f"Bearer {token}"}

    resp = await client.post(
        "/auth/change-password",
        json={"current_password": "correctpassword1", "new_password": "short1"},
        headers=headers,
    )
    assert resp.status_code == 422
