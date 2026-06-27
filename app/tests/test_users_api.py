import pytest


async def test_list_users_requires_superadmin(client, analyst_headers):
    res = await client.get("/users", headers=analyst_headers)
    assert res.status_code == 403


async def test_list_users_as_superadmin(client, superadmin_headers):
    res = await client.get("/users", headers=superadmin_headers)
    assert res.status_code == 200
    assert "users" in res.json()


async def test_create_user(client, superadmin_headers):
    res = await client.post(
        "/users",
        json={"username": "newanalyst", "password": "pass123", "role": "analyst"},
        headers=superadmin_headers,
    )
    assert res.status_code == 201
    body = res.json()
    assert body["username"] == "newanalyst"
    assert body["role"] == "analyst"
    assert "password_hash" not in body


async def test_create_user_duplicate_username(client, superadmin_headers):
    await client.post(
        "/users",
        json={"username": "dupuser", "password": "p", "role": "analyst"},
        headers=superadmin_headers,
    )
    res = await client.post(
        "/users",
        json={"username": "dupuser", "password": "p", "role": "analyst"},
        headers=superadmin_headers,
    )
    assert res.status_code == 409


async def test_create_user_invalid_role(client, superadmin_headers):
    res = await client.post(
        "/users",
        json={"username": "baduser", "password": "p", "role": "god"},
        headers=superadmin_headers,
    )
    assert res.status_code == 422


async def test_update_user(client, superadmin_headers):
    create_res = await client.post(
        "/users",
        json={"username": "updateme", "password": "pass", "role": "analyst"},
        headers=superadmin_headers,
    )
    user_id = create_res.json()["id"]
    res = await client.put(
        f"/users/{user_id}",
        json={"role": "admin"},
        headers=superadmin_headers,
    )
    assert res.status_code == 200
    assert res.json()["role"] == "admin"


async def test_delete_user(client, superadmin_headers):
    create_res = await client.post(
        "/users",
        json={"username": "deleteme", "password": "pass", "role": "analyst"},
        headers=superadmin_headers,
    )
    user_id = create_res.json()["id"]
    res = await client.delete(f"/users/{user_id}", headers=superadmin_headers)
    assert res.status_code == 204


async def test_cannot_delete_last_superadmin(client, superadmin_headers):
    # Find the admin user created by ensure_superadmin
    users_res = await client.get("/users", headers=superadmin_headers)
    users = users_res.json()["users"]
    admins = [u for u in users if u["role"] == "superadmin"]
    if len(admins) == 1:
        res = await client.delete(f"/users/{admins[0]['id']}", headers=superadmin_headers)
        assert res.status_code == 409
