import pytest


async def test_list_users_requires_superadmin(client, analyst_headers):
    res = await client.get("/users", headers=analyst_headers)
    assert res.status_code == 403


async def test_list_users_requires_superadmin_not_admin(client, admin_headers):
    res = await client.get("/users", headers=admin_headers)
    assert res.status_code == 403


async def test_list_users_as_superadmin(client, superadmin_headers):
    res = await client.get("/users", headers=superadmin_headers)
    assert res.status_code == 200
    assert "users" in res.json()


async def test_create_user(client, superadmin_headers):
    res = await client.post(
        "/users",
        json={"username": "newanalyst", "password": "pass12345678", "role": "analyst"},
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
        json={"username": "dupuser", "password": "duppassword1", "role": "analyst"},
        headers=superadmin_headers,
    )
    res = await client.post(
        "/users",
        json={"username": "dupuser", "password": "duppassword1", "role": "analyst"},
        headers=superadmin_headers,
    )
    assert res.status_code == 409


async def test_create_user_invalid_role(client, superadmin_headers):
    res = await client.post(
        "/users",
        json={"username": "baduser", "password": "badpassword12", "role": "god"},
        headers=superadmin_headers,
    )
    assert res.status_code == 422


async def test_create_user_rejects_short_password(client, superadmin_headers):
    res = await client.post(
        "/users",
        json={"username": "shortpwuser", "password": "short1", "role": "analyst"},
        headers=superadmin_headers,
    )
    assert res.status_code == 422


async def test_update_user_rejects_short_password(client, superadmin_headers):
    create_res = await client.post(
        "/users",
        json={"username": "updateshortpw", "password": "password12345", "role": "analyst"},
        headers=superadmin_headers,
    )
    user_id = create_res.json()["id"]
    res = await client.put(
        f"/users/{user_id}",
        json={"password": "short1"},
        headers=superadmin_headers,
    )
    assert res.status_code == 422


async def test_update_user(client, superadmin_headers):
    create_res = await client.post(
        "/users",
        json={"username": "updateme", "password": "updatepass123", "role": "analyst"},
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
    assert "password_hash" not in res.json()


async def test_delete_user(client, superadmin_headers):
    create_res = await client.post(
        "/users",
        json={"username": "deleteme", "password": "deletepass123", "role": "analyst"},
        headers=superadmin_headers,
    )
    user_id = create_res.json()["id"]
    res = await client.delete(f"/users/{user_id}", headers=superadmin_headers)
    assert res.status_code == 204


async def test_update_user_duplicate_username(client, superadmin_headers):
    await client.post("/users", json={"username": "orig_user", "password": "password12345", "role": "analyst"}, headers=superadmin_headers)
    res2 = await client.post("/users", json={"username": "other_user", "password": "password12345", "role": "analyst"}, headers=superadmin_headers)
    other_id = res2.json()["id"]
    res = await client.put(f"/users/{other_id}", json={"username": "orig_user"}, headers=superadmin_headers)
    assert res.status_code == 409
    # Verify the user was NOT deleted
    check = await client.get("/users", headers=superadmin_headers)
    assert any(u["id"] == other_id for u in check.json()["users"])


async def test_cannot_delete_last_superadmin(client, superadmin_headers):
    # Create a fresh superadmin to use as our isolated test subject
    create_res = await client.post(
        "/users",
        json={"username": "sole_sadmin_test", "password": "password12345", "role": "superadmin"},
        headers=superadmin_headers,
    )
    assert create_res.status_code == 201
    new_id = create_res.json()["id"]

    # Mint a fresh token for the new superadmin itself. This test needs to delete
    # every OTHER superadmin (including the DB row backing superadmin_headers), so
    # we can't keep using superadmin_headers past that point — its own row may get
    # deleted, which would revoke it for any subsequent request.
    login_res = await client.post(
        "/auth/login", json={"username": "sole_sadmin_test", "password": "password12345"}
    )
    assert login_res.status_code == 200
    new_headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Delete all other superadmins except our new one so it's the only one
    users_res = await client.get("/users", headers=new_headers)
    other_superadmins = [
        u for u in users_res.json()["users"]
        if u["role"] == "superadmin" and u["id"] != new_id
    ]
    for u in other_superadmins:
        await client.delete(f"/users/{u['id']}", headers=new_headers)

    # Now our new user should be the sole superadmin — deletion must be rejected
    res = await client.delete(f"/users/{new_id}", headers=new_headers)
    assert res.status_code == 409
