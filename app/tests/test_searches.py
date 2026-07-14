async def test_create_and_list_own_search(client, analyst_headers):
    r = await client.post(
        "/searches",
        json={"name": "my 404s", "page": "events", "query_string": "status_code=404"},
        headers=analyst_headers,
    )
    assert r.status_code == 201
    search = r.json()
    assert search["name"] == "my 404s"
    assert search["owner"] == "fixture-analyst"

    r2 = await client.get("/searches?page=events", headers=analyst_headers)
    assert r2.status_code == 200
    assert any(s["id"] == search["id"] for s in r2.json()["searches"])


async def test_invalid_page_rejected(client, analyst_headers):
    r = await client.post(
        "/searches",
        json={"name": "bad page", "page": "not-a-page", "query_string": "x"},
        headers=analyst_headers,
    )
    assert r.status_code == 422


async def test_owner_cannot_see_or_delete_others_search(client, analyst_headers, admin_headers):
    r = await client.post(
        "/searches",
        json={"name": "admin only", "page": "alerts", "query_string": "severity=high"},
        headers=admin_headers,
    )
    search_id = r.json()["id"]

    r2 = await client.get("/searches?page=alerts", headers=analyst_headers)
    assert not any(s["id"] == search_id for s in r2.json()["searches"])

    r3 = await client.delete(f"/searches/{search_id}", headers=analyst_headers)
    assert r3.status_code == 404

    r4 = await client.delete(f"/searches/{search_id}", headers=admin_headers)
    assert r4.status_code == 204


async def test_requires_auth(client):
    r = await client.get("/searches")
    assert r.status_code == 401


async def test_delete_search_is_owner_scoped(client, analyst_headers, admin_headers):
    # Regression test: verify the DELETE statement itself is owner-scoped,
    # not just guarded by a preceding SELECT check.
    # Creates a search as admin, then attempts to delete it as analyst
    # via the storage layer directly. Verifies deletion fails and search persists.
    from app.searches.store import create_search, delete_search, list_searches

    # Create a search owned by admin
    search = create_search("admin", "test", "events", "status_code=500")
    search_id = search["id"]

    # Verify it exists
    admin_searches = list_searches("admin")
    assert any(s["id"] == search_id for s in admin_searches)

    # Attempt to delete it as a different owner (analyst) via storage layer
    result = delete_search(search_id, "analyst")
    assert result is False  # deletion should fail

    # Verify the search still exists under admin's ownership
    admin_searches_after = list_searches("admin")
    assert any(s["id"] == search_id for s in admin_searches_after)
