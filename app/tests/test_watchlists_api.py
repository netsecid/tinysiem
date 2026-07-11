async def test_create_and_list_entry_admin(client, admin_headers):
    r = await client.post(
        "/watchlists",
        json={"list_name": "api-test-1", "indicator_type": "ip", "value": "198.51.100.1",
              "severity": "high", "note": "test entry"},
        headers=admin_headers,
    )
    assert r.status_code == 201
    entry = r.json()
    assert entry["value"] == "198.51.100.1"

    r2 = await client.get("/watchlists?list_name=api-test-1", headers=admin_headers)
    assert r2.status_code == 200
    assert any(e["id"] == entry["id"] for e in r2.json()["entries"])


async def test_create_entry_analyst_forbidden(client, analyst_headers):
    r = await client.post(
        "/watchlists",
        json={"list_name": "api-test-2", "indicator_type": "ip", "value": "198.51.100.2",
              "severity": "low", "note": None},
        headers=analyst_headers,
    )
    assert r.status_code == 403


async def test_list_entries_analyst_allowed(client, analyst_headers):
    r = await client.get("/watchlists", headers=analyst_headers)
    assert r.status_code == 200


async def test_toggle_and_delete_entry(client, admin_headers):
    r = await client.post(
        "/watchlists",
        json={"list_name": "api-test-3", "indicator_type": "ip", "value": "198.51.100.3",
              "severity": "medium", "note": None},
        headers=admin_headers,
    )
    entry_id = r.json()["id"]

    r2 = await client.patch(f"/watchlists/{entry_id}?active=false", headers=admin_headers)
    assert r2.status_code == 200
    assert r2.json()["active"] is False

    r3 = await client.delete(f"/watchlists/{entry_id}", headers=admin_headers)
    assert r3.status_code == 204

    r4 = await client.delete(f"/watchlists/{entry_id}", headers=admin_headers)
    assert r4.status_code == 404


async def test_invalid_indicator_type_returns_422(client, admin_headers):
    r = await client.post(
        "/watchlists",
        json={"list_name": "api-test-4", "indicator_type": "bogus", "value": "x",
              "severity": "low", "note": None},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_csv_import(client, admin_headers):
    csv_body = "type,value,severity,note\nip,203.0.113.50,high,imported scanner\ncidr,203.0.113.0/24,medium,imported range\n"
    files = {"file": ("watchlist.csv", csv_body, "text/csv")}
    r = await client.post(
        "/watchlists/import?list_name=api-test-import",
        files=files,
        headers=admin_headers,
    )
    assert r.status_code == 201
    body = r.json()
    assert len(body["created"]) == 2
    assert body["errors"] == []


async def test_csv_import_missing_columns_returns_422(client, admin_headers):
    files = {"file": ("bad.csv", "not,the,right,columns\n1,2,3,4\n", "text/csv")}
    r = await client.post(
        "/watchlists/import?list_name=api-test-import-bad",
        files=files,
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_bulk_add(client, admin_headers):
    r = await client.post(
        "/watchlists/bulk",
        json={"list_name": "api-test-bulk", "entries": [
            {"indicator_type": "ip", "value": "203.0.113.60", "severity": "low", "note": None},
            {"indicator_type": "uri_substring", "value": "/wp-admin", "severity": "medium", "note": "wp probe"},
        ]},
        headers=admin_headers,
    )
    assert r.status_code == 201
    assert len(r.json()["created"]) == 2
