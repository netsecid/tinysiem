async def test_add_list_delete_exception(client, admin_headers):
    r = await client.post(
        "/rules/nginx-http-404-spike/exceptions",
        json={"field": "source_ip", "value": "10.0.0.1", "reason": "known internal scanner"},
        headers=admin_headers,
    )
    assert r.status_code == 201
    exc = r.json()
    assert exc["field"] == "source_ip"
    assert exc["rule_name"] == "nginx-http-404-spike"

    r2 = await client.get("/rules/nginx-http-404-spike/exceptions", headers=admin_headers)
    assert r2.status_code == 200
    assert any(e["id"] == exc["id"] for e in r2.json()["exceptions"])

    r3 = await client.delete(f"/rules/nginx-http-404-spike/exceptions/{exc['id']}", headers=admin_headers)
    assert r3.status_code == 204

    r4 = await client.get("/rules/nginx-http-404-spike/exceptions", headers=admin_headers)
    assert not any(e["id"] == exc["id"] for e in r4.json()["exceptions"])


async def test_reason_required(client, admin_headers):
    r = await client.post(
        "/rules/nginx-http-404-spike/exceptions",
        json={"field": "source_ip", "value": "10.0.0.2", "reason": ""},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_disallowed_field_rejected(client, admin_headers):
    r = await client.post(
        "/rules/nginx-http-404-spike/exceptions",
        json={"field": "raw", "value": "x", "reason": "not allowed"},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_analyst_forbidden(client, analyst_headers):
    r = await client.post(
        "/rules/nginx-http-404-spike/exceptions",
        json={"field": "source_ip", "value": "10.0.0.3", "reason": "test"},
        headers=analyst_headers,
    )
    assert r.status_code == 403


async def test_delete_nonexistent_exception_404(client, admin_headers):
    r = await client.delete("/rules/nginx-http-404-spike/exceptions/does-not-exist", headers=admin_headers)
    assert r.status_code == 404
