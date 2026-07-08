async def test_sbom_requires_admin(client, analyst_headers):
    resp = await client.get("/sbom", headers=analyst_headers)
    assert resp.status_code == 403


async def test_sbom_requires_auth(client):
    resp = await client.get("/sbom")
    assert resp.status_code == 401


async def test_sbom_returns_list(client, admin_headers):
    resp = await client.get("/sbom", headers=admin_headers)
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)
