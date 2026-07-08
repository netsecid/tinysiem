async def test_ui_response_has_csp_header(client):
    resp = await client.get("/ui/login.html")
    assert "content-security-policy" in resp.headers
    assert "default-src 'self'" in resp.headers["content-security-policy"]
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]


async def test_api_response_has_no_csp_header(client):
    resp = await client.get("/health")
    assert "content-security-policy" not in resp.headers
