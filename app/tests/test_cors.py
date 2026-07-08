from app.config import parse_cors_origins


def test_parse_cors_origins_empty_string_returns_empty_list():
    assert parse_cors_origins("") == []


def test_parse_cors_origins_parses_comma_separated():
    assert parse_cors_origins("http://a.com, http://b.com") == ["http://a.com", "http://b.com"]


def test_parse_cors_origins_strips_blank_entries():
    assert parse_cors_origins("http://a.com,, http://b.com,") == ["http://a.com", "http://b.com"]


async def test_cors_default_has_no_allowed_origins(client):
    resp = await client.get("/health", headers={"Origin": "http://evil.example"})
    assert "access-control-allow-origin" not in resp.headers
