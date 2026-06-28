from pathlib import Path
import pytest

DECODERS_DIR = Path(__file__).parent.parent / "decoder" / "decoders"
CUSTOM_DIR = DECODERS_DIR / "custom"

SAMPLE_LOG = (
    '203.0.113.42 - frank [10/Oct/2023:13:55:36 -0700] '
    '"GET /api/v1/users HTTP/1.1" 200 1234 '
    '"http://example.com/" "Mozilla/5.0"'
)

VALID_PARSER_YAML = """\
name: test-custom-parser
source: test-source
type: regex
pattern: '^(?P<msg>.+)$'
fields:
  raw_msg: msg
"""


@pytest.fixture(autouse=True)
def clean_custom_parsers():
    if CUSTOM_DIR.exists():
        for f in CUSTOM_DIR.glob("*.yaml"):
            f.unlink()
    yield
    if CUSTOM_DIR.exists():
        for f in CUSTOM_DIR.glob("*.yaml"):
            f.unlink()


async def test_list_parsers_returns_builtin(client, analyst_headers):
    r = await client.get("/parsers", headers=analyst_headers)
    assert r.status_code == 200
    data = r.json()
    names = [p["name"] for p in data["parsers"]]
    assert "nginx-access" in names


async def test_list_parsers_requires_auth(client):
    r = await client.get("/parsers")
    assert r.status_code == 401


async def test_get_parser_returns_yaml(client, analyst_headers):
    r = await client.get("/parsers/nginx-access", headers=analyst_headers)
    assert r.status_code == 200
    assert "source: nginx" in r.json()["yaml_text"]


async def test_get_parser_not_found(client, analyst_headers):
    r = await client.get("/parsers/nonexistent", headers=analyst_headers)
    assert r.status_code == 404


async def test_create_parser_admin(client, admin_headers):
    r = await client.post(
        "/parsers",
        json={"name": "test-custom-parser", "yaml_text": VALID_PARSER_YAML},
        headers=admin_headers,
    )
    assert r.status_code == 201
    assert (CUSTOM_DIR / "test-custom-parser.yaml").exists()


async def test_create_parser_analyst_forbidden(client, analyst_headers):
    r = await client.post(
        "/parsers",
        json={"name": "test-custom-parser", "yaml_text": VALID_PARSER_YAML},
        headers=analyst_headers,
    )
    assert r.status_code == 403


async def test_create_parser_invalid_yaml(client, admin_headers):
    r = await client.post(
        "/parsers",
        json={"name": "bad", "yaml_text": "not: valid: yaml: [[["},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_create_parser_missing_keys(client, admin_headers):
    r = await client.post(
        "/parsers",
        json={"name": "bad", "yaml_text": "name: ok\nsource: nginx\n"},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_create_parser_conflict(client, admin_headers):
    await client.post(
        "/parsers",
        json={"name": "test-custom-parser", "yaml_text": VALID_PARSER_YAML},
        headers=admin_headers,
    )
    r = await client.post(
        "/parsers",
        json={"name": "test-custom-parser", "yaml_text": VALID_PARSER_YAML},
        headers=admin_headers,
    )
    assert r.status_code == 409


async def test_update_custom_parser(client, admin_headers):
    await client.post(
        "/parsers",
        json={"name": "test-custom-parser", "yaml_text": VALID_PARSER_YAML},
        headers=admin_headers,
    )
    updated = VALID_PARSER_YAML.replace("raw_msg: msg", "message: msg")
    r = await client.put(
        "/parsers/test-custom-parser",
        json={"name": "test-custom-parser", "yaml_text": updated},
        headers=admin_headers,
    )
    assert r.status_code == 200


async def test_update_builtin_parser_forbidden(client, admin_headers):
    r = await client.put(
        "/parsers/nginx-access",
        json={"name": "nginx-access", "yaml_text": VALID_PARSER_YAML},
        headers=admin_headers,
    )
    assert r.status_code == 403


async def test_delete_custom_parser(client, admin_headers):
    await client.post(
        "/parsers",
        json={"name": "test-custom-parser", "yaml_text": VALID_PARSER_YAML},
        headers=admin_headers,
    )
    r = await client.delete("/parsers/test-custom-parser", headers=admin_headers)
    assert r.status_code == 204
    assert not (CUSTOM_DIR / "test-custom-parser.yaml").exists()


async def test_delete_builtin_parser_forbidden(client, admin_headers):
    r = await client.delete("/parsers/nginx-access", headers=admin_headers)
    assert r.status_code == 403


async def test_parser_test_endpoint_matches(client, analyst_headers):
    r = await client.post(
        "/parsers/nginx-access/test",
        json={"log_line": SAMPLE_LOG},
        headers=analyst_headers,
    )
    assert r.status_code == 200
    data = r.json()
    assert data["matched"] is True
    assert data["fields"]["source_ip"] == "203.0.113.42"


async def test_parser_test_endpoint_no_match(client, analyst_headers):
    r = await client.post(
        "/parsers/nginx-access/test",
        json={"log_line": "this is not nginx"},
        headers=analyst_headers,
    )
    assert r.status_code == 200
    assert r.json()["matched"] is False


async def test_invalid_parser_name_rejected(client, admin_headers):
    r = await client.post(
        "/parsers",
        json={"name": "../etc/passwd", "yaml_text": VALID_PARSER_YAML},
        headers=admin_headers,
    )
    assert r.status_code == 422
