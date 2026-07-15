from pathlib import Path
import pytest

RULES_DIR = Path(__file__).parent.parent / "rules" / "rules"
CUSTOM_DIR = RULES_DIR / "custom"

VALID_RULE_YAML = """\
name: test-custom-rule
severity: low
source: nginx
condition:
  type: field_match
  field: status_code
  value: 999
  operator: eq
"""


@pytest.fixture(autouse=True)
def clean_custom_rules():
    if CUSTOM_DIR.exists():
        for f in CUSTOM_DIR.glob("*.yaml"):
            f.unlink()
    yield
    if CUSTOM_DIR.exists():
        for f in CUSTOM_DIR.glob("*.yaml"):
            f.unlink()


async def test_list_rules_returns_builtins(client, analyst_headers):
    r = await client.get("/rules", headers=analyst_headers)
    assert r.status_code == 200
    names = [rule["name"] for rule in r.json()["rules"]]
    assert "nginx-http-404-spike" in names
    assert "nginx-http-500-error" in names


async def test_list_rules_requires_auth(client):
    r = await client.get("/rules")
    assert r.status_code == 401


async def test_get_rule_returns_yaml(client, analyst_headers):
    r = await client.get("/rules/nginx-http-404-spike", headers=analyst_headers)
    assert r.status_code == 200
    assert "threshold" in r.json()["yaml_text"]


async def test_get_rule_not_found(client, analyst_headers):
    r = await client.get("/rules/nonexistent", headers=analyst_headers)
    assert r.status_code == 404


async def test_create_rule_admin(client, admin_headers):
    r = await client.post(
        "/rules",
        json={"name": "test-custom-rule", "yaml_text": VALID_RULE_YAML},
        headers=admin_headers,
    )
    assert r.status_code == 201
    assert (CUSTOM_DIR / "test-custom-rule.yaml").exists()


async def test_create_rule_analyst_forbidden(client, analyst_headers):
    r = await client.post(
        "/rules",
        json={"name": "test-custom-rule", "yaml_text": VALID_RULE_YAML},
        headers=analyst_headers,
    )
    assert r.status_code == 403


async def test_create_rule_missing_keys(client, admin_headers):
    r = await client.post(
        "/rules",
        json={"name": "bad", "yaml_text": "name: ok\n"},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_update_custom_rule(client, admin_headers):
    await client.post(
        "/rules",
        json={"name": "test-custom-rule", "yaml_text": VALID_RULE_YAML},
        headers=admin_headers,
    )
    updated = VALID_RULE_YAML.replace("value: 999", "value: 888")
    r = await client.put(
        "/rules/test-custom-rule",
        json={"name": "test-custom-rule", "yaml_text": updated},
        headers=admin_headers,
    )
    assert r.status_code == 200


async def test_update_builtin_rule_forbidden(client, admin_headers):
    r = await client.put(
        "/rules/nginx-http-404-spike",
        json={"name": "nginx-http-404-spike", "yaml_text": VALID_RULE_YAML},
        headers=admin_headers,
    )
    assert r.status_code == 403


async def test_delete_custom_rule(client, admin_headers):
    await client.post(
        "/rules",
        json={"name": "test-custom-rule", "yaml_text": VALID_RULE_YAML},
        headers=admin_headers,
    )
    r = await client.delete("/rules/test-custom-rule", headers=admin_headers)
    assert r.status_code == 204
    assert not (CUSTOM_DIR / "test-custom-rule.yaml").exists()


async def test_delete_builtin_rule_forbidden(client, admin_headers):
    r = await client.delete("/rules/nginx-http-404-spike", headers=admin_headers)
    assert r.status_code == 403


async def test_invalid_rule_name_rejected(client, admin_headers):
    r = await client.post(
        "/rules",
        json={"name": "../../etc/passwd", "yaml_text": VALID_RULE_YAML},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_create_rule_name_mismatch_rejected(client, admin_headers):
    mismatched_yaml = VALID_RULE_YAML.replace("name: test-custom-rule", "name: some-other-name")
    r = await client.post(
        "/rules",
        json={"name": "test-custom-rule", "yaml_text": mismatched_yaml},
        headers=admin_headers,
    )
    assert r.status_code == 422
    assert not (CUSTOM_DIR / "test-custom-rule.yaml").exists()


async def test_update_rule_name_mismatch_rejected(client, admin_headers):
    await client.post(
        "/rules",
        json={"name": "test-custom-rule", "yaml_text": VALID_RULE_YAML},
        headers=admin_headers,
    )
    mismatched_yaml = VALID_RULE_YAML.replace("name: test-custom-rule", "name: renamed-rule")
    r = await client.put(
        "/rules/test-custom-rule",
        json={"name": "test-custom-rule", "yaml_text": mismatched_yaml},
        headers=admin_headers,
    )
    assert r.status_code == 422


async def test_generate_rule_no_api_key(client, admin_headers):
    r = await client.post(
        "/rules/generate",
        json={"description": "alert when 500 errors spike", "source": "nginx"},
        headers=admin_headers,
    )
    assert r.status_code == 503
    assert "AI features require configuration" in r.json()["detail"]
