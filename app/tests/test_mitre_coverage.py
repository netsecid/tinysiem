async def test_mitre_coverage_includes_all_14_tactics(client, analyst_headers):
    r = await client.get("/rules/mitre-coverage", headers=analyst_headers)
    assert r.status_code == 200
    data = r.json()
    assert len(data["tactics"]) == 14
    tactic_names = {t["tactic"] for t in data["tactics"]}
    assert "Discovery" in tactic_names
    assert "Credential Access" in tactic_names


async def test_mitre_coverage_reflects_builtin_rules(client, analyst_headers):
    r = await client.get("/rules/mitre-coverage", headers=analyst_headers)
    data = r.json()
    discovery = next(t for t in data["tactics"] if t["tactic"] == "Discovery")
    technique_names = {tech["technique"] for tech in discovery["techniques"]}
    # nginx-http-404-spike is tagged Discovery / T1595 per its built-in YAML
    assert "T1595" in technique_names


async def test_mitre_coverage_requires_auth(client):
    r = await client.get("/rules/mitre-coverage")
    assert r.status_code == 401
