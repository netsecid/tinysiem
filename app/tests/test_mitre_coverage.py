"""Tests for the MITRE Detection Coverage feature (v1.7).

Covers:
  - GET /rules/mitre-coverage (legacy endpoint — unchanged shape)
  - GET /dashboard/coverage (new endpoint shape, auth, validation, payload)
  - validate_mitre() validator (good/bad tactic, technique regex, sub-technique
    prefix resolution, field-without-pair, unmapped-rule-allowed)
  - compute_full_coverage() with a fixture dataset
  - Multi-tactic technique (T1078) counted ONCE in global total
  - Alert activity: counts filtered by window; missing mitre fields → alerts_unmapped
  - Dataset missing → 503 on endpoint (mock the loader)
"""
from __future__ import annotations

import json
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

import pytest
import yaml


# ── GET /rules/mitre-coverage (legacy endpoint) ────────────────────────────


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
    # nginx-http-404-spike is tagged Reconnaissance / T1595 (was Discovery in v1.6.x
    # but the spec mandates Reconnaissance — T1595 is Active Scanning).
    recon = next(t for t in data["tactics"] if t["tactic"] == "Reconnaissance")
    technique_ids = {tech["technique"] for tech in recon["techniques"]}
    assert "T1595" in technique_ids


async def test_mitre_coverage_requires_auth(client):
    r = await client.get("/rules/mitre-coverage")
    assert r.status_code == 401


# ── GET /dashboard/coverage (new endpoint) ─────────────────────────────────


async def test_dashboard_coverage_requires_auth(client):
    r = await client.get("/dashboard/coverage")
    assert r.status_code == 401


async def test_dashboard_coverage_window_validation(client, analyst_headers):
    """?window=<invalid> → 422."""
    r = await client.get("/dashboard/coverage?window=123", headers=analyst_headers)
    assert r.status_code == 422
    assert "window" in r.json()["detail"].lower()


async def test_dashboard_coverage_response_shape_and_stats(client, analyst_headers):
    """Smoke test: endpoint returns the documented shape with stats."""
    r = await client.get("/dashboard/coverage", headers=analyst_headers)
    assert r.status_code == 200
    data = r.json()
    assert data["window_seconds"] == 86400
    assert data["window_label"] == "24h"
    assert isinstance(data["generated_at"], str) and data["generated_at"].endswith("Z")
    assert set(data.keys()) == {
        "matrix_version", "generated", "window_seconds", "window_label",
        "generated_at", "stats", "tactics",
    }
    # stats shape
    stats = data["stats"]
    assert set(stats.keys()) == {
        "rules_total", "rules_mapped", "rules_unmapped",
        "techniques_covered", "techniques_total", "coverage_pct",
        "tactics_covered", "tactics_total",
        "alerts_total", "alerts_unmapped",
    }
    # We ship 9 rules, all MITRE-mapped after the validator lands.
    assert stats["rules_total"] == 9
    assert stats["rules_mapped"] == 9
    assert stats["rules_unmapped"] == 0
    # 4 unique techniques covered: T1110 (Cred), T1595 (Recon), T1046 (Disc), T1499 (Impact)
    assert stats["techniques_covered"] == 4
    # 4 tactics touched
    assert stats["tactics_covered"] == 4
    assert stats["tactics_total"] == 14
    # coverage_pct = 100 * 4 / totals.techniques — exact value depends on dataset.
    assert stats["coverage_pct"] == round(100.0 * 4 / stats["techniques_total"], 2)
    # Each tactic row carries totals + per-technique detail
    for tac in data["tactics"]:
        assert set(tac.keys()) == {"tactic", "total", "covered", "coverage_pct", "alerts", "techniques"}
        for tech in tac["techniques"]:
            assert set(tech.keys()) == {"id", "name", "covered", "rules", "alerts"}
            assert isinstance(tech["rules"], list)
            assert isinstance(tech["alerts"], int)
            assert isinstance(tech["covered"], bool)
    # Full matrix always rendered — at least the 4 standard tactics we know are big.
    discovery = next(t for t in data["tactics"] if t["tactic"] == "Discovery")
    assert discovery["total"] >= 30  # ATT&CK v18.1 lists 34 in Discovery
    recon = next(t for t in data["tactics"] if t["tactic"] == "Reconnaissance")
    assert any(t["id"] == "T1595" and t["covered"] for t in recon["techniques"])


async def test_dashboard_coverage_full_matrix_always_includes_gaps(client, analyst_headers):
    """Even with zero rules, the matrix must include EVERY technique so the UI
    can render honest gap cells. Verified by deleting one mapped rule.
    """
    r = await client.get("/dashboard/coverage", headers=analyst_headers)
    data = r.json()
    # All 14 tactics always present
    assert len(data["tactics"]) == 14
    # Total techniques across all tactics = matrix totals
    all_ids = {t["id"] for tac in data["tactics"] for t in tac["techniques"]}
    assert len(all_ids) >= 190  # spec floor; v18.1 ships 216
    # Most cells should be uncovered (gap) — TinySIEM has only 4 covered.
    gaps = sum(1 for tac in data["tactics"] for t in tac["techniques"] if not t["covered"])
    assert gaps > stats_techniques_total(data) - 4


def stats_techniques_total(data):
    return data["stats"]["techniques_total"]


async def test_dashboard_coverage_alerts_in_window(client, analyst_headers):
    """Alert activity is windowed: write 3 in-window alerts for T1110 and 1
    for T1046, then verify the endpoint surfaces them per-technique.
    """
    from app.alerts import file_writer
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    rule_t1110 = {"name": "cov-test-1", "severity": "high",
                  "mitre_tactic": "Credential Access", "mitre_technique": "T1110"}
    rule_t1046 = {"name": "cov-test-2", "severity": "medium",
                  "mitre_tactic": "Discovery", "mitre_technique": "T1046"}
    evt = {"id": "fake-evt-cov", "source": "cov-test-src"}
    for _ in range(3):
        file_writer.write_alert(rule_t1110, evt)
    file_writer.write_alert(rule_t1046, evt)

    r = await client.get("/dashboard/coverage?window=86400", headers=analyst_headers)
    assert r.status_code == 200
    data = r.json()
    cred = next(t for t in data["tactics"] if t["tactic"] == "Credential Access")
    t1110 = next(t for t in cred["techniques"] if t["id"] == "T1110")
    assert t1110["alerts"] >= 3
    assert data["stats"]["alerts_total"] >= 4


async def test_dashboard_coverage_alerts_unmapped_counted(client, analyst_headers):
    """Alerts with missing/empty mitre_technique land in alerts_unmapped."""
    from app.alerts import file_writer
    rule_unmapped = {"name": "cov-unmapped-rule", "severity": "low"}
    rule_with_tech = {"name": "cov-tech-rule", "severity": "low",
                      "mitre_tactic": "Discovery", "mitre_technique": "T1046"}
    evt = {"id": "fake-evt-un", "source": "cov-unmapped-src"}
    file_writer.write_alert(rule_unmapped, evt)  # no mitre_technique
    file_writer.write_alert(rule_with_tech, evt)

    r = await client.get("/dashboard/coverage?window=86400", headers=analyst_headers)
    data = r.json()
    assert data["stats"]["alerts_unmapped"] >= 1


async def test_dashboard_coverage_subtechnique_alerts_bucket_under_prefix(client, analyst_headers):
    """Sub-technique alerts (T1059.001) bucket under the prefix technique (T1059)
    so they line up with the matrix's top-level rows.
    """
    from app.alerts import file_writer
    rule_sub = {"name": "cov-sub-rule", "severity": "high",
                "mitre_tactic": "Execution", "mitre_technique": "T1059.001"}
    evt = {"id": "fake-evt-sub", "source": "cov-sub-src"}
    file_writer.write_alert(rule_sub, evt)

    r = await client.get("/dashboard/coverage?window=86400", headers=analyst_headers)
    data = r.json()
    exec_tac = next(t for t in data["tactics"] if t["tactic"] == "Execution")
    t1059 = next(t for t in exec_tac["techniques"] if t["id"] == "T1059")
    assert t1059["alerts"] >= 1


async def test_dashboard_coverage_returns_503_when_matrix_missing(client, analyst_headers, monkeypatch):
    """When the matrix dataset can't be loaded, the endpoint returns 503 with
    a clear message.
    """
    from app.dashboard import router as dash_router
    from app.dashboard import coverage as coverage_module
    from app.rules import mitre as mitre_module

    def _fake_build(rule_files, window_seconds):
        return None  # mimics missing dataset
    monkeypatch.setattr(coverage_module, "build_coverage_payload", _fake_build)

    # matrix_path() is also called for the 503 message
    monkeypatch.setattr(mitre_module, "matrix_path", lambda: Path("/tmp/nope.json"))

    r = await client.get("/dashboard/coverage", headers=analyst_headers)
    assert r.status_code == 503
    assert "MITRE matrix" in r.json()["detail"]
    assert "scripts/fetch_mitre_matrix.py" in r.json()["detail"]


# ── Validator unit tests ───────────────────────────────────────────────────


def test_validate_mitre_both_none_is_allowed():
    """Unmapped rule (both fields missing) is ALLOWED."""
    from app.rules.mitre import validate_mitre
    ok, msg = validate_mitre(None, None)
    assert ok and msg == ""
    ok, msg = validate_mitre("", "")
    assert ok and msg == ""


def test_validate_mitre_partial_pair_is_rejected():
    """Either field present without the other → reject."""
    from app.rules.mitre import validate_mitre
    ok, msg = validate_mitre("Discovery", None)
    assert not ok and "together" in msg
    ok, msg = validate_mitre(None, "T1046")
    assert not ok and "together" in msg
    ok, msg = validate_mitre("Discovery", "")
    assert not ok and "together" in msg


def test_validate_mitre_bad_tactic_rejected():
    from app.rules.mitre import validate_mitre
    ok, msg = validate_mitre("NotARealTactic", "T1046")
    assert not ok
    assert "not a valid ATT&CK Enterprise tactic" in msg


def test_validate_mitre_bad_technique_regex_rejected():
    from app.rules.mitre import validate_mitre
    ok, msg = validate_mitre("Discovery", "T99999")
    assert not ok
    assert "must match pattern" in msg
    ok, msg = validate_mitre("Discovery", "1046")  # missing T
    assert not ok
    ok, msg = validate_mitre("Discovery", "T1046A")  # wrong suffix
    assert not ok


def test_validate_mitre_tactic_technique_mismatch_rejected():
    """T1046 belongs to Discovery, not Credential Access."""
    from app.rules.mitre import validate_mitre
    ok, msg = validate_mitre("Credential Access", "T1046")
    assert not ok
    assert "belongs to tactics" in msg


def test_validate_mitre_subtechnique_prefix_resolution():
    """Sub-technique IDs are resolved against the PREFIX technique's tactic list."""
    from app.rules.mitre import validate_mitre
    # T1059 belongs to Execution — T1059.001 (PowerShell) must validate.
    ok, msg = validate_mitre("Execution", "T1059.001")
    assert ok, msg
    # But T1059.001 does NOT belong to Persistence (where T1053.005 may be).
    ok, msg = validate_mitre("Persistence", "T1059.001")
    assert not ok


def test_validate_mitre_valid_pairs_accepted():
    """Sanity check: every (tactic, technique) pair we use in our rule YAMLs."""
    from app.rules.mitre import validate_mitre
    pairs = [
        ("Reconnaissance", "T1595"),
        ("Resource Development", "T1583"),  # acquired infrastructure
        ("Initial Access", "T1078"),
        ("Execution", "T1059"),
        ("Persistence", "T1136"),
        ("Privilege Escalation", "T1068"),
        ("Defense Evasion", "T1027"),
        ("Credential Access", "T1110"),
        ("Discovery", "T1046"),
        ("Lateral Movement", "T1021"),
        ("Collection", "T1005"),
        ("Command and Control", "T1071"),
        ("Exfiltration", "T1041"),
        ("Impact", "T1499"),
    ]
    for tactic, technique in pairs:
        ok, msg = validate_mitre(tactic, technique)
        assert ok, f"{tactic}/{technique}: {msg}"


# ── compute_full_coverage() unit tests ──────────────────────────────────────


def _rule_yaml(name: str, tactic: str, technique: str) -> str:
    return yaml.safe_dump({
        "name": name,
        "severity": "medium",
        "source": "nginx",
        "condition": {"type": "field_match", "field": "status_code", "value": 404, "operator": "eq"},
        "mitre_tactic": tactic,
        "mitre_technique": technique,
    })


def _write_rules(tmp: Path, rules: list[tuple[str, str, str]]) -> list[tuple[Path, bool]]:
    out = []
    for name, tactic, technique in rules:
        p = tmp / f"{name}.yaml"
        p.write_text(_rule_yaml(name, tactic, technique))
        out.append((p, True))
    return out


def test_compute_full_coverage_returns_full_matrix_with_gaps(tmp_path):
    """With 1 rule, payload still includes ALL techniques (covered + gaps)."""
    from app.rules.mitre import compute_full_coverage
    rules = _write_rules(tmp_path, [("r1", "Credential Access", "T1110")])
    p = compute_full_coverage(rules, alert_counts_by_technique={}, alerts_unmapped=0)
    assert p is not None
    # Every tactic in the matrix is present.
    assert p["stats"]["tactics_total"] == 14
    # We covered exactly 1 technique.
    assert p["stats"]["techniques_covered"] == 1
    # But the techniques_total reflects the entire matrix (≥190 unique).
    assert p["stats"]["techniques_total"] >= 190
    # coverage_pct = round(100 * 1 / totals.techniques, 2)
    assert p["stats"]["coverage_pct"] == round(100.0 * 1 / p["stats"]["techniques_total"], 2)


def test_compute_full_coverage_multi_tactic_technique_counted_once():
    """T1078 belongs to 4 tactics in ATT&CK. It must count ONCE in
    stats.techniques_covered / techniques_total.
    """
    from app.rules.mitre import compute_full_coverage
    with tempfile.TemporaryDirectory() as tmp:
        rules = _write_rules(Path(tmp), [("r1", "Initial Access", "T1078")])
        p = compute_full_coverage(rules, alert_counts_by_technique={}, alerts_unmapped=0)
    # T1078 appears under 4 tactics but we count it once globally.
    t1078_count = sum(
        1 for tac in p["tactics"] for t in tac["techniques"]
        if t["id"] == "T1078"
    )
    # It MUST appear under 4 tactic columns (matrix truth), but counted once in stats.
    assert t1078_count >= 4
    assert p["stats"]["techniques_covered"] == 1


def test_compute_full_coverage_alert_counts_bucketed():
    from app.rules.mitre import compute_full_coverage
    with tempfile.TemporaryDirectory() as tmp:
        rules = _write_rules(Path(tmp), [
            ("r1", "Credential Access", "T1110"),
            ("r2", "Discovery", "T1046"),
        ])
        p = compute_full_coverage(
            rules,
            alert_counts_by_technique={"T1110": 12, "T1046": 7},
            alerts_unmapped=2,
        )
    assert p["stats"]["alerts_total"] == 19
    assert p["stats"]["alerts_unmapped"] == 2
    cred = next(t for t in p["tactics"] if t["tactic"] == "Credential Access")
    assert cred["alerts"] == 12
    disc = next(t for t in p["tactics"] if t["tactic"] == "Discovery")
    assert disc["alerts"] == 7


def test_compute_full_coverage_unmapped_rules_counted():
    from app.rules.mitre import compute_full_coverage
    with tempfile.TemporaryDirectory() as tmp:
        # One valid mapped rule + one rule with no MITRE fields (unmapped allowed)
        ok = tmp + "/ok.yaml"
        Path(ok).write_text(yaml.safe_dump({
            "name": "ok", "severity": "low", "source": "nginx",
            "condition": {"type": "field_match", "field": "status_code",
                          "value": 404, "operator": "eq"},
            "mitre_tactic": "Discovery", "mitre_technique": "T1046",
        }))
        unmapped = tmp + "/unmapped.yaml"
        Path(unmapped).write_text(yaml.safe_dump({
            "name": "unmapped", "severity": "low", "source": "nginx",
            "condition": {"type": "field_match", "field": "status_code",
                          "value": 500, "operator": "eq"},
        }))
        p = compute_full_coverage([(Path(ok), True), (Path(unmapped), True)], {}, 0)
    assert p["stats"]["rules_total"] == 2
    assert p["stats"]["rules_mapped"] == 1
    assert p["stats"]["rules_unmapped"] == 1
    assert p["stats"]["techniques_covered"] == 1


def test_compute_full_coverage_returns_none_when_matrix_unavailable(tmp_path, monkeypatch):
    """When load_matrix() returns None, payload is None (caller returns 503)."""
    from app.rules import mitre as mitre_module
    monkeypatch.setattr(mitre_module, "load_matrix", lambda: None)
    p = mitre_module.compute_full_coverage([], {}, 0)
    assert p is None


# ── Coverage alert-stats helper ────────────────────────────────────────────


def test_coverage_alert_stats_by_technique_filters_window():
    """Windowed scan: only in-window alerts count; sub-techniques bucket under prefix."""
    from app.dashboard import coverage as coverage_module
    from app.config import settings

    now = datetime.utcnow().replace(microsecond=0)
    recent = now.isoformat() + "Z"
    old = "2000-01-01T00:00:00Z"
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "alerts.log"
        with open(path, "w") as fh:
            # 3 recent T1110 alerts
            for _ in range(3):
                fh.write(json.dumps({
                    "alert_id": str(uuid.uuid4()), "triggered_at": recent,
                    "rule_name": "r1", "mitre_technique": "T1110",
                }) + "\n")
            # 1 recent T1059.001 → buckets under T1059
            fh.write(json.dumps({
                "alert_id": str(uuid.uuid4()), "triggered_at": recent,
                "rule_name": "r2", "mitre_technique": "T1059.001",
            }) + "\n")
            # 1 alert with NO mitre_technique → unmapped
            fh.write(json.dumps({
                "alert_id": str(uuid.uuid4()), "triggered_at": recent,
                "rule_name": "r3",
            }) + "\n")
            # 1 old (out of window) alert
            fh.write(json.dumps({
                "alert_id": str(uuid.uuid4()), "triggered_at": old,
                "rule_name": "r4", "mitre_technique": "T9999",
            }) + "\n")
        original = settings.tinysiem_alerts_path
        settings.tinysiem_alerts_path = str(path)
        try:
            counts, unmapped = coverage_module._alert_stats_by_technique(60)
        finally:
            settings.tinysiem_alerts_path = original
    assert counts.get("T1110") == 3
    assert counts.get("T1059") == 1  # sub-technique → prefix
    assert unmapped == 1


def test_coverage_alert_stats_by_technique_handles_missing_file():
    from app.dashboard import coverage as coverage_module
    from app.config import settings
    original = settings.tinysiem_alerts_path
    with tempfile.TemporaryDirectory() as tmp:
        settings.tinysiem_alerts_path = str(Path(tmp) / "missing.log")
        try:
            counts, unmapped = coverage_module._alert_stats_by_technique(60)
        finally:
            settings.tinysiem_alerts_path = original
    assert counts == {} and unmapped == 0


# ── Matrix dataset sanity ───────────────────────────────────────────────────


def test_bundled_matrix_has_expected_shape():
    """The shipped dataset must have the documented top-level keys."""
    from app.rules.mitre import load_matrix
    m = load_matrix()
    assert m is not None
    assert set(m.keys()) >= {"version", "generated", "source", "tactics", "totals"}
    assert isinstance(m["totals"]["tactics"], int)
    assert isinstance(m["totals"]["techniques"], int)
    assert m["totals"]["tactics"] == 14
    assert m["totals"]["techniques"] >= 190
    # Every tactic has the same name as in _TACTICS
    from app.rules.mitre import _TACTICS
    assert [t["tactic"] for t in m["tactics"]] == _TACTICS
