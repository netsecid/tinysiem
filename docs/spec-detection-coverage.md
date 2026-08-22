# Spec: Detection Coverage Dashboard (MITRE ATT&CK Navigator Heatmap)

Status: LOCKED design (2026-08-22, Wahyu + Hermes brainstorm). Implement via opencode.
Branch: `feat/detection-coverage` (from `origin/main`).
Model: opencode-go/minimax-m3 (bounded feature build, locked spec).

## Goal

New **Detection Coverage** tab in `ui/dashboard.html`: an ATT&CK Navigator-style heatmap
mapping all active detection rules to the full MITRE ATT&CK Enterprise matrix, overlaid
with live alert activity per technique. Distinguishes **detection intent** (rule exists)
from **detection actual** (rule fired). Renders the FULL matrix (14 tactics × all
top-level Enterprise techniques) so blind spots are visible, with honest coverage %.

## Non-goals (do NOT build)

- Sub-techniques in the dataset/matrix (deferred; validator accepts `.001` suffixes, see below).
- Tactic/technique editing UI or rule editor changes — validator only hooks existing create/update path.
- Navigator import/export JSON, version diffing, or tactic filtering UI.
- Backend changes to `GET /rules/mitre-coverage` (leave untouched; new endpoint is separate).

## Data model

### 1. Reference dataset — `app/rules/data/mitre_enterprise.json` (committed)

Generated once by `scripts/fetch_mitre_matrix.py` (stdlib only: urllib + json) from
MITRE's STIX bundle (`https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json`).

Trim: `type == "attack-pattern"`, `x_mitre_is_subtechnique != true`, `kill_chain_phases`
with `kill_chain_name == "mitre-attack"`. ID from `external_references[].external_id`
where `source_name == "mitre-attack"`. **A technique may appear under MULTIPLE tactics**
(ATT&CK allows this, e.g. T1078 under 4 tactics) — list it under each tactic it belongs to.

```json
{
  "version": "v17.x",                 // from bundle's x_mitre_version (latest at fetch time)
  "generated": "2026-08-22",
  "source": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
  "tactics": [
    {"tactic": "Initial Access", "techniques": [{"id": "T1078", "name": "Valid Accounts"}, ...]},
    ...
  ],
  "totals": {"tactics": 14, "techniques": 207}
}
```

- `totals.techniques` = count of UNIQUE technique IDs across all tactics (not sum of rows).
- Canonical tactic ORDER for rendering: reuse the existing `_TACTICS` list in
  `app/rules/mitre.py` (Reconnaissance → Impact, ATT&CK v12+ order). Any tactic in the
  dataset not in `_TACTICS` is skipped with a warning log.
- Loader: repo-relative `app/rules/data/mitre_enterprise.json`, optional override
  `TINYSIEM_MITRE_MATRIX_PATH` env var (must be added to `Settings` in `config.py` AND
  pinned in `conftest.py` — see existing `TINYSIEM_GEOIP_DB_PATH` precedent). If the file
  is missing/unparseable → `GET /dashboard/coverage` returns 503 with clear message
  ("run scripts/fetch_mitre_matrix.py").

### 2. API — `GET /dashboard/coverage?window=60|3600|86400` (analyst+, new)

`window` semantics identical to fidelity: default `86400`; invalid → 422.

```json
{
  "matrix_version": "v17.x",
  "generated": "2026-08-22",
  "window": 86400,
  "stats": {
    "rules_total": 9, "rules_mapped": 9, "rules_unmapped": 0,
    "techniques_covered": 4, "techniques_total": 207, "coverage_pct": 1.9,
    "tactics_covered": 3, "tactics_total": 14,
    "alerts_total": 5678, "alerts_unmapped": 12
  },
  "tactics": [
    {
      "tactic": "Credential Access",
      "total": 17, "covered": 1, "coverage_pct": 5.9, "alerts": 5600,
      "techniques": [
        {"id": "T1110", "name": "Brute Force", "covered": true,
         "rules": ["ssh-bruteforce", "fail2ban-ban"], "alerts": 5600},
        {"id": "T1003", "name": "OS Credential Dumping", "covered": false, "rules": [], "alerts": 0}
      ]
    }
  ]
}
```

Semantics:
- `techniques` arrays ALWAYS contain the full tactic list from the dataset (covered + gaps).
- `covered: true` when ≥1 rule maps to that technique id (from rule YAMLs, keyed by
  `mitre_technique`). `rules` = rule names (sorted), `alerts` = count in window.
- `coverage_pct` global = 100 × unique-covered-technique-ids / `totals.techniques` (unique).
  Per-tactic = covered-in-tactic / total-in-tactic. `null` never — dataset always present (503 otherwise).
- Alert counts: ONE scan of the alerts JSONL per request, filtered by
  `epoch(triggered_at) >= epoch(current_timestamp) - window` — same pattern as
  `_alert_stats()` in `app/dashboard/fidelity.py`. Alerts with missing/empty
  `mitre_technique` (pre-PR#14 records) → `stats.alerts_unmapped`. Alerts file is small
  (<10k/day), full scan per 7.5s poll is fine. No in-memory deques needed here.
- `_list_rule_files()` already returns ALL rules (no enabled flag exists — every YAML is
  active by definition). Rules with missing/invalid `mitre_tactic`/`mitre_technique` →
  `stats.rules_unmapped` + log; never crash.

### 3. Validator (rule create/update only — `_validate_rule_yaml` path in `app/rules/router.py`)

Reject with 422 + clear message when:
1. `mitre_tactic` present but not in `_TACTICS` enum (case-sensitive exact match).
2. `mitre_technique` present but not matching `^T\d{4}(\.\d{3})?$`.
3. Both present but the technique is not in the dataset, OR the declared tactic is not one
   of the technique's tactics in the dataset. Sub-technique suffix (`.001`): resolve the
   cross-check against the PREFIX technique's tactics (e.g. `T1059.001` → check T1059).
4. Either field present without the other.

Missing both fields on a rule is ALLOWED (unmapped rule — counted in `rules_unmapped`).

### 4. Existing-rule data fix (same PR)

`app/rules/rules/nginx-http-404-spike.yaml`: `mitre_tactic: "Discovery"` is WRONG —
T1595 (Active Scanning) belongs to **Reconnaissance**. Change to `"Reconnaissance"`.
Also verify the remaining rules pass the new validator (T1110→Credential Access,
T1046→Discovery, T1499→Impact all correct). Update the rule's playbook/description if it
references the tactic.

## UI — `ui/dashboard.html`

Reuse existing patterns from the Detection Fidelity tab (tabs, deep-link, polling, CSS vars):

- New tab button `Detection Coverage` (`data-tab="coverage"`) between Fidelity and end;
  pane `#coveragePane`; `#coverage` hash deep-link via existing `switchTab`/init code.
- Window filter `1m|1h|24h` (same control as fidelity; localStorage key `ts_cov_window`).
- 7.5s polling, paused when tab hidden (same as fidelity).
- **KPI strip**: Rules mapped (9/9) · Techniques covered (4/207 · 1.9%) · Tactics covered
  (3/14) · Alerts by MITRE (24h) · unmapped note (rules_unmapped / alerts_unmapped, dimmed,
  only when >0). Reuse fidelity KPI strip CSS (wraps 6→3 cols <900px).
- **Heatmap** (authentic Navigator layout — tactics as COLUMNS, techniques stacked as rows
  within each tactic):
  - Container `overflow-x: auto` (wide grid on mobile).
  - Cell states:
    - Covered + alerts>0: accent fill, intensity shaded by alert count (log scale).
    - Covered, alerts=0: muted primary tint.
    - Gap: transparent/grey, dashed border, hover shows technique id + name.
  - Tooltip (hover): technique id + name, rule names, alert count in window.
  - Click covered cell → drill panel below/beside: rule list + recent alerts
    (`GET /alerts?mitre_technique=T1110&limit=10` — filter registry already supports it),
    with rule severity dot. Click gap cell → nothing (or small "no detection" hint).
  - Legend + summary line: "4/207 techniques covered (1.9%) · 3/14 tactics · 9 rules".
- Dark + light via CSS vars only. `esc()`/`fmtT` helpers as elsewhere.

## Tests (add to `app/tests/`)

- `test_mitre_coverage.py`:
  - compute_coverage with a fixture dataset (2 tactics, 5 techniques): full matrix always
    returned (gaps included), covered flags, unique technique counting, rules_unmapped,
    per-tactic totals.
  - Multi-tactic technique (e.g. T1078 in 2 tactics) counted ONCE in global total.
  - Alert activity: counts filtered by window; missing mitre fields → alerts_unmapped.
  - Dataset missing → 503 on endpoint (mock the loader).
  - Validator: bad tactic, bad technique regex, tactic↔technique mismatch,
    sub-technique prefix resolution, field-without-pair, unmapped-rule-allowed.
- Endpoint shape test: `GET /dashboard/coverage` returns 422 on bad window, 200 with
  expected keys, analyst+ auth required.
- Existing suite (546 tests) must stay green. conftest: pin `TINYSIEM_MITRE_MATRIX_PATH=""`
  and use a fixture dataset for tests.

## Definition of Done

1. `scripts/fetch_mitre_matrix.py` exists; RUN it; `app/rules/data/mitre_enterprise.json`
   committed with 14 tactics and ≥190 unique techniques (verify real numbers).
2. `GET /dashboard/coverage?window=` implemented per shape above (verify live via curl after restart).
3. Validator live on rule create/update; `nginx-http-404-spike` fixed to Reconnaissance;
   all 9 rules pass the validator.
4. UI tab renders: KPI strip, full heatmap, tooltips, drill panel, window filter,
   `#coverage` deep-link, dark/light, responsive. Verify in browser (playwright or manual).
5. Tests added, full suite green.
6. Docs: `CLAUDE.md` Current State (v1.6.x section), `README.md` feature list,
   `docs/api-reference.md` (new endpoint + params + response shape),
   `docs/configuration.md` (TINYSIEM_MITRE_MATRIX_PATH) — as a docs update.
7. No push/PR from the coding run — Hermes runs security gate (gitleaks staged, semgrep
   scoped, bandit) and opens the PR with Summary + Test Plan.

## Constraints (do not regress)

- DuckDB: NOT touched by this feature (alerts are JSONL). No new indexes/ALTERs.
- Timestamps: window filtering uses `epoch(triggered_at)` vs `epoch(current_timestamp)`
  (never compare naive UTC to current_timestamp directly).
- UI files are disk-served (instant); Python changes need `sudo systemctl restart tinysiem`.
- `config.py` is `extra_forbidden` — new env var MUST be declared in Settings + pinned in conftest.
