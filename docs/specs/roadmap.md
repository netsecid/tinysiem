# TinySIEM — Feature Roadmap v1.0 → v1.4

> Status: v1.0–v1.3 shipped; v1.4 approved design  
> Current version: 1.3  
> Author: TinySIEM project

---

## Overview

This roadmap covers seven features decided after the v0.9 audit logging release. Features are grouped into three versions based on dependency order and risk:

- **v1.0** — Core SOC operations (Cases, Log Sources)
- **v1.1** — Intelligence layer (Smart Baselines, AI Enrichment)
- **v1.2** — Extensibility (API Integrations, Custom Dashboard)
- **UI polish** — Runs parallel to all versions; each release ships polished pages

---

## Feature Index

| ID | Feature | Version | Spec |
|---|---|---|---|
| F1 | Cases & Workflow | v1.0 | [v1.0-cases.md](v1.0-cases.md) |
| F2 | Log Sources Page | v1.0 | [v1.0-log-sources.md](v1.0-log-sources.md) |
| F3 | Smart Baselines | v1.1 | [v1.1-smart-baselines.md](v1.1-smart-baselines.md) |
| F4 | AI Context Enrichment | v1.1 | [v1.1-ai-enrichment.md](v1.1-ai-enrichment.md) |
| F5 | API Integrations | v1.2 | [v1.2-integrations.md](v1.2-integrations.md) |
| F6 | Custom Dashboard | v1.2 | [v1.2-dashboard.md](v1.2-dashboard.md) |
| F7 | UI Polish | ongoing | [ui-polish.md](ui-polish.md) |

---

## Dependency Map

```
v0.9 (current)
  ├── F1 Cases          ← extends alerts; adds cases + comments tables
  ├── F2 Log Sources    ← read-only; queries existing events table
  │
  └── v1.1
        ├── F3 Baselines     ← needs events history; adds baselines table + background job
        ├── F4 AI Enrichment ← extends existing /parsers/generate, /rules/generate; no new tables
        │
        └── v1.2
              ├── F5 Integrations  ← new integrations table; needs Fernet encryption; new background scheduler
              └── F6 Dashboard     ← reads existing endpoints; adds dashboards table
```

F1 and F2 are independent of each other. F3 requires populated event history (weeks of data for meaningful baselines). F4 has no prerequisites. F5 and F6 are independent.

---

## Cross-Cutting Decisions

### Credential Storage (F5)
All integration credentials are encrypted at rest using `cryptography.fernet.Fernet`. The master key is stored in env var `TINYSIEM_MASTER_KEY`. Credentials are never returned raw through the API after initial save (masked to last 4 chars). See [v1.2-integrations.md](v1.2-integrations.md).

### New Python Dependencies

| Package | Version | Used by | Reason |
|---|---|---|---|
| `cryptography` | ≥42.0 | F5 | Fernet encryption for integration credentials |
| `numpy` | ≥1.26 | F3 | Statistical baseline computation |
| `boto3` | ≥1.34 | F5 | AWS CloudTrail API |
| `google-api-python-client` | ≥2.120 | F5 | Google Workspace API |
| `google-auth` | ≥2.28 | F5 | GCP service account auth |

All other features use stdlib only.

### New DuckDB Tables

| Table | Added in | Purpose |
|---|---|---|
| `cases` | F1 | Security investigation cases |
| `case_comments` | F1 | Threaded comments on cases |
| `case_alerts` | F1 | Many-to-many: alerts → cases |
| `source_registry` | F2 | Inferred log source metadata |
| `baselines` | F3 | Hourly statistical baselines per source |
| `baseline_violations` | F3 | Detected anomalies |
| `integrations` | F5 | Integration configs with encrypted credentials |
| `integration_runs` | F5 | Poll history and status |
| `dashboards` | F6 | Saved dashboard layouts |

### Nav Changes

New nav items added across all pages:

```
Home | Events | Alerts | Cases | Rules | Parsers | Audit Log | Configuration
                          ↑ new
```

Configuration page gains new sections: Log Sources, Integrations, Baselines, Dashboard.

---

## What Is Explicitly Out of Scope

- SBOM/dependency vulnerability scanning UI (a static `/sbom` endpoint is sufficient)
- Real-time push notifications (SSE, WebSockets) — polling is fine
- Case SLA timers or escalation policies
- Multi-tenant / organization isolation
- Sigma rule format
- Slack/PagerDuty alert destinations (webhook already covers this)
- Drag-and-drop query builder for dashboard widgets
- ML models (Isolation Forest, ARIMA, etc.) — statistical z-score only

---

## Version Milestones

### v1.0 — Core SOC Operations
- Cases: create from alert, threaded comments, assignee, mandatory resolution
- Log Sources: inferred activity view, health status, events-per-period chart
- UI polish: nav updated, Cases page, Sources page

### v1.1 — Intelligence Layer
- Smart Baselines: per-source, per-hour-of-day z-score computation + violation alerts
- AI Enrichment: schema + context injection for parser gen, rule gen + 2 new AI functions (MITRE mapping, log analysis)
- UI polish: Baselines section in dashboard, enriched AI panels

### v1.2 — Extensibility
- API Integrations: AWS CloudTrail + Google Workspace pollers, Fernet credential store, integration health UI
- Custom Dashboard: widget grid (6 pre-built widget types), layout persistence, PDF/HTML export
- UI polish: Integrations page, Dashboard builder page

### v1.3 — Guided Response (shipped)
- Playbooks: structured YAML response steps on rules, snapshotted into alerts, case Playbook tab with step completion, AI generate + refine
- Alert Enrichment: tabbed alert modal (Alert | Logs | Rule), triggering-log view, rule condition view, escalate-to-case flow
- Specs: [2026-07-02-playbook-triage-design.md](../superpowers/specs/2026-07-02-playbook-triage-design.md), [2026-07-02-alert-enrichment-design.md](../superpowers/specs/2026-07-02-alert-enrichment-design.md)

### v1.4 — "Hardened Tiny" (approved design)

Security controls are **mandatory features** of this release, not nice-to-haves. Zero new Python dependencies; one large dependency removed. Full spec: [2026-07-08-v1.4-hardening-design.md](../superpowers/specs/2026-07-08-v1.4-hardening-design.md)

**Track A — Mandatory security controls**
- A1 Login brute-force lockout (in-memory, exponential backoff; the only carve-out from the no-rate-limiting rule)
- A2 Forced password change for seeded superadmin + 12-char minimum password policy
- A3 Token revocation via per-user `token_epoch` + `POST /auth/logout`
- A4 Global API key scoped to `/ingest/*` only (breaking change)
- A5 Syslog listener source-CIDR allowlist + message size cap + drop counters in `/health`
- A6 Content-Security-Policy header + self-hosted IBM Plex fonts (zero external requests, air-gap friendly)
- A7 CORS default same-origin; `TINYSIEM_CORS_ORIGINS` override (breaking change)
- A8 Built-in TLS via `TINYSIEM_TLS_CERT`/`TINYSIEM_TLS_KEY`
- A9 Startup guardrails: refuse weak JWT secret, warn on default superadmin password / missing master key
- A10 Static `/sbom` endpoint

**Track B — SOC quality of life**
- B1 Alert suppression window per rule + entity (`suppress_seconds`, alert-fatigue control)
- B2 Self-monitoring: audit events feed the detection pipeline as `tinysiem_internal` + built-in brute-force rule
- B3 Backup endpoint (DuckDB export + alerts + custom YAML) with documented restore

**Track C — Footprint reduction**
- C1 Remove chromadb entirely (largest image-size win; nothing reads from it)

**Considered and deferred to v1.5+:** TOTP/2FA, optional-extras split for boto3/google-api-python-client, audit-log hash chaining
