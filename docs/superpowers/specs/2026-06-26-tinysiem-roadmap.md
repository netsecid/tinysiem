# TinySIEM — Product Roadmap

**Date:** 2026-06-26
**Target:** v1.0 on-premise release
**Deployment model:** Self-hosted, single-tenant per customer (not SaaS)

---

## Vision

A small, minimalist, AI-native SIEM that works. Simple enough to deploy and manage without a dedicated ops team. Powerful enough for a real SOC workflow. Parsers and detection rules can be created through a coding agent (Claude Code or similar) using built-in skills — paste a log sample, get a working decoder and rule.

---

## Roles

Three tiers, enforced across all API endpoints and UI pages from v0.5 onward:

| Capability | Superadmin | Admin / Sec Eng | SOC Analyst |
|---|---|---|---|
| Manage users, roles, API keys | ✓ | — | — |
| Create / edit / delete parsers & rules | ✓ | ✓ | — |
| Ingest logs (API) | ✓ | ✓ | — |
| View events, alerts, dashboard | ✓ | ✓ | ✓ |
| Export data | ✓ | ✓ | ✓ |
| Archive / retention config | ✓ | — | — |
| Use MCP tools | ✓ | ✓ | ✓ |

---

## Phases

### Phase 1 — v0.4: Visual Foundation *(current)*

**Goal:** Nail the UX before adding any more features. Everything else builds on this layout.

- Collapsible left nav sidebar (Home / Events / Alerts / Rules / Parsers / Configuration)
- Dashboard page — threat posture: stat cards, severity breakdown, event volume chart, recent high/critical alerts, top IPs, top rules
- Visual refresh across Events and Alerts pages — card panels, locked severity palette, better table density
- Shell pages for Rules, Parsers, Configuration (nav wired, content placeholder)
- No new backend endpoints

*Full spec:* `docs/superpowers/specs/2026-06-26-v04-visual-foundation-design.md`

---

### Phase 2 — v0.5: Auth & Access Control

**Goal:** Make it safe to hand to a real team.

- Username/password login with session tokens (JWT or signed cookie)
- 3-tier role enforcement on all existing API endpoints
- User management UI (Superadmin only): create/edit/delete users, assign roles, generate API keys
- Login page, logout, session expiry
- Wire user avatar + name into nav sidebar (placeholder added in v0.4)
- Configuration page: basic instance settings (retention window, alert thresholds, SMTP config)

---

### Phase 3 — v0.6: AI-Native

**Goal:** The primary differentiator. Parsers and rules should take minutes, not hours.

- **In-app parser generator** — paste a raw log sample, call Claude API, receive a decoder YAML preview, review and save. Populates the Parsers page.
- **In-app rule builder** — describe a detection behavior in plain English, call Claude API, receive a rule YAML preview, review and save. Populates the Rules page.
- **Rules page** — list, view, enable/disable, delete YAML rules
- **Parsers page** — list, view, test against a sample, enable/disable, delete YAML decoders
- **MCP server** — exposes structured tools for coding agents:
  - `query_events` — search events with filters
  - `query_alerts` — search alerts with filters
  - `create_decoder` — generate and save a decoder YAML from a log sample
  - `create_rule` — generate and save a rule YAML from a description
  - `test_decoder` — test a decoder YAML against a provided log sample
  - Role-scoped: all 3 roles can query; only Admin+ can create/modify

---

### Phase 4 — v0.7: Operations

**Goal:** Make it production-grade for a real deployment.

- **Log retention** — 30-day online window in DuckDB; events older than 30 days auto-archived to compressed JSONL files, split by size, named with timestamp (`archive-2026-05-01T00:00:00-500mb.jsonl.gz`). Configurable window.
- **Alert notifications** — email and webhook per rule or per severity threshold. Configured via Configuration page. Templates for subject/body.
- **Alert triage workflow** — status field on alerts: `open → investigating → resolved`. Add notes, optionally assign to a user. Visible on Alerts page and dashboard.
- **Scheduled reports** — daily/weekly digest: alert summary, top source IPs, top triggered rules, event volume trend. Delivered via email or downloadable as PDF.

---

### Phase 5 — v0.8: Ecosystem

**Goal:** Support real log sources and more sophisticated detection.

- **Built-in decoders** — syslog (RFC 3164 + 5424), Windows Event Log (XML/JSON), AWS CloudTrail, common firewall formats
- **Log shipper / listener** — syslog UDP/TCP receiver built into TinySIEM (port configurable); Beats-compatible HTTP endpoint for Filebeat/Winlogbeat
- **Multi-source correlation rules** — rule conditions that join events across multiple sources within a time window (e.g., "failed login on Windows followed by outbound connection from same IP within 60s")

---

### v1.0 — Release

**Goal:** Packaged, documented, and shippable to customers.

- Installer / packaging for on-premise deployment (Docker Compose + setup script)
- Admin setup wizard (first-run: set API key, create superadmin, configure SMTP)
- User-facing documentation (quick start, decoder authoring, rule authoring, MCP integration guide)
- End-to-end tested with at least 3 real log sources

---

## Backlog / Deferred

These are explicitly out of scope until after v1.0:

- Real-time SSE log tailing (polling is sufficient)
- Multi-tenant / SaaS mode
- LDAP / SSO integration
- Threat intelligence feed integration
- Asset / host inventory management
- Sigma rule format compatibility
- React / Vue / any build-step frontend framework
- Rate limiting
- Log retention purge (deletion is manual or via archive tooling)
