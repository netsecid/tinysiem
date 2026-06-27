# TinySIEM v0.6 — AI-Native Design Spec

**Date:** 2026-06-27
**Status:** Approved for implementation
**Builds on:** v0.5 Auth & Access Control (JWT, role hierarchy, DuckDB user store)

---

## Overview

v0.6 makes parsers and rules first-class, editable objects. Instead of static YAML files baked into the container, they live as files on disk that the app can read, write, and reload at runtime. A Claude API integration generates YAML from natural language or log samples. A built-in MCP server exposes structured tools so coding agents (Claude Code, etc.) can query and manage the SIEM programmatically.

---

## Section 1 — Architecture

Four-layer stack:

```
┌─────────────────────────────────────────────────────────────┐
│  UI Layer         parsers.html          rules.html           │
│  (vanilla HTML)   list + YAML editor   list + YAML editor   │
│                   AI generator panel   AI generator panel    │
│                   test panel                                  │
└───────────────────────────┬─────────────────────────────────┘
                            │ REST
┌───────────────────────────▼─────────────────────────────────┐
│  API Layer        /parsers  CRUD + generate + test           │
│  (FastAPI)        /rules    CRUD + generate                  │
│                   /mcp      MCP server (SSE)                 │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  AI Layer         app/ai/claude.py                           │
│  (Anthropic SDK)  generate_parser(log_sample) → YAML        │
│                   generate_rule(description) → YAML          │
│                   Validates structure before returning        │
└───────────────────────────┬─────────────────────────────────┘
                            │
┌───────────────────────────▼─────────────────────────────────┐
│  Storage Layer    app/decoder/decoders/*.yaml  (built-in)    │
│  (YAML on disk)   app/decoder/decoders/custom/*.yaml         │
│                   app/rules/*.yaml             (built-in)    │
│                   app/rules/custom/*.yaml                    │
└─────────────────────────────────────────────────────────────┘
```

Hot reload: after any write to disk, the relevant engine (`decoder_engine.load_decoders()` or `rule_engine.load_rules()`) is called under the existing `threading.Lock()` so the running container picks up changes without restart.

---

## Section 2 — File Structure & Naming

### Naming convention

All YAML files use kebab-case: `{source}-{description}.yaml`

- Decoder example: `nginx-access.yaml`, `apache-access.yaml`, `syslog-rfc3164.yaml`
- Rule example: `nginx-http-404-spike.yaml`, `nginx-http-500-error.yaml`, `ssh-brute-force.yaml`

The `{source}` prefix lets users instantly see which log source a file applies to. Cross-referencing a rule to its decoder is instant: if a rule fires on source `nginx`, the decoder is `nginx-*.yaml`.

### Migration (existing files)

These renames happen in Task 1:

| Current | New |
|---|---|
| `app/decoder/decoders/nginx_access.yaml` | `app/decoder/decoders/nginx-access.yaml` |
| `app/rules/http_404_spike.yaml` | `app/rules/nginx-http-404-spike.yaml` |
| `app/rules/http_500_error.yaml` | `app/rules/nginx-http-500-error.yaml` |

The engines already load `*.yaml` by glob, so no code change is needed for the rename — only the files themselves and any hardcoded references in tests.

### Directory layout (v0.6 additions)

```
app/
  decoder/
    decoders/
      nginx-access.yaml           ← renamed built-in
      custom/                     ← new; user-created parsers land here
  rules/
    nginx-http-404-spike.yaml     ← renamed built-in
    nginx-http-500-error.yaml     ← renamed built-in
    custom/                       ← new; user-created rules land here
  parsers/
    router.py                     ← new; /parsers endpoints
  rules_router/
    router.py                     ← new; /rules endpoints (separate from existing rule engine)
  ai/
    __init__.py
    claude.py                     ← new; Anthropic SDK client + generate functions
  mcp_server/
    __init__.py
    server.py                     ← new; MCP tool definitions + FastAPI mount
```

**Note on naming collision:** The existing `app/rules/` directory contains the rule engine (`engine.py`, `__init__.py`) plus rule YAML files. The new CRUD router lives in `app/rules_router/router.py` to avoid shadowing the existing module. The router is imported in `main.py` as `rules_crud_router`.

---

## Section 3 — Backend API

### Parsers endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/parsers` | analyst+ | List all parsers (built-in + custom). Returns metadata: `name`, `source`, `is_custom`, `path`. |
| `GET` | `/parsers/{name}` | analyst+ | Return full YAML text for the named parser. |
| `POST` | `/parsers` | admin+ | Create new parser. Body: `{name, yaml_text}`. Saves to `custom/{name}.yaml`. Reloads decoder engine. |
| `PUT` | `/parsers/{name}` | admin+ | Update existing parser. Only allowed for custom parsers (built-ins are read-only). Saves and reloads. |
| `DELETE` | `/parsers/{name}` | admin+ | Delete custom parser. Built-ins return 403. Reloads decoder engine. |
| `POST` | `/parsers/generate` | admin+ | Body: `{log_sample: str}`. Calls Claude API, returns `{yaml_text, preview: true}`. Does NOT save. |
| `POST` | `/parsers/{name}/test` | analyst+ | Body: `{log_line: str}`. Runs the named parser against one log line. Returns `{matched: bool, fields: dict}`. |

### Rules endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/rules` | analyst+ | List all rules. Returns metadata: `name`, `severity`, `source`, `is_custom`, `path`. |
| `GET` | `/rules/{name}` | analyst+ | Return full YAML text for the named rule. |
| `POST` | `/rules` | admin+ | Create new rule. Body: `{name, yaml_text}`. Saves to `custom/{name}.yaml`. Reloads rule engine. |
| `PUT` | `/rules/{name}` | admin+ | Update existing rule. Only allowed for custom rules. Saves and reloads. |
| `DELETE` | `/rules/{name}` | admin+ | Delete custom rule. Built-ins return 403. Reloads rule engine. |
| `POST` | `/rules/generate` | admin+ | Body: `{description: str, source: str}`. Calls Claude API, returns `{yaml_text, preview: true}`. Does NOT save. |

### YAML validation on write

`POST /parsers` and `PUT /parsers/{name}` run a basic structural check on the submitted YAML before saving:
- Must parse as valid YAML (`yaml.safe_load`)
- Must have required top-level keys: `name`, `source`, `type`, `pattern`, `fields`
- Returns 422 with a descriptive error if invalid

Same for rules: required keys `name`, `severity`, `source`, `condition`.

### Hot reload

After every write or delete, the relevant engine is called:
- Parsers: `decoder_engine.load_decoders()` under `decoder_engine._lock`
- Rules: `rule_engine.load_rules()` under `rule_engine._lock`

Both engines already load from directory globs, so they pick up `custom/` automatically once the `custom/` subdirectory is included in the glob pattern.

---

## Section 4 — AI Integration

### Module: `app/ai/claude.py`

```python
import anthropic
from app.config import settings

_client: anthropic.Anthropic | None = None

def get_client() -> anthropic.Anthropic:
    global _client
    if _client is None:
        if not settings.tinysiem_claude_api_key:
            raise RuntimeError("TINYSIEM_CLAUDE_API_KEY not set")
        _client = anthropic.Anthropic(api_key=settings.tinysiem_claude_api_key)
    return _client

def generate_parser(log_sample: str) -> str:
    response = get_client().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=2048,
        system=PARSER_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": log_sample}]
    )
    return response.content[0].text

def generate_rule(description: str, source: str) -> str:
    response = get_client().messages.create(
        model="claude-sonnet-4-6",
        max_tokens=1024,
        system=RULE_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": f"Source: {source}\n\n{description}"}]
    )
    return response.content[0].text
```

### Model

`claude-sonnet-4-6` — explicitly approved for this project. Fast enough for interactive use, capable enough for YAML generation tasks.

### System prompts

`PARSER_SYSTEM_PROMPT` embeds:
- The decoder YAML format from CLAUDE.md verbatim
- A worked example (nginx-access.yaml)
- Instruction to return only the YAML block, no prose, no fences

`RULE_SYSTEM_PROMPT` embeds:
- The rule YAML format from CLAUDE.md verbatim
- A worked example
- Available severity values, operator values
- Instruction to return only the YAML block

### Error handling

- No `TINYSIEM_CLAUDE_API_KEY` → `/parsers/generate` and `/rules/generate` return `503 Service Unavailable` with `{"detail": "AI features require TINYSIEM_CLAUDE_API_KEY"}`
- `anthropic.APIError` → return 502 with the error message
- Generated YAML that fails structural validation → return 422 with `{"detail": "Generated YAML failed validation", "errors": [...], "raw": "<yaml>"}`

### What generate endpoints return

```json
{
  "yaml_text": "name: nginx-access\nsource: nginx\n...",
  "preview": true
}
```

The UI shows this in a read-only editor. The user reviews it, optionally edits, then clicks Save to call `POST /parsers` or `POST /rules` with the final YAML.

---

## Section 5 — MCP Server

### Purpose

Expose structured tools so coding agents (Claude Code, Claude Desktop, etc.) can query TinySIEM data and manage parsers/rules without scraping the UI or calling raw REST endpoints.

### Tools (5)

| Tool | Description | Auth |
|---|---|---|
| `list_events` | Search events. Params: `source`, `source_ip`, `status_code`, `q`, `start`, `end`, `limit`. Returns event list. | analyst+ |
| `get_alerts` | Search alerts. Params: `severity`, `rule_name`, `source_ip`, `q`, `start`, `end`, `limit`. Returns alert list. | analyst+ |
| `list_parsers` | List all parsers with name, source, is_custom. | analyst+ |
| `list_rules` | List all rules with name, severity, source, is_custom. | analyst+ |
| `get_health` | Return `{status, version, event_count, alert_count}`. | analyst+ |

### Implementation

- Module: `app/mcp_server/server.py`
- Library: `mcp[server]==1.0.0` — uses `FastMCP` class or the raw `Server` + ASGI adapter
- Mounted at `/mcp` in `main.py`: `app.mount("/mcp", mcp_app)`
- Runs in the same process as FastAPI — no separate container or port
- Auth: `Authorization: Bearer <jwt>` header, validated by the same `require_role("analyst")` dependency
- Enabled only when `TINYSIEM_MCP_ENABLED=true` (default: false); if disabled, `/mcp` returns 404

### MCP client connection (usage)

```
Server URL: http://localhost:8000/mcp
Auth header: Bearer <jwt>
Transport: SSE (default for FastMCP ASGI)
```

---

## Section 6 — UI

### parsers.html

Layout mirrors `users.html` (table + action panel):

```
┌─────────────────────────────────────────────────────┐
│  Nav sidebar (same as all pages)                    │
│  Parsers                                  [+ New]   │
├──────────────────────┬──────────────────────────────┤
│  Parser list table   │  Selected parser panel       │
│  Name | Source | ... │  ┌──────────────────────┐   │
│  nginx-access   ●    │  │ YAML editor (textarea)│   │
│  my-custom      ◐    │  └──────────────────────┘   │
│                      │  [Save]  [Delete]            │
│                      │                              │
│                      │  ── Test ──────────────────  │
│                      │  Log line: [____________]    │
│                      │  [Test]  → matched fields    │
│                      │                              │
│                      │  ── AI Generator ──────────  │
│                      │  Log sample: [textarea]      │
│                      │  [Generate with Claude]      │
│                      │  Preview: [readonly textarea] │
│                      │  [Use this YAML]             │
└──────────────────────┴──────────────────────────────┘
```

- Built-in parsers: YAML shown read-only, no Save/Delete
- Custom parsers: fully editable
- "Use this YAML" copies generated YAML into the editor; user can still edit before saving
- Role gate: if `role === 'analyst'`, hide New/Save/Delete/Generate buttons

### rules.html

Same two-panel layout. No test panel (rules evaluate against stored events, not a single line).

```
┌─────────────────────────────────────────────────────┐
│  Nav sidebar                                        │
│  Rules                                    [+ New]   │
├──────────────────────┬──────────────────────────────┤
│  Rule list table     │  Selected rule panel         │
│  Name | Severity|... │  ┌──────────────────────┐   │
│  nginx-404-spike M   │  │ YAML editor (textarea)│   │
│  my-custom-rule  H   │  └──────────────────────┘   │
│                      │  [Save]  [Delete]            │
│                      │                              │
│                      │  ── AI Generator ──────────  │
│                      │  Source: [input]             │
│                      │  Describe detection:         │
│                      │  [textarea]                  │
│                      │  [Generate with Claude]      │
│                      │  Preview: [readonly textarea] │
│                      │  [Use this YAML]             │
└──────────────────────┴──────────────────────────────┘
```

### Nav wiring

All existing pages (`dashboard.html`, `events.html`, `alerts.html`, `users.html`, `login.html`) have nav items for Parsers and Rules already in the sidebar HTML (added in v0.4). In v0.6, those links get `href` values wired to `/ui/parsers.html` and `/ui/rules.html`.

### Design system

Same as all existing pages: IBM Plex Sans + IBM Plex Mono, CSS custom properties (`--bg`, `--surface`, `--accent`, etc.), dark/light theme via `data-theme` on `<html>`, no build step.

---

## Section 7 — Dependencies & Configuration

### New Python dependencies (add to requirements.txt)

```
anthropic==0.40.0
mcp[server]==1.0.0
```

### Updated config.py

```python
tinysiem_claude_api_key: str = ""          # optional; empty = AI features disabled
tinysiem_mcp_enabled: bool = False         # mount /mcp when true
tinysiem_version: str = "0.6.0"
```

### New docker-compose environment variables

```yaml
TINYSIEM_CLAUDE_API_KEY: ""        # set to real key to enable AI generation
TINYSIEM_MCP_ENABLED: "false"      # set to "true" to mount /mcp
```

`TINYSIEM_CLAUDE_API_KEY` is deliberately optional — the stack runs fine without it; the generate endpoints just return 503.

### Volume mount additions

No new volumes needed. Parser and rule YAML files live under `app/decoder/decoders/` and `app/rules/`, which are baked into the image. Custom files go in `custom/` subdirectories within those paths — these are inside the container and persist via the `tinysiem_data` named volume.

**Important:** `custom/` subdirectories must be writable by `appuser`. The Dockerfile must `mkdir` them and `chown` them before switching to `appuser`.

---

## Section 8 — Testing

### New test file: `app/tests/test_parsers.py`

- `test_list_parsers_returns_builtin` — GET /parsers returns at least one entry
- `test_create_parser_admin` — POST /parsers with valid YAML, admin token → 201
- `test_create_parser_analyst_forbidden` — POST /parsers with analyst token → 403
- `test_create_parser_invalid_yaml` — POST /parsers with malformed YAML → 422
- `test_get_parser` — GET /parsers/{name} returns YAML text
- `test_update_custom_parser` — PUT /parsers/{name} for custom parser → 200
- `test_update_builtin_parser_forbidden` — PUT /parsers/nginx-access → 403
- `test_delete_custom_parser` — DELETE /parsers/{name} → 204
- `test_parser_test_endpoint` — POST /parsers/nginx-access/test with sample log → matched=true, fields populated
- `test_generate_parser_no_api_key` — POST /parsers/generate with no API key configured → 503

### New test file: `app/tests/test_rules_crud.py`

Same pattern as test_parsers.py for rules endpoints.

### AI generation tests

AI generation (`/parsers/generate`, `/rules/generate`) is NOT tested against the real Claude API in the test suite — the generate endpoints are tested only for the "no API key" 503 path. Integration with Claude is tested manually.

---

## Implementation Order

Tasks should be executed in this sequence (each is independently reviewable):

1. **File rename + custom dirs** — rename existing YAML files to kebab-case, create `custom/` subdirectories, update engine glob patterns, update Dockerfile chown, update tests that reference old filenames
2. **Parsers CRUD API** — `app/parsers/router.py`, mount in main.py, tests in test_parsers.py (no AI, no hot reload yet)
3. **Rules CRUD API** — `app/rules_router/router.py`, mount in main.py, tests in test_rules_crud.py
4. **Hot reload** — wire `load_decoders()` / `load_rules()` calls after each write/delete in both routers
5. **AI integration** — `app/ai/claude.py` + generate endpoints in both routers + 503 test
6. **MCP server** — `app/mcp_server/server.py`, mount at `/mcp`, JWT auth wiring
7. **UI: parsers.html + rules.html** — both pages, nav wiring in all existing pages
8. **Final review** — security check (auth enforcement on all new endpoints, no path traversal in file writes, YAML only via safe_load)
