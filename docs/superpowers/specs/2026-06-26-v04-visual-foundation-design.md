# TinySIEM v0.4 — Visual Foundation Design Spec

**Date:** 2026-06-26
**Phase:** 1 of 5
**Status:** Approved

---

## Goal

Ship the visual foundation that all future phases build on: a collapsible left-nav layout, a threat-posture dashboard, and a unified design language applied across all existing pages. No new backend endpoints required.

---

## Design Language

### Theme
- Dark-first (refined, not raw). Dark mode is primary; light mode stays as an option.
- Background layers: `--bg-base` (darkest) → `--bg-card` (panels, slightly lighter) → `--bg-hover` (interactive hover states)
- All colors via CSS custom properties; `[data-theme="light"]` overrides the same set of variables

### Typography
- **IBM Plex Sans** — all UI chrome: labels, headings, nav items, button text, descriptions
- **IBM Plex Mono** — data values only: IPs, timestamps, raw log lines, counts, hashes

### Severity Palette (locked across all pages and components)
| Severity | Color | Hex |
|---|---|---|
| critical | red | `#ef4444` |
| high | orange | `#f97316` |
| medium | amber | `#eab308` |
| low | blue | `#3b82f6` |

Severity dots, badges, and card accents all use this palette. No exceptions.

### Cards & Panels
- `1px` border in a slightly lighter shade than the card background (`--border-subtle`)
- `6–8px` border-radius
- Consistent `16–20px` internal padding

### Tables
- More row padding than current (comfortable density, not cramped)
- Clean hover state using `--bg-hover`
- Sticky header retained from current implementation

---

## Layout

### Left Navigation Sidebar

Replaces the current top nav bar on all pages.

**Expanded state (~220px wide)**
- TinySIEM logo + wordmark at the top
- Nav items: icon + label, vertically stacked
- Active item: colored left-border accent + `--bg-hover` background
- Bottom of sidebar: theme toggle + user avatar placeholder (name/role wired in v0.5)
- Collapse toggle: `‹` chevron button at the bottom or top-right edge of sidebar

**Collapsed state (~56px wide)**
- Logo collapses to icon mark only
- Nav items: icon only, centered
- Tooltips on hover reveal the label
- Collapse toggle: `›` chevron

**Nav items (in order)**
1. Home (dashboard icon)
2. Events
3. Alerts
4. Rules *(shell only — no content until v0.6)*
5. Parsers *(shell only — no content until v0.6)*
6. Configuration *(shell only — no content until v0.5)*

**Persistence**
- Collapsed/expanded state saved to `localStorage` key `ts_nav_collapsed`
- Default: expanded
- Auto-collapses on screens < 768px

### Main Content Area

Fills remaining width to the right of the left nav.

**Slim topbar (across main content only)**
- Left: page title
- Center: context-aware search bar (present on Events and Alerts; absent on Dashboard)
- Right: Refresh button + last-refreshed timestamp

**Secondary sidebar (Events and Alerts pages only)**
- Facets/filter sidebar (232px) — existing behavior retained, sits between left nav and main panel
- Full layout: `[left nav] [facets 232px] [main panel flex-1]`

**Dashboard and shell pages**
- No secondary sidebar — full main content width used

---

## Dashboard Page (`ui/dashboard.html`)

Primary story: **threat posture** — is anything on fire right now, and what does recent activity look like?

### Row 1 — Stat Cards (4 cards, equal width)

| Card | Value | Detail |
|---|---|---|
| Total Events | count, last 24h | sourced from `/events` with `start=now-24h` |
| Total Alerts | count, last 24h | sourced from `/alerts` with `start=now-24h` |
| Critical Alerts | count, last 24h | sourced from `/alerts?severity=critical&start=now-24h` |
| High Alerts | count, last 24h | sourced from `/alerts?severity=high&start=now-24h` |

Critical and High cards get a colored left-border accent (red and orange respectively) so they jump visually. All other cards use `--border-subtle`.

### Row 2 — Two Panels

**Left (40%): Alert Severity Breakdown**
- One horizontal bar per severity: critical / high / medium / low
- Each bar: colored dot + label + count + proportion bar (same pattern as existing facet sidebar but larger)
- Data from `GET /alerts/facets`
- Clicking a severity row navigates to Alerts page pre-filtered to that severity

**Right (60%): Event Volume (24h)**
- Bar chart using Chart.js (same library already used on Events page)
- Data from `GET /events/histogram?start=now-24h&end=now&buckets=48`
- Shows whether log ingestion is healthy or has gaps
- X-axis: time, Y-axis: event count

### Row 3 — Two Panels

**Left (60%): Recent High/Critical Alerts**
- Last 10 alerts where severity is `high` or `critical`
- Columns: triggered time | rule name | severity badge | source IP | summary
- Data from two calls — `GET /alerts?severity=critical&limit=5` and `GET /alerts?severity=high&limit=5` — merged and sorted newest-first client-side
- Each row is clickable → navigates to Alerts page pre-filtered to that rule/IP
- Empty state: green "No high or critical alerts in the last 24h" message

**Right (40%): Two stacked mini-tables**

*Top Source IPs (top 5 by event count)*
- Data from `GET /events/facets` → `source_ip` array, top 5
- Columns: IP address | event count
- Clicking an IP navigates to Events page pre-filtered to that IP

*Top Triggered Rules (top 5 by alert count)*
- Data from `GET /alerts/facets` → `rule_name` array, top 5
- Columns: rule name | alert count
- Clicking a rule navigates to Alerts page pre-filtered to that rule

---

## Shell Pages

Rules, Parsers, and Configuration nav items are wired up and navigate to placeholder pages. Each placeholder shows:
- Page title
- A short description of what the page will do (one sentence)
- "Coming in a future version" notice

No backend work required for these.

---

## Affected Files

| File | Change |
|---|---|
| `ui/events.html` | Remove top nav; add left nav sidebar; apply visual refresh (cards, severity palette, table spacing) |
| `ui/alerts.html` | Remove top nav; add left nav sidebar; apply visual refresh |
| `ui/dashboard.html` | New file |
| `ui/rules.html` | New file (shell) |
| `ui/parsers.html` | New file (shell) |
| `ui/configuration.html` | New file (shell) |

The left nav sidebar HTML + CSS will be duplicated across all HTML files (no build step, no framework). Extract shared styles into a common `<style>` block pattern — copy-paste is acceptable given the no-framework constraint.

---

## API Usage (no new endpoints)

| Dashboard widget | Endpoint |
|---|---|
| Total Events 24h | `GET /events?start=<24h-ago>&limit=0` → `total` field |
| Total Alerts 24h | `GET /alerts?start=<24h-ago>&limit=0` → `total` field |
| Critical/High alert counts | `GET /alerts?severity=critical&start=<24h-ago>&limit=1` → `total`, repeated for high |
| Severity breakdown | `GET /alerts/facets` |
| Event volume chart | `GET /events/histogram?start=<24h-ago>&end=<now>&buckets=48` |
| Recent high/critical alerts | `GET /alerts?severity=critical&limit=5`, `GET /alerts?severity=high&limit=5` |
| Top source IPs | `GET /events/facets` → `source_ip` |
| Top triggered rules | `GET /alerts/facets` → `rule_name` |

---

## State & Persistence (`localStorage`)

| Key | Value |
|---|---|
| `ts_nav_collapsed` | `true` / `false` |
| `ts_theme` | `dark` / `light` (existing) |
| `ts_ep` | API endpoint URL (existing) |
| `ts_key` | API key (existing) |

---

## Out of Scope for This Phase

- Auth, login, user management (v0.5)
- Rules and Parsers page content (v0.6)
- Configuration page content (v0.5)
- Any new backend endpoints
- Real-time / SSE updates (polling is fine)
