# UI Navigation Shell Redesign — Design

> Status: Approved design
> Date: 2026-07-13
> Sub-project A of a 3-part effort (A: this spec — nav shell + Settings/Profile/Dashboard reorg; B: AI provider abstraction layer, spec pending; C: Home AI-search page, spec pending, depends on A + B)

## Context

The current TinySIEM UI uses a fixed ~220px left sidenav duplicated verbatim across all 10 `ui/*.html` pages, with 8 top-level items (Home, Events, Alerts, Cases, Rules, Parsers, Audit Log, Configuration). The user, running TinySIEM in a SOC on ultrawide monitors where events/alerts often contain very long raw log lines, wants that horizontal space back, and wants the overall visual language to move toward the clean, minimalist, search-first style of GreyNoise's homepage — starting with the navigation chrome itself.

This spec covers **Sub-project A only**: the shared navigation shell, the Profile menu, the Settings page reorganization, and relocating the existing Dashboard. It deliberately excludes:
- A new AI-powered search homepage (**Sub-project C** — depends on this spec plus Sub-project B)
- Multi-provider AI backend support (**Sub-project B** — independent, ships before C)
- Restyling the *content* of Events/Alerts/Cases/Rules/Parsers/Audit/Settings-panels/Users (a later phase, once this shell ships and the pattern is validated)
- Dashboard enhancements — a time-range picker and clickable pivot-to-entity charts (explicitly deferred by the user as a stretch goal)

Constraints carried over from the project charter: zero new Python dependencies, no build-step frontend framework, DuckDB + single-file HTML pages only. This spec adds no backend dependencies at all — it is almost entirely a frontend + one backend role-check change.

## Information Architecture

**New top nav bar**, replacing the left sidenav on every page:

```
[Shield logo → /ui/home.html]   Dashboard   Events   Alerts   Cases   Rules   Parsers        [theme toggle]  [Avatar ▾]
```

- **Home** (`/ui/home.html`, new, Sub-project C): the AI search landing page. `/` and the post-login redirect both point here instead of `/ui/dashboard.html`. Not itself a nav-bar link — reached via the logo, matching the mockup.
- **Dashboard** (`/ui/dashboard.html`, unchanged content): now a normal top-nav item, positioned immediately after the logo. Still the existing editable-widget page; no functional changes in this spec.
- **Events, Alerts, Cases, Rules, Parsers**: unchanged pages, now reached via the horizontal nav instead of the sidenav. No content changes.
- **Configuration → Settings**: removed from the top nav entirely. Reached only via Profile ▾ → Settings. The existing `ui/configuration.html` file is renamed `ui/settings.html` (all internal links/tests referencing `configuration.html` updated accordingly). Content unchanged except for the tab reorganization below.
- **Audit Log**: removed from the top nav. Reached only via Profile ▾ → Audit Log, and that menu item is rendered *only* when the logged-in user's role is `superadmin` (checked client-side the same way other role-gated buttons already work in this codebase, e.g. `if(S.role==='admin'||S.role==='superadmin')`). The backend tightens from `require_admin` to `require_superadmin` on every `/audit*` endpoint — see Breaking Changes below.
- **Users** (`/ui/users.html`): unchanged. Still reached via the existing "Manage Users" link inside Settings → Users & Access tab, not a top-level nav item.

## Shared `nav.js` + `nav.css`

Every page today copies the same sidenav HTML block and several JS helper functions (`parseJwt`, `clearAuth`, `logout`, `updateNavUser`, `toggleNav`, `applyNav`, `toggleTheme`) into its own `<script>` block. This redesign touches that block in all 10 files regardless, so it's extracted once:

- **`ui/nav.css`** — all top-nav bar, profile-dropdown, and Settings-tab-strip styling. Uses the existing CSS custom properties (`--bg`, `--surface`, `--surface2`, `--surface3`, `--border`, `--border2`, `--text`, `--text-dim`, `--text-muted`, `--accent`, `--accent-dim`, IBM Plex Sans/Mono) already defined per-page today, so dark/light theming and the existing visual identity carry over unchanged — this redesign changes *layout*, not the color system.
- **`ui/nav.js`** — on `DOMContentLoaded`, reads `ts_jwt`/`ts_ep` from `localStorage` (same as today), redirects to `/ui/login.html` if missing/expired (same as today), then injects the nav bar markup into a `<div id="nav-root"></div>` placeholder each page includes near the top of `<body>`. It also:
  - Highlights the active nav item by comparing `location.pathname` against each link's `href`.
  - Renders the Profile dropdown (username, role, Settings, Audit Log conditionally, Sign out) and wires its open/close toggle.
  - Exposes `logout()` (calls `POST /auth/logout` then clears storage and redirects — preserving the v1.4 fix), `parseJwt()`, `clearAuth()`, and the theme toggle, so no page needs its own copy of these anymore.
  - Each page still owns its own `S` state object, API calls, and page-specific logic entirely unchanged; `nav.js` only owns the chrome.

Each of the 10 pages changes in the same mechanical way: delete the local sidenav markup and the now-shared JS functions, add `<div id="nav-root"></div>`, add `<link rel="stylesheet" href="nav.css">` and `<script src="nav.js"></script>`.

One accepted tradeoff: there's a brief instant before `nav.js` runs where the nav area is empty. This matches the existing pattern where every page's *content* also loads asynchronously after the auth check — not a new class of loading behavior.

## Settings Page Reorganization

`ui/configuration.html` → `ui/settings.html`. Its 9 existing sections (Instance Info, Users & Access, Alert Notifications, Log Retention, Log Ingestion, Smart Baselines, Integrations, Log Sources, Reports) currently stack vertically on one long-scrolling page. This spec adds a horizontal tab strip at the top of the content area:

```
[ Instance | Users & Access | Notifications | Retention | Ingestion | Baselines | Integrations | Sources | Reports ]
```

Clicking a tab swaps the panel shown below it; only one section's content is visible at a time, eliminating the long scroll. Each panel's *internal* fields, buttons, and behavior are unchanged — this is purely a navigation-within-the-page change, styled via `nav.css`'s new tab-strip classes.

## Profile Dropdown

Top-right avatar (accent-colored rounded square, first letter of username, e.g. "A" for `admin` — matching the provided mockup exactly), always visible, next to a separate theme-toggle icon button (not nested inside the dropdown — matches the mockup). Clicking the avatar opens:

```
admin
superadmin
─────────────
⚙ Settings
▤ Audit Log        (superadmin only)
─────────────
⇥ Sign out
```

## Dashboard Relocation

`ui/dashboard.html` itself is untouched in this spec — same widgets, same edit mode, same 60s auto-refresh. The only change is where it's reached from: a "Dashboard" top-nav item instead of being the default landing page.

Root `/` and the post-login redirect move to `/ui/home.html`. Since Sub-project C (the AI search itself) hasn't shipped yet, this spec includes a minimal **stub** `/ui/home.html`: the shared nav shell, the centered shield/title/subtitle, and the search input — rendered but disabled/inert (e.g. `disabled` attribute, a "Coming soon" placeholder instead of a working submit), with no backend call wired up. This keeps the redirect target stable across both specs instead of migrating it twice, and gives Sub-project C a page to build into rather than create from scratch.

## Breaking Change: Audit Log now superadmin-only

`GET /audit`, `GET /audit/facets`, and any other `/audit*` endpoints currently gated with `require_admin` change to `require_superadmin`. A user with the `admin` role (not `superadmin`) loses API access to audit data entirely, not just the nav link. This is a deliberate, user-confirmed security tightening, consistent with this project's precedent of calling out breaking auth changes explicitly (matching v1.4's A4/A7 pattern in `CLAUDE.md`).

**Test impact:** `app/tests/test_audit.py` currently has a test asserting `admin_headers` can access `/audit`; that assertion flips to expect `403`, and a new/adjusted test confirms `superadmin_headers` still succeeds.

## Testing Approach

This is almost entirely a frontend change with no new backend endpoints (only the audit role tightening touches the backend). Verification is:
- **Backend:** update `test_audit.py` for the role change; run the full suite to confirm no other regressions.
- **Frontend (manual, live browser):** click through all 10 pages confirming: nav renders and highlights the correct active item; Profile dropdown opens/closes and shows/hides Audit Log correctly per role (test with an admin-role and a superadmin-role login); Settings tab strip switches panels correctly; Dashboard is reachable from the nav and unchanged; login → lands on the new default page; logout still correctly calls `/auth/logout` before clearing; theme toggle still persists via `localStorage`.

## Out of Scope (confirmed deferred)

- Visual restyle of existing page *content* (Events/Alerts/Cases/Rules/Parsers/Audit/Settings-panel-internals/Users) — future phase(s), one page at a time, once this shell is validated in daily use.
- Dashboard enhancements (time-range picker, clickable pivot-to-entity-view charts) — future phase.
- AI provider abstraction (Sub-project B) and the Home AI search itself (Sub-project C) — separate specs, B ships before C.
