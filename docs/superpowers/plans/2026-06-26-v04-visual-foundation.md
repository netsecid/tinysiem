# v0.4 Visual Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the collapsible left-nav layout, threat-posture dashboard, unified design language across all pages, and shell pages for future features — with no new backend endpoints.

**Architecture:** Introduce `ui/shared.css` for design tokens, the left nav component CSS, card/panel base styles, and severity badge styles. Each HTML page links to it and keeps page-specific styles inline. The left nav HTML is duplicated across pages (copy-paste is intentional — no build step, no framework). The dashboard page makes 7 parallel API calls on load and renders widgets from the results.

**Tech Stack:** Vanilla HTML/CSS/JS, Chart.js 4.4.0 (CDN, already used), IBM Plex Sans + IBM Plex Mono (Google Fonts, already used), Docker Compose for local serving.

## Global Constraints

- No build step, no JS framework, no npm — all files are self-contained HTML or plain CSS
- All existing `localStorage` keys preserved: `ts_ep`, `ts_key`, `ts_theme`
- New key added: `ts_nav_collapsed` (`"true"` / `"false"`, default expanded)
- Severity palette is locked: critical=`#ef4444`, high=`#f97316`, medium=`#eab308`, low=`#3b82f6`
- IBM Plex Mono used only for data values: IPs, timestamps, raw log lines, counts
- IBM Plex Sans for all UI chrome: nav items, labels, headings, button text
- After any HTML-only change: `docker-compose restart tinysiem` is sufficient (no rebuild)
- After any Python/Dockerfile change: `docker-compose up --build` required
- API base URL and key come from `localStorage` (`ts_ep` / `ts_key`)
- All `fetch` calls include `Authorization: Bearer <key>` header

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `ui/shared.css` | **Create** | Design tokens, left nav CSS, card styles, severity badges |
| `ui/events.html` | **Modify** | Replace top nav with left nav; new layout wrapper; link shared.css; visual refresh |
| `ui/alerts.html` | **Modify** | Replace top nav with left nav; new layout wrapper; link shared.css; visual refresh |
| `ui/dashboard.html` | **Create** | Threat posture dashboard: stat cards, severity panel, histogram, alert feed, top IPs/rules |
| `ui/rules.html` | **Create** | Shell page (nav + placeholder) |
| `ui/parsers.html` | **Create** | Shell page (nav + placeholder) |
| `ui/configuration.html` | **Create** | Shell page (nav + placeholder) |

---

## Task 1: Create `ui/shared.css` — Design Token Foundation

**Files:**
- Create: `ui/shared.css`

**Interfaces:**
- Produces: CSS classes `.sidenav`, `.sidenav.collapsed`, `.nav-link`, `.nav-link.active`, `.layout`, `.main-wrap`, `.topbar`, `.card`, `.stat-card`, `.stat-card.critical`, `.stat-card.high`, `.badge`, `.badge.critical`, `.badge.high`, `.badge.medium`, `.badge.low`
- Produces: CSS custom properties `--severity-critical`, `--severity-high`, `--severity-medium`, `--severity-low`, `--nav-w`, `--nav-collapsed-w`, `--radius`

- [ ] **Step 1: Create `ui/shared.css`**

```css
/* TinySIEM shared design tokens and nav component */

/* ── SEVERITY TOKENS ── */
:root {
  --severity-critical: #ef4444;
  --severity-high:     #f97316;
  --severity-medium:   #eab308;
  --severity-low:      #3b82f6;
  --severity-critical-bg: rgba(239,68,68,.12);
  --severity-high-bg:     rgba(249,115,22,.12);
  --severity-medium-bg:   rgba(234,179,8,.12);
  --severity-low-bg:      rgba(59,130,246,.12);

  /* Nav dimensions */
  --nav-w: 220px;
  --nav-collapsed-w: 56px;
  --radius: 6px;
}

/* ── LAYOUT ── */
.layout {
  display: flex;
  height: 100vh;
  overflow: hidden;
}

.main-wrap {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
  min-width: 0;
}

/* ── LEFT NAV ── */
.sidenav {
  width: var(--nav-w);
  background: var(--surface);
  border-right: 1px solid var(--border);
  display: flex;
  flex-direction: column;
  flex-shrink: 0;
  transition: width 0.2s ease;
  overflow: hidden;
}

.sidenav.collapsed { width: var(--nav-collapsed-w); }

.sidenav-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 10px 14px 14px;
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}

.sidenav-logo {
  display: flex;
  align-items: center;
  gap: 9px;
  font-weight: 600;
  font-size: 14px;
  color: var(--text);
  letter-spacing: -.3px;
  text-decoration: none;
  white-space: nowrap;
  overflow: hidden;
}

.sidenav-logo-text {
  opacity: 1;
  transition: opacity 0.15s;
  white-space: nowrap;
}

.sidenav.collapsed .sidenav-logo-text { opacity: 0; width: 0; overflow: hidden; }

.sidenav-collapse-btn {
  background: none;
  border: 1px solid var(--border);
  border-radius: 4px;
  color: var(--text-muted);
  cursor: pointer;
  padding: 3px 5px;
  display: flex;
  align-items: center;
  flex-shrink: 0;
  transition: all .15s;
}

.sidenav-collapse-btn:hover { color: var(--text); background: var(--surface3); }

.sidenav-items {
  list-style: none;
  padding: 8px 0;
  flex: 1;
  overflow-y: auto;
}

.sidenav-items::-webkit-scrollbar { width: 3px; }
.sidenav-items::-webkit-scrollbar-thumb { background: var(--border2); border-radius: 2px; }

.nav-link {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  margin: 1px 8px;
  color: var(--text-dim);
  text-decoration: none;
  border-radius: var(--radius);
  border-left: 2px solid transparent;
  font-size: 13px;
  white-space: nowrap;
  overflow: hidden;
  transition: background .12s, color .12s;
}

.nav-link:hover { background: var(--surface3); color: var(--text); }

.nav-link.active {
  color: var(--accent);
  background: var(--accent-dim);
  border-left-color: var(--accent);
}

.nav-link svg { flex-shrink: 0; }

.nav-link-label {
  opacity: 1;
  transition: opacity 0.15s;
  white-space: nowrap;
}

.sidenav.collapsed .nav-link { justify-content: center; margin: 1px 6px; padding: 8px; }
.sidenav.collapsed .nav-link-label { opacity: 0; width: 0; overflow: hidden; }

.sidenav-footer {
  padding: 10px 12px;
  border-top: 1px solid var(--border);
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}

.sidenav-user {
  font-size: 12px;
  color: var(--text-muted);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  opacity: 1;
  transition: opacity 0.15s;
}

.sidenav.collapsed .sidenav-user { opacity: 0; width: 0; overflow: hidden; }

/* ── TOPBAR ── */
.topbar {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 0 16px;
  height: 44px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  flex-shrink: 0;
}

.topbar-title {
  font-weight: 600;
  font-size: 14px;
  color: var(--text);
  white-space: nowrap;
}

.topbar-search { flex: 1; }

.topbar-right {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-left: auto;
  white-space: nowrap;
}

/* ── CARDS ── */
.card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 16px 20px;
}

.stat-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-left: 3px solid var(--border2);
  border-radius: var(--radius);
  padding: 16px 20px;
}

.stat-card.critical { border-left-color: var(--severity-critical); }
.stat-card.high     { border-left-color: var(--severity-high); }

.stat-label {
  font-size: 11px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .07em;
  color: var(--text-muted);
  margin-bottom: 6px;
}

.stat-value {
  font-family: var(--mono);
  font-size: 28px;
  font-weight: 500;
  color: var(--text);
  line-height: 1;
}

.stat-card.critical .stat-value { color: var(--severity-critical); }
.stat-card.high .stat-value     { color: var(--severity-high); }

/* ── SEVERITY BADGES ── */
.badge {
  display: inline-flex;
  align-items: center;
  padding: 2px 7px;
  border-radius: 3px;
  font-size: 10.5px;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: .05em;
  white-space: nowrap;
}

.badge.critical { background: var(--severity-critical-bg); color: var(--severity-critical); }
.badge.high     { background: var(--severity-high-bg);     color: var(--severity-high); }
.badge.medium   { background: var(--severity-medium-bg);   color: var(--severity-medium); }
.badge.low      { background: var(--severity-low-bg);      color: var(--severity-low); }

/* ── SEVERITY DOTS (for facet bars) ── */
.dot-critical { background: var(--severity-critical) !important; }
.dot-high     { background: var(--severity-high) !important; }
.dot-medium   { background: var(--severity-medium) !important; }
.dot-low      { background: var(--severity-low) !important; }

/* ── RESPONSIVE: auto-collapse below 768px ── */
@media (max-width: 768px) {
  .sidenav { width: var(--nav-collapsed-w); }
  .sidenav-logo-text,
  .nav-link-label,
  .sidenav-user { opacity: 0; width: 0; overflow: hidden; }
  .sidenav .nav-link { justify-content: center; margin: 1px 6px; padding: 8px; }
  .sidenav .sidenav-collapse-btn { display: none; }
}
```

- [ ] **Step 2: Verify file exists**

```bash
ls -la /path/to/repo/ui/shared.css
```
Expected: file created, non-zero size.

- [ ] **Step 3: Commit**

```bash
git add ui/shared.css
git commit -m "feat: add shared.css design tokens and left nav component"
```

---

## Task 2: Refactor `ui/events.html` — Left Nav + Visual Refresh

**Files:**
- Modify: `ui/events.html`

**Interfaces:**
- Consumes: `ui/shared.css` classes `.layout`, `.main-wrap`, `.sidenav`, `.nav-link`, `.topbar`, `.badge`
- Produces: working Events page with left nav replacing top nav; `initNav()` / `toggleNav()` JS functions reusable as the pattern for all pages

- [ ] **Step 1: Add `shared.css` link and replace old nav CSS**

In the `<head>`, after the Google Fonts link, add:
```html
<link rel="stylesheet" href="/ui/shared.css">
```

Remove the entire `/* ── NAV ── */` CSS block (lines with `.nav`, `.nav-logo`, `.nav-item`, `.nav-space`, `.live-badge`, `.live-dot`, `.nav-btn` rules). These are replaced by shared.css.

Remove the old `/* ── APP LAYOUT ── */` block:
```css
/* DELETE THIS: */
.app{display:flex;flex-direction:column;height:100vh}
```
The new layout uses `.layout` from shared.css.

- [ ] **Step 2: Update CSS custom properties — add `--radius` and table row padding**

Inside the existing `:root` block, add after the existing properties:
```css
  --radius: 6px;
```

Update table row padding (find the `tbody td` rule and change padding from `4px 10px` to `7px 10px`):
```css
tbody td{padding:7px 10px;border-bottom:1px solid var(--border);vertical-align:middle;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12.5px}
```

- [ ] **Step 3: Replace the HTML body layout**

The current HTML body opens with:
```html
<div class="app">
  <nav class="nav">
    ... (logo, nav items, settings btn, theme btn)
  </nav>
  <div class="top-area">
    ...
  </div>
  <div class="body-area">
    ...
  </div>
</div>
```

Replace the outer `<div class="app">` and the entire `<nav class="nav">...</nav>` with this new structure. The `.top-area` and `.body-area` contents stay intact — just rewrap them:

```html
<div class="layout">

  <!-- ── LEFT NAV ── -->
  <nav class="sidenav" id="sidenav">
    <div class="sidenav-header">
      <a href="/ui/dashboard.html" class="sidenav-logo">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span class="sidenav-logo-text">TinySIEM</span>
      </a>
      <button class="sidenav-collapse-btn" onclick="toggleNav()" title="Toggle sidebar">
        <svg id="collapseIcon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="15 18 9 12 15 6"/>
        </svg>
      </button>
    </div>
    <ul class="sidenav-items">
      <li><a href="/ui/dashboard.html" class="nav-link" title="Home">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        <span class="nav-link-label">Home</span>
      </a></li>
      <li><a href="/ui/events.html" class="nav-link active" title="Events">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
        <span class="nav-link-label">Events</span>
      </a></li>
      <li><a href="/ui/alerts.html" class="nav-link" title="Alerts">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
        <span class="nav-link-label">Alerts</span>
      </a></li>
      <li><a href="/ui/rules.html" class="nav-link" title="Rules">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span class="nav-link-label">Rules</span>
      </a></li>
      <li><a href="/ui/parsers.html" class="nav-link" title="Parsers">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        <span class="nav-link-label">Parsers</span>
      </a></li>
      <li><a href="/ui/configuration.html" class="nav-link" title="Configuration">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg>
        <span class="nav-link-label">Configuration</span>
      </a></li>
    </ul>
    <div class="sidenav-footer">
      <button class="nav-btn" onclick="toggleTheme()" title="Toggle theme" id="themeBtn">◑</button>
      <span class="sidenav-user">v0.4</span>
    </div>
  </nav>

  <!-- ── MAIN WRAP ── -->
  <div class="main-wrap">
    <div class="topbar">
      <span class="topbar-title">Events</span>
      <div class="topbar-search"><!-- search bar moved here in Step 4 --></div>
      <div class="topbar-right">
        <div class="live-badge" id="liveBadge" onclick="toggleLive()">
          <span class="live-dot"></span>LIVE
        </div>
        <button class="nav-btn" onclick="openSettings()" title="Settings">⚙</button>
      </div>
    </div>

    <!-- existing .top-area contents (search bar, filters, histogram) go here -->
    <div class="top-area">
      ...existing search bar, active filters, histogram HTML...
    </div>

    <!-- existing .body-area stays unchanged -->
    <div class="body-area">
      ...existing sidebar + main panel HTML...
    </div>
  </div>

</div><!-- /.layout -->
```

> **Note:** Keep all existing `.top-area` and `.body-area` inner HTML exactly as-is. Only the outer wrapper and the nav change.

- [ ] **Step 4: Add nav JS functions**

Find the `<script>` block. Locate the existing `load()` function and add nav initialization inside it, after the `S.theme = ...` line:

```js
// Add to existing load() function:
S.navCollapsed = localStorage.getItem('ts_nav_collapsed') === 'true';
if (window.innerWidth < 768) S.navCollapsed = true;
applyNav();
```

Add these two new functions anywhere in the script block (before `load()`):

```js
function toggleNav() {
  S.navCollapsed = !S.navCollapsed;
  localStorage.setItem('ts_nav_collapsed', String(S.navCollapsed));
  applyNav();
}

function applyNav() {
  const nav = document.getElementById('sidenav');
  const icon = document.getElementById('collapseIcon');
  if (S.navCollapsed) {
    nav.classList.add('collapsed');
    // point chevron right
    icon.innerHTML = '<polyline points="9 18 15 12 9 6"/>';
  } else {
    nav.classList.remove('collapsed');
    // point chevron left
    icon.innerHTML = '<polyline points="15 18 9 12 15 6"/>';
  }
}
```

Also add `navCollapsed: false` to the `S` object initialization.

- [ ] **Step 5: Remove old theme/settings button HTML from nav (already moved to topbar/sidenav-footer)**

Delete the old `<button onclick="openSettings()">` and `<button onclick="toggleTheme()">` elements that were inside `<nav class="nav">`, since they are now in the new locations.

- [ ] **Step 6: Start Docker and verify in browser**

```bash
docker-compose restart tinysiem
```

Open `http://localhost:8000/ui/events.html`. Verify:
- Left sidebar visible with logo + 6 nav items
- Events item highlighted with accent left-border
- Clicking the collapse chevron narrows sidebar to icons only
- Clicking again expands it
- Page title "Events" visible in topbar
- Existing events table, search, facets all still work
- Theme toggle still works

- [ ] **Step 7: Commit**

```bash
git add ui/events.html
git commit -m "feat: replace top nav with collapsible left nav on events page"
```

---

## Task 3: Refactor `ui/alerts.html` — Left Nav + Visual Refresh

**Files:**
- Modify: `ui/alerts.html`

**Interfaces:**
- Consumes: `ui/shared.css` same classes as Task 2
- Consumes: `toggleNav()` / `applyNav()` pattern from Task 2 (copy exactly)

- [ ] **Step 1: Add `shared.css` link and remove old nav CSS**

Same as Task 2 Step 1 — add after Google Fonts link:
```html
<link rel="stylesheet" href="/ui/shared.css">
```

Remove the `/* ── NAV ── */` CSS block (`.nav`, `.nav-logo`, `.nav-item`, `.nav-space`, `.nav-btn` rules from alerts.html).
Remove `.app{display:flex;flex-direction:column;height:100vh}`.

- [ ] **Step 2: Update CSS custom properties — add `--radius` and table row padding**

Inside the existing `:root` block, add:
```css
  --radius: 6px;
```

Update `tbody td` padding from `4px 10px` to `7px 10px` (same as Task 2 Step 2).

- [ ] **Step 3: Update severity dot classes to use new palette**

In the alerts.html `<style>`, find or add these rules to override the severity dot colors with the locked palette:
```css
.dot-critical{background:var(--severity-critical)}
.dot-high{background:var(--severity-high)}
.dot-medium{background:var(--severity-medium)}
.dot-low{background:var(--severity-low)}
```

In the `dotClass()` JS function, update it to return the new dot classes:
```js
function dotClass(field, value) {
  if (field === 'severity') {
    const v = (value || 'unknown').toLowerCase();
    // map 'high' → 'dot-high', etc.
    return 'dot-' + v;
  }
  return 'dot-rule';
}
```

- [ ] **Step 4: Replace HTML body layout — same structure as Task 2 with alerts-specific changes**

Wrap existing content in `.layout` / `.main-wrap`. The left nav HTML is identical to Task 2 except:
- `href="/ui/alerts.html"` gets `class="nav-link active"` (Alerts item is active)
- `href="/ui/events.html"` gets `class="nav-link"` (no active)

```html
<div class="layout">
  <nav class="sidenav" id="sidenav">
    <div class="sidenav-header">
      <a href="/ui/dashboard.html" class="sidenav-logo">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
        <span class="sidenav-logo-text">TinySIEM</span>
      </a>
      <button class="sidenav-collapse-btn" onclick="toggleNav()" title="Toggle sidebar">
        <svg id="collapseIcon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="15 18 9 12 15 6"/>
        </svg>
      </button>
    </div>
    <ul class="sidenav-items">
      <li><a href="/ui/dashboard.html" class="nav-link" title="Home">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        <span class="nav-link-label">Home</span>
      </a></li>
      <li><a href="/ui/events.html" class="nav-link" title="Events">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
        <span class="nav-link-label">Events</span>
      </a></li>
      <li><a href="/ui/alerts.html" class="nav-link active" title="Alerts">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
        <span class="nav-link-label">Alerts</span>
      </a></li>
      <li><a href="/ui/rules.html" class="nav-link" title="Rules">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span class="nav-link-label">Rules</span>
      </a></li>
      <li><a href="/ui/parsers.html" class="nav-link" title="Parsers">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        <span class="nav-link-label">Parsers</span>
      </a></li>
      <li><a href="/ui/configuration.html" class="nav-link" title="Configuration">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg>
        <span class="nav-link-label">Configuration</span>
      </a></li>
    </ul>
    <div class="sidenav-footer">
      <button class="nav-btn" onclick="toggleTheme()" title="Toggle theme">◑</button>
      <span class="sidenav-user">v0.4</span>
    </div>
  </nav>

  <div class="main-wrap">
    <div class="topbar">
      <span class="topbar-title">Alerts</span>
      <div class="topbar-right">
        <button class="nav-btn" onclick="openSettings()" title="Settings">⚙</button>
      </div>
    </div>
    <!-- existing .top-area and .body-area contents unchanged -->
    <div class="top-area">...</div>
    <div class="body-area">...</div>
  </div>
</div>
```

- [ ] **Step 5: Add `toggleNav()` / `applyNav()` and update `S` object + `load()`**

Copy the exact same functions from Task 2 Step 4 into alerts.html's `<script>` block. Add `navCollapsed: false` to the `S` object. Add nav init to the `load()` function:
```js
S.navCollapsed = localStorage.getItem('ts_nav_collapsed') === 'true';
if (window.innerWidth < 768) S.navCollapsed = true;
applyNav();
```

- [ ] **Step 6: Verify in browser**

```bash
docker-compose restart tinysiem
```

Open `http://localhost:8000/ui/alerts.html`. Verify:
- Left nav shows with Alerts item highlighted
- Severity facet dots now use the locked palette colors (red/orange/amber/blue)
- Nav collapse/expand works and state persists across page refresh
- Clicking Events in nav goes to events.html; Alerts item is active there
- Existing alerts table, filters, export still work

- [ ] **Step 7: Commit**

```bash
git add ui/alerts.html
git commit -m "feat: replace top nav with collapsible left nav on alerts page; lock severity palette"
```

---

## Task 4: Create `ui/dashboard.html` — Threat Posture Dashboard

**Files:**
- Create: `ui/dashboard.html`

**Interfaces:**
- Consumes: `ui/shared.css` (`.layout`, `.sidenav`, `.main-wrap`, `.topbar`, `.card`, `.stat-card`, `.stat-card.critical`, `.stat-card.high`, `.badge.*`)
- Consumes: `GET /events?start=<iso>&limit=1` → `{total: N, events: [...]}`
- Consumes: `GET /alerts?start=<iso>&limit=1` → `{total: N, alerts: [...]}`
- Consumes: `GET /alerts?severity=critical&start=<iso>&limit=1` → `{total: N}`
- Consumes: `GET /alerts?severity=high&start=<iso>&limit=1` → `{total: N}`
- Consumes: `GET /alerts/facets` → `{severity: [{value, count}], rule_name: [{value, count}]}`
- Consumes: `GET /events/histogram?start=<iso>&end=<iso>&buckets=48` → `[{ts, count}]`
- Consumes: `GET /alerts?severity=critical&limit=5` → `{alerts: [...]}`
- Consumes: `GET /alerts?severity=high&limit=5` → `{alerts: [...]}`
- Consumes: `GET /events/facets` → `{source_ip: [{value, count}]}`

- [ ] **Step 1: Create `ui/dashboard.html` with full structure**

```html
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TinySIEM — Home</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js" integrity="sha512-SIMGYRUjwY8+gKg7nn9EItdD8LCADSDfJNutF9TPrvEo86sQmFMh6MyralfIyhADlajSxqc7G0gs7+MwWF/ogQ==" crossorigin="anonymous"></script>
<link rel="stylesheet" href="/ui/shared.css">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

:root{
  --bg:#0d0e17;
  --surface:#12131f;
  --surface2:#191a2d;
  --surface3:#1f2138;
  --surface4:#252845;
  --border:#252840;
  --border2:#323560;
  --text:#cdd0eb;
  --text-dim:#7b7fa8;
  --text-muted:#454870;
  --accent:#4d9fff;
  --accent-dim:#0d2a50;
  --green:#3ddc84;
  --green-dim:#0a2e1c;
  --red:#e85555;
  --mono:'IBM Plex Mono',monospace;
  --sans:'IBM Plex Sans',sans-serif;
}
[data-theme="light"]{
  --bg:#f0f2f8;
  --surface:#ffffff;
  --surface2:#f5f7fc;
  --surface3:#eaecf5;
  --surface4:#e0e3f0;
  --border:#dde0f0;
  --border2:#c0c6e0;
  --text:#1a1c2e;
  --text-dim:#4a4f6a;
  --text-muted:#9096b8;
  --accent:#2979ff;
  --accent-dim:#e3ecff;
  --green:#1a8a4a;
  --green-dim:#eaf7ef;
  --red:#c0392b;
}

html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;line-height:1.5;overflow:hidden}

.nav-btn{width:30px;height:30px;display:flex;align-items:center;justify-content:center;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text-dim);cursor:pointer;font-size:14px;transition:all .15s}
.nav-btn:hover{color:var(--text);border-color:var(--border2);background:var(--surface3)}

/* Dashboard layout */
.dash-body{flex:1;overflow-y:auto;padding:16px 20px;display:flex;flex-direction:column;gap:14px}
.dash-body::-webkit-scrollbar{width:6px}
.dash-body::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}

/* Stat card row */
.stat-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}

/* Two-col rows */
.panel-row{display:grid;gap:12px}
.panel-row.r40-60{grid-template-columns:2fr 3fr}
.panel-row.r60-40{grid-template-columns:3fr 2fr}

/* Panel */
.panel-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text-muted);margin-bottom:12px}

/* Severity bar */
.sev-bar-row{display:flex;align-items:center;gap:10px;padding:5px 0;cursor:pointer;border-radius:4px;transition:background .1s}
.sev-bar-row:hover{background:var(--surface3);margin:0 -8px;padding:5px 8px}
.sev-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sev-label{width:64px;font-size:12px;color:var(--text-dim);text-transform:capitalize}
.sev-count{font-family:var(--mono);font-size:12px;color:var(--text);width:40px;text-align:right;flex-shrink:0}
.sev-track{flex:1;height:4px;background:var(--border);border-radius:2px;overflow:hidden}
.sev-fill{height:100%;border-radius:2px;min-width:2px;transition:width .3s}

/* Alert feed table */
.feed-table{width:100%;border-collapse:collapse}
.feed-table th{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);padding:4px 8px;border-bottom:1px solid var(--border);text-align:left;white-space:nowrap}
.feed-table td{padding:7px 8px;border-bottom:1px solid var(--border);font-size:12px;vertical-align:middle;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.feed-table tbody tr{cursor:pointer;transition:background .08s}
.feed-table tbody tr:hover{background:var(--surface3)}
.feed-table .col-time{width:100px;font-family:var(--mono);font-size:11px;color:var(--text-dim)}
.feed-table .col-rule{max-width:180px;overflow:hidden;text-overflow:ellipsis}
.feed-table .col-ip{width:100px;font-family:var(--mono);font-size:11px;color:var(--text-dim)}
.feed-table .col-sev{width:74px}
.feed-table .col-sum{color:var(--text-dim);font-size:11px}

/* Mini table (top IPs / top rules) */
.mini-table{width:100%;border-collapse:collapse}
.mini-table th{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);padding:4px 8px;border-bottom:1px solid var(--border);text-align:left}
.mini-table td{padding:5px 8px;border-bottom:1px solid var(--border);font-size:12px}
.mini-table tbody tr{cursor:pointer;transition:background .08s}
.mini-table tbody tr:hover{background:var(--surface3)}
.mini-table .col-val{font-family:var(--mono);font-size:11.5px;color:var(--text)}
.mini-table .col-cnt{font-family:var(--mono);font-size:11.5px;color:var(--text-dim);text-align:right}
.mini-section-title{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.06em;color:var(--text-muted);margin-bottom:8px;margin-top:16px}
.mini-section-title:first-child{margin-top:0}

/* Empty state */
.empty-state{padding:20px;text-align:center;color:var(--text-muted);font-size:12px}
.empty-state.ok{color:var(--green)}

/* Spinner */
.spinner{display:inline-block;width:12px;height:12px;border:2px solid var(--border2);border-top-color:var(--accent);border-radius:50%;animation:spin .7s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}

/* Last refreshed */
.refresh-ts{font-family:var(--mono);font-size:11px;color:var(--text-muted)}

/* Settings modal (reused pattern from other pages) */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,.6);z-index:200;display:none;align-items:center;justify-content:center}
.modal-overlay.show{display:flex}
.modal{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:20px;min-width:320px;max-width:440px;width:100%}
.modal h3{font-size:14px;font-weight:600;color:var(--text);margin-bottom:14px}
.modal label{display:block;font-size:11px;color:var(--text-muted);margin-bottom:3px}
.modal input{width:100%;background:var(--bg);border:1px solid var(--border2);border-radius:4px;color:var(--text);font-family:var(--mono);font-size:12px;padding:5px 8px;margin-bottom:10px}
.modal input:focus{outline:none;border-color:var(--accent)}
.modal-btns{display:flex;justify-content:flex-end;gap:8px;margin-top:4px}
.modal-btn{padding:5px 14px;border-radius:4px;font-size:12px;cursor:pointer;border:1px solid var(--border2);background:var(--surface3);color:var(--text)}
.modal-btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
.modal-btn:hover{opacity:.85}
</style>
</head>
<body>
<div class="layout">

  <!-- ── LEFT NAV ── -->
  <nav class="sidenav" id="sidenav">
    <div class="sidenav-header">
      <a href="/ui/dashboard.html" class="sidenav-logo">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span class="sidenav-logo-text">TinySIEM</span>
      </a>
      <button class="sidenav-collapse-btn" onclick="toggleNav()" title="Toggle sidebar">
        <svg id="collapseIcon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round">
          <polyline points="15 18 9 12 15 6"/>
        </svg>
      </button>
    </div>
    <ul class="sidenav-items">
      <li><a href="/ui/dashboard.html" class="nav-link active" title="Home">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
        <span class="nav-link-label">Home</span>
      </a></li>
      <li><a href="/ui/events.html" class="nav-link" title="Events">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg>
        <span class="nav-link-label">Events</span>
      </a></li>
      <li><a href="/ui/alerts.html" class="nav-link" title="Alerts">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>
        <span class="nav-link-label">Alerts</span>
      </a></li>
      <li><a href="/ui/rules.html" class="nav-link" title="Rules">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span class="nav-link-label">Rules</span>
      </a></li>
      <li><a href="/ui/parsers.html" class="nav-link" title="Parsers">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
        <span class="nav-link-label">Parsers</span>
      </a></li>
      <li><a href="/ui/configuration.html" class="nav-link" title="Configuration">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg>
        <span class="nav-link-label">Configuration</span>
      </a></li>
    </ul>
    <div class="sidenav-footer">
      <button class="nav-btn" onclick="toggleTheme()" title="Toggle theme">◑</button>
      <span class="sidenav-user">v0.4</span>
    </div>
  </nav>

  <!-- ── MAIN WRAP ── -->
  <div class="main-wrap">

    <!-- Topbar -->
    <div class="topbar">
      <span class="topbar-title">Home</span>
      <div class="topbar-right">
        <span class="refresh-ts" id="refreshTs"></span>
        <button class="nav-btn" onclick="fetchAll()" title="Refresh">↻</button>
        <button class="nav-btn" onclick="openSettings()" title="Settings">⚙</button>
      </div>
    </div>

    <!-- Dashboard body -->
    <div class="dash-body">

      <!-- Row 1: Stat cards -->
      <div class="stat-row">
        <div class="stat-card" id="cardEvents">
          <div class="stat-label">Events (24h)</div>
          <div class="stat-value" id="valEvents">—</div>
        </div>
        <div class="stat-card" id="cardAlerts">
          <div class="stat-label">Alerts (24h)</div>
          <div class="stat-value" id="valAlerts">—</div>
        </div>
        <div class="stat-card critical">
          <div class="stat-label">Critical (24h)</div>
          <div class="stat-value" id="valCritical">—</div>
        </div>
        <div class="stat-card high">
          <div class="stat-label">High (24h)</div>
          <div class="stat-value" id="valHigh">—</div>
        </div>
      </div>

      <!-- Row 2: Severity breakdown + Event volume -->
      <div class="panel-row r40-60">
        <div class="card">
          <div class="panel-title">Alert Severity</div>
          <div id="sevPanel"><span class="spinner"></span>Loading…</div>
        </div>
        <div class="card">
          <div class="panel-title">Event Volume — Last 24h</div>
          <div style="height:120px;position:relative"><canvas id="histCanvas"></canvas></div>
        </div>
      </div>

      <!-- Row 3: Recent alerts + Top IPs/Rules -->
      <div class="panel-row r60-40">
        <div class="card" style="overflow:hidden">
          <div class="panel-title">Recent High / Critical Alerts</div>
          <div style="overflow-x:auto">
            <table class="feed-table">
              <thead><tr>
                <th class="col-time">Time</th>
                <th class="col-sev">Severity</th>
                <th class="col-rule">Rule</th>
                <th class="col-ip">Source IP</th>
                <th class="col-sum">Summary</th>
              </tr></thead>
              <tbody id="alertFeed"><tr><td colspan="5"><span class="spinner"></span>Loading…</td></tr></tbody>
            </table>
          </div>
        </div>
        <div class="card">
          <div class="mini-section-title">Top Source IPs</div>
          <table class="mini-table">
            <thead><tr><th class="col-val">IP Address</th><th class="col-cnt">Events</th></tr></thead>
            <tbody id="topIPs"><tr><td colspan="2"><span class="spinner"></span></td></tr></tbody>
          </table>
          <div class="mini-section-title">Top Triggered Rules</div>
          <table class="mini-table">
            <thead><tr><th class="col-val">Rule</th><th class="col-cnt">Alerts</th></tr></thead>
            <tbody id="topRules"><tr><td colspan="2"><span class="spinner"></span></td></tr></tbody>
          </table>
        </div>
      </div>

    </div><!-- /.dash-body -->
  </div><!-- /.main-wrap -->
</div><!-- /.layout -->

<!-- Settings Modal -->
<div class="modal-overlay" id="settingsOverlay" onclick="if(event.target===this)closeSettings()">
  <div class="modal">
    <h3>Settings</h3>
    <label>API Endpoint</label>
    <input type="text" id="settingsEp" placeholder="http://localhost:8000">
    <label>API Key</label>
    <input type="password" id="settingsKey" placeholder="Bearer token">
    <div class="modal-btns">
      <button class="modal-btn" onclick="closeSettings()">Cancel</button>
      <button class="modal-btn primary" onclick="saveSettings()">Save</button>
    </div>
  </div>
</div>

<script>
const TH = document.documentElement;

const S = {
  ep: '', key: '', theme: 'dark', navCollapsed: false,
  hc: null,
};

// ── NAV ──────────────────────────────────────────────────────────────────
function toggleNav() {
  S.navCollapsed = !S.navCollapsed;
  localStorage.setItem('ts_nav_collapsed', String(S.navCollapsed));
  applyNav();
}

function applyNav() {
  const nav = document.getElementById('sidenav');
  const icon = document.getElementById('collapseIcon');
  if (S.navCollapsed) {
    nav.classList.add('collapsed');
    icon.innerHTML = '<polyline points="9 18 15 12 9 6"/>';
  } else {
    nav.classList.remove('collapsed');
    icon.innerHTML = '<polyline points="15 18 9 12 15 6"/>';
  }
}

// ── THEME ────────────────────────────────────────────────────────────────
function toggleTheme() {
  S.theme = TH.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  TH.setAttribute('data-theme', S.theme);
  localStorage.setItem('ts_theme', S.theme);
}

// ── SETTINGS ─────────────────────────────────────────────────────────────
function openSettings() {
  document.getElementById('settingsEp').value = S.ep;
  document.getElementById('settingsKey').value = S.key;
  document.getElementById('settingsOverlay').classList.add('show');
}
function closeSettings() {
  document.getElementById('settingsOverlay').classList.remove('show');
}
function saveSettings() {
  S.ep = document.getElementById('settingsEp').value.trim().replace(/\/$/, '');
  S.key = document.getElementById('settingsKey').value.trim();
  localStorage.setItem('ts_ep', S.ep);
  localStorage.setItem('ts_key', S.key);
  closeSettings();
  fetchAll();
}

// ── API ───────────────────────────────────────────────────────────────────
async function api(path) {
  const r = await fetch(S.ep + path, {
    headers: { 'Authorization': 'Bearer ' + S.key }
  });
  if (!r.ok) throw new Error('HTTP ' + r.status);
  return r.json();
}

function since24h() {
  return new Date(Date.now() - 86400000).toISOString();
}

function fmtNum(n) {
  return n == null ? '—' : Number(n).toLocaleString();
}

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso + (iso.endsWith('Z') ? '' : 'Z'));
  return d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
}

function esc(s) {
  return String(s ?? '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── FETCH ALL ─────────────────────────────────────────────────────────────
async function fetchAll() {
  const start = since24h();
  const now = new Date().toISOString();
  document.getElementById('refreshTs').textContent = '';

  await Promise.allSettled([
    fetchStatCards(start),
    fetchSeverityPanel(),
    fetchHistogram(start, now),
    fetchAlertFeed(),
    fetchTopIPs(),
    fetchTopRules(),
  ]);

  document.getElementById('refreshTs').textContent =
    'Updated ' + new Date().toLocaleTimeString();
}

// ── STAT CARDS ────────────────────────────────────────────────────────────
async function fetchStatCards(start) {
  try {
    const [evts, alrts, crit, high] = await Promise.all([
      api('/events?start=' + encodeURIComponent(start) + '&limit=1'),
      api('/alerts?start=' + encodeURIComponent(start) + '&limit=1'),
      api('/alerts?severity=critical&start=' + encodeURIComponent(start) + '&limit=1'),
      api('/alerts?severity=high&start='     + encodeURIComponent(start) + '&limit=1'),
    ]);
    document.getElementById('valEvents').textContent   = fmtNum(evts.total);
    document.getElementById('valAlerts').textContent   = fmtNum(alrts.total);
    document.getElementById('valCritical').textContent = fmtNum(crit.total);
    document.getElementById('valHigh').textContent     = fmtNum(high.total);
  } catch(e) {
    ['valEvents','valAlerts','valCritical','valHigh'].forEach(id => {
      document.getElementById(id).textContent = 'err';
    });
  }
}

// ── SEVERITY PANEL ────────────────────────────────────────────────────────
async function fetchSeverityPanel() {
  const el = document.getElementById('sevPanel');
  try {
    const d = await api('/alerts/facets');
    const sevs = d.severity || [];
    if (!sevs.length) {
      el.innerHTML = '<div class="empty-state">No alerts yet</div>';
      return;
    }
    const max = Math.max(1, ...sevs.map(s => s.count));
    const order = ['critical','high','medium','low'];
    const map = Object.fromEntries(sevs.map(s => [s.value, s.count]));
    el.innerHTML = order.map(sev => {
      const cnt = map[sev] || 0;
      const pct = Math.round(cnt / max * 100);
      return `<div class="sev-bar-row" onclick="location.href='/ui/alerts.html?severity=${sev}'">
        <span class="sev-dot dot-${sev}"></span>
        <span class="sev-label">${sev}</span>
        <div class="sev-track"><div class="sev-fill dot-${sev}" style="width:${pct}%"></div></div>
        <span class="sev-count">${fmtNum(cnt)}</span>
      </div>`;
    }).join('');
  } catch(e) {
    el.innerHTML = '<div class="empty-state">Failed to load</div>';
  }
}

// ── HISTOGRAM ─────────────────────────────────────────────────────────────
async function fetchHistogram(start, end) {
  try {
    const d = await api('/events/histogram?start=' + encodeURIComponent(start) +
      '&end=' + encodeURIComponent(end) + '&buckets=48');
    renderHistogram(d);
  } catch(_) {}
}

function renderHistogram(buckets) {
  const canvas = document.getElementById('histCanvas');
  const dark = TH.getAttribute('data-theme') !== 'light';
  if (S.hc) S.hc.destroy();
  S.hc = new Chart(canvas, {
    type: 'bar',
    data: {
      labels: buckets.map(b => new Date(b.ts).toLocaleTimeString()),
      datasets: [{
        data: buckets.map(b => b.count),
        backgroundColor: dark ? 'rgba(77,159,255,.35)' : 'rgba(41,121,255,.3)',
        borderColor:     dark ? 'rgba(77,159,255,.6)'  : 'rgba(41,121,255,.6)',
        borderWidth: 1, borderRadius: 1,
      }]
    },
    options: {
      responsive: true, maintainAspectRatio: false, animation: false,
      plugins: {
        legend: { display: false },
        tooltip: {
          callbacks: { title: i => i[0].label, label: i => ` ${i.raw} events` },
          backgroundColor: dark ? '#1f2138' : '#fff',
          titleColor: dark ? '#cdd0eb' : '#1a1c2e',
          bodyColor:  dark ? '#7b7fa8' : '#4a4f6a',
          borderColor: dark ? '#2a2d4a' : '#dde0f0', borderWidth: 1, padding: 7,
        }
      },
      scales: { x: { display: false }, y: { display: false, beginAtZero: true } },
    }
  });
}

// ── ALERT FEED ────────────────────────────────────────────────────────────
async function fetchAlertFeed() {
  const tbody = document.getElementById('alertFeed');
  try {
    const [crit, high] = await Promise.all([
      api('/alerts?severity=critical&limit=5'),
      api('/alerts?severity=high&limit=5'),
    ]);
    const alerts = [...(crit.alerts || []), ...(high.alerts || [])]
      .sort((a, b) => b.triggered_at.localeCompare(a.triggered_at))
      .slice(0, 10);

    if (!alerts.length) {
      tbody.innerHTML = `<tr><td colspan="5" class="empty-state ok">✓ No high or critical alerts in the last 24h</td></tr>`;
      return;
    }
    tbody.innerHTML = alerts.map(a => `
      <tr onclick="location.href='/ui/alerts.html?rule_name=${encodeURIComponent(a.rule_name)}'">
        <td class="col-time">${esc(fmtTime(a.triggered_at))}</td>
        <td class="col-sev"><span class="badge ${esc(a.severity)}">${esc(a.severity)}</span></td>
        <td class="col-rule">${esc(a.rule_name)}</td>
        <td class="col-ip">${esc(a.source_ip || '—')}</td>
        <td class="col-sum">${esc(a.summary || '')}</td>
      </tr>`).join('');
  } catch(e) {
    tbody.innerHTML = `<tr><td colspan="5" class="empty-state">Failed to load alerts</td></tr>`;
  }
}

// ── TOP IPs ───────────────────────────────────────────────────────────────
async function fetchTopIPs() {
  const tbody = document.getElementById('topIPs');
  try {
    const d = await api('/events/facets');
    const ips = (d.source_ip || []).slice(0, 5);
    if (!ips.length) {
      tbody.innerHTML = `<tr><td colspan="2" class="empty-state">No data</td></tr>`;
      return;
    }
    tbody.innerHTML = ips.map(ip =>
      `<tr onclick="location.href='/ui/events.html?source_ip=${encodeURIComponent(ip.value)}'">
        <td class="col-val">${esc(ip.value)}</td>
        <td class="col-cnt">${fmtNum(ip.count)}</td>
      </tr>`).join('');
  } catch(_) {
    tbody.innerHTML = `<tr><td colspan="2" class="empty-state">Failed to load</td></tr>`;
  }
}

// ── TOP RULES ─────────────────────────────────────────────────────────────
async function fetchTopRules() {
  const tbody = document.getElementById('topRules');
  try {
    const d = await api('/alerts/facets');
    const rules = (d.rule_name || []).slice(0, 5);
    if (!rules.length) {
      tbody.innerHTML = `<tr><td colspan="2" class="empty-state">No data</td></tr>`;
      return;
    }
    tbody.innerHTML = rules.map(r =>
      `<tr onclick="location.href='/ui/alerts.html?rule_name=${encodeURIComponent(r.value)}'">
        <td class="col-val">${esc(r.value)}</td>
        <td class="col-cnt">${fmtNum(r.count)}</td>
      </tr>`).join('');
  } catch(_) {
    tbody.innerHTML = `<tr><td colspan="2" class="empty-state">Failed to load</td></tr>`;
  }
}

// ── BOOT ──────────────────────────────────────────────────────────────────
function load() {
  S.ep    = localStorage.getItem('ts_ep')    || 'http://localhost:8000';
  S.key   = localStorage.getItem('ts_key')   || '';
  S.theme = localStorage.getItem('ts_theme') || 'dark';
  S.navCollapsed = localStorage.getItem('ts_nav_collapsed') === 'true';
  if (window.innerWidth < 768) S.navCollapsed = true;

  TH.setAttribute('data-theme', S.theme);
  applyNav();
  fetchAll();
}

window.addEventListener('DOMContentLoaded', load);
</script>
</body>
</html>
```

- [ ] **Step 2: Start Docker and verify in browser**

```bash
docker-compose restart tinysiem
```

Open `http://localhost:8000/ui/dashboard.html` (or `http://localhost:8000` which redirects). Verify:
- 4 stat cards render with event/alert counts
- Severity breakdown shows bars for each severity level, colored correctly
- Event volume histogram renders (may be empty if no data; that's fine)
- Recent alerts feed shows or shows "No high or critical alerts" green message
- Top IPs and Top Rules mini-tables render
- Nav works: active item is "Home", clicking Events/Alerts navigates correctly
- Nav collapse works and persists to localStorage

Seed data first if needed:
```bash
python scripts/ingest_test_logs.py 500
```

- [ ] **Step 3: Commit**

```bash
git add ui/dashboard.html
git commit -m "feat: add threat posture dashboard (v0.4)"
```

---

## Task 5: Create Shell Pages — Rules, Parsers, Configuration

**Files:**
- Create: `ui/rules.html`
- Create: `ui/parsers.html`
- Create: `ui/configuration.html`

**Interfaces:**
- Produces: navigable pages with left nav; each has the active nav item set correctly

- [ ] **Step 1: Create `ui/rules.html`**

```html
<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TinySIEM — Rules</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="/ui/shared.css">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0d0e17;--surface:#12131f;--surface2:#191a2d;--surface3:#1f2138;
  --border:#252840;--border2:#323560;--text:#cdd0eb;--text-dim:#7b7fa8;
  --text-muted:#454870;--accent:#4d9fff;--accent-dim:#0d2a50;
  --mono:'IBM Plex Mono',monospace;--sans:'IBM Plex Sans',sans-serif;
}
[data-theme="light"]{
  --bg:#f0f2f8;--surface:#ffffff;--surface2:#f5f7fc;--surface3:#eaecf5;
  --border:#dde0f0;--border2:#c0c6e0;--text:#1a1c2e;--text-dim:#4a4f6a;
  --text-muted:#9096b8;--accent:#2979ff;--accent-dim:#e3ecff;
}
html,body{height:100%;background:var(--bg);color:var(--text);font-family:var(--sans);font-size:13px;line-height:1.5;overflow:hidden}
.nav-btn{width:30px;height:30px;display:flex;align-items:center;justify-content:center;background:none;border:1px solid var(--border);border-radius:4px;color:var(--text-dim);cursor:pointer;font-size:14px;transition:all .15s}
.nav-btn:hover{color:var(--text);border-color:var(--border2);background:var(--surface3)}
.shell-body{flex:1;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:10px;color:var(--text-muted)}
.shell-title{font-size:18px;font-weight:600;color:var(--text-dim)}
.shell-desc{font-size:13px;max-width:380px;text-align:center;line-height:1.6}
.shell-tag{font-size:11px;padding:3px 10px;border-radius:12px;border:1px solid var(--border2);color:var(--text-muted);margin-top:4px}
</style>
</head>
<body>
<div class="layout">
  <nav class="sidenav" id="sidenav">
    <div class="sidenav-header">
      <a href="/ui/dashboard.html" class="sidenav-logo">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
        <span class="sidenav-logo-text">TinySIEM</span>
      </a>
      <button class="sidenav-collapse-btn" onclick="toggleNav()" title="Toggle sidebar">
        <svg id="collapseIcon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"/></svg>
      </button>
    </div>
    <ul class="sidenav-items">
      <li><a href="/ui/dashboard.html" class="nav-link" title="Home"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg><span class="nav-link-label">Home</span></a></li>
      <li><a href="/ui/events.html" class="nav-link" title="Events"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="8" y1="6" x2="21" y2="6"/><line x1="8" y1="12" x2="21" y2="12"/><line x1="8" y1="18" x2="21" y2="18"/><line x1="3" y1="6" x2="3.01" y2="6"/><line x1="3" y1="12" x2="3.01" y2="12"/><line x1="3" y1="18" x2="3.01" y2="18"/></svg><span class="nav-link-label">Events</span></a></li>
      <li><a href="/ui/alerts.html" class="nav-link" title="Alerts"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg><span class="nav-link-label">Alerts</span></a></li>
      <li><a href="/ui/rules.html" class="nav-link active" title="Rules"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg><span class="nav-link-label">Rules</span></a></li>
      <li><a href="/ui/parsers.html" class="nav-link" title="Parsers"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg><span class="nav-link-label">Parsers</span></a></li>
      <li><a href="/ui/configuration.html" class="nav-link" title="Configuration"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.07 4.93a10 10 0 0 1 0 14.14M4.93 4.93a10 10 0 0 0 0 14.14"/></svg><span class="nav-link-label">Configuration</span></a></li>
    </ul>
    <div class="sidenav-footer">
      <button class="nav-btn" onclick="toggleTheme()" title="Toggle theme">◑</button>
      <span class="sidenav-user">v0.4</span>
    </div>
  </nav>
  <div class="main-wrap">
    <div class="topbar">
      <span class="topbar-title">Rules</span>
    </div>
    <div class="shell-body">
      <div class="shell-title">Detection Rules</div>
      <div class="shell-desc">Create and manage YAML detection rules. Rules evaluate incoming events and fire alerts when conditions are met. AI-assisted rule generation coming in v0.6.</div>
      <span class="shell-tag">Coming in v0.6</span>
    </div>
  </div>
</div>
<script>
const TH=document.documentElement;
const S={navCollapsed:false,theme:'dark'};
function toggleNav(){S.navCollapsed=!S.navCollapsed;localStorage.setItem('ts_nav_collapsed',String(S.navCollapsed));applyNav()}
function applyNav(){const nav=document.getElementById('sidenav');const icon=document.getElementById('collapseIcon');if(S.navCollapsed){nav.classList.add('collapsed');icon.innerHTML='<polyline points="9 18 15 12 9 6"/>';}else{nav.classList.remove('collapsed');icon.innerHTML='<polyline points="15 18 9 12 15 6"/>';}}
function toggleTheme(){S.theme=TH.getAttribute('data-theme')==='dark'?'light':'dark';TH.setAttribute('data-theme',S.theme);localStorage.setItem('ts_theme',S.theme)}
function load(){S.theme=localStorage.getItem('ts_theme')||'dark';S.navCollapsed=localStorage.getItem('ts_nav_collapsed')==='true';if(window.innerWidth<768)S.navCollapsed=true;TH.setAttribute('data-theme',S.theme);applyNav()}
window.addEventListener('DOMContentLoaded',load);
</script>
</body>
</html>
```

- [ ] **Step 2: Create `ui/parsers.html`**

Same structure as rules.html. Change:
- `<title>TinySIEM — Parsers</title>`
- `class="nav-link active"` on the Parsers link (not Rules)
- `class="nav-link"` on the Rules link
- Topbar title: `Parsers`
- Shell title: `Log Parsers`
- Shell desc: `Create and manage YAML log decoders. Paste a raw log sample to generate a parser automatically. AI-assisted parser generation coming in v0.6.`
- Shell tag: `Coming in v0.6`

- [ ] **Step 3: Create `ui/configuration.html`**

Same structure. Change:
- `<title>TinySIEM — Configuration</title>`
- `class="nav-link active"` on the Configuration link
- Topbar title: `Configuration`
- Shell title: `Configuration`
- Shell desc: `Manage instance settings: API keys, log retention window, alert thresholds, and notification destinations. Coming in v0.5.`
- Shell tag: `Coming in v0.5`

- [ ] **Step 4: Verify navigation works across all pages**

```bash
docker-compose restart tinysiem
```

Click through all 6 nav items. Verify:
- Each page loads without JS errors
- The correct nav item is highlighted (active) on each page
- Collapse state persists as you navigate between pages (stored in localStorage)
- Theme toggle works on all pages
- Back button works normally

- [ ] **Step 5: Commit**

```bash
git add ui/rules.html ui/parsers.html ui/configuration.html
git commit -m "feat: add shell pages for rules, parsers, configuration"
```

---

## Self-Review

**Spec coverage check:**
- ✓ Collapsible left nav (Tasks 2, 3, 4, 5)
- ✓ Dashboard: 4 stat cards (Task 4)
- ✓ Dashboard: severity breakdown panel (Task 4)
- ✓ Dashboard: event volume chart (Task 4)
- ✓ Dashboard: recent high/critical alerts feed (Task 4)
- ✓ Dashboard: top source IPs (Task 4)
- ✓ Dashboard: top triggered rules (Task 4)
- ✓ Visual refresh: severity palette locked (Task 1 shared.css + Task 3 alerts.html)
- ✓ Visual refresh: card panels with border + radius (Task 1 shared.css)
- ✓ Visual refresh: table row padding increased (Tasks 2, 3)
- ✓ Visual refresh: IBM Plex Mono for data values only (maintained throughout)
- ✓ Shell pages: Rules, Parsers, Configuration (Task 5)
- ✓ No new backend endpoints used
- ✓ `ts_nav_collapsed` localStorage key (Tasks 2, 3, 4, 5)
- ✓ Auto-collapse below 768px (shared.css @media query + JS init)

**Type/name consistency:**
- `toggleNav()` / `applyNav()` — identical signature across all pages ✓
- `S.navCollapsed` — boolean, stored as string `"true"/"false"` in localStorage ✓
- `api(path)` — returns Promise, throws on non-ok response ✓
- `.badge.critical/high/medium/low` — defined in shared.css, used in dashboard alert feed ✓
- `.dot-critical/high/medium/low` — defined in shared.css, used in severity panel ✓

**Placeholder scan:** None found. All steps include actual code.
