# Spec: UI Polish (F7)

> Version: Ongoing — ships incrementally with each version  
> Status: Design  
> Reference: Datadog UI aesthetic (clean, minimalist, professional)

---

## Design Philosophy

The target aesthetic is Datadog's product UI: high information density, no decorative chrome, monochromatic base with semantic color accents only, precise typography, and smooth interactions that feel fast without being flashy.

This spec defines the design system. Individual pages should be built to it. Polish work does not change functionality — it improves visual consistency, readability, and information density without altering any behavior.

---

## Color System

Two themes: dark (default) and light. All colors are defined as CSS custom properties on `:root` and `[data-theme="light"]`.

### Dark theme (default)

```css
:root {
    /* Backgrounds */
    --bg-base:       #0f0f11;    /* page background */
    --bg-surface:    #17181c;    /* card, panel, widget surfaces */
    --bg-raised:     #1e1f24;    /* dropdown, modal, hover */
    --bg-border:     #2a2b32;    /* borders, dividers */

    /* Text */
    --text-primary:  #f0f0f2;    /* headings, labels */
    --text-secondary:#8b8d99;    /* secondary labels, metadata */
    --text-muted:    #55565e;    /* placeholder, disabled */

    /* Accent — Datadog purple-ish blue */
    --accent:        #7b61ff;
    --accent-hover:  #9b87ff;
    --accent-subtle: #7b61ff1a;  /* 10% opacity — hover backgrounds */

    /* Semantic colors */
    --sev-critical:  #f85149;    /* red */
    --sev-high:      #e36209;    /* orange */
    --sev-medium:    #d29922;    /* amber */
    --sev-low:       #3fb950;    /* green */

    --status-active: #3fb950;
    --status-stale:  #d29922;
    --status-silent: #f85149;

    /* Interactive */
    --btn-bg:        #7b61ff;
    --btn-hover:     #9b87ff;
    --btn-text:      #ffffff;

    --input-bg:      #1e1f24;
    --input-border:  #2a2b32;
    --input-focus:   #7b61ff;
}
```

### Light theme

```css
[data-theme="light"] {
    --bg-base:       #f8f8fa;
    --bg-surface:    #ffffff;
    --bg-raised:     #f0f0f4;
    --bg-border:     #e0e0e8;

    --text-primary:  #111114;
    --text-secondary:#5c5c70;
    --text-muted:    #9a9aaa;

    --accent:        #6b4fff;
    --accent-hover:  #5540dd;
    --accent-subtle: #6b4fff14;

    --sev-critical:  #d1242f;
    --sev-high:      #bc4c00;
    --sev-medium:    #9a6700;
    --sev-low:       #1a7f37;

    --status-active: #1a7f37;
    --status-stale:  #9a6700;
    --status-silent: #d1242f;

    --btn-bg:        #6b4fff;
    --btn-hover:     #5540dd;
    --btn-text:      #ffffff;

    --input-bg:      #ffffff;
    --input-border:  #d0d0dc;
    --input-focus:   #6b4fff;
}
```

---

## Typography

```css
body {
    font-family: 'Inter', 'IBM Plex Sans', system-ui, -apple-system, sans-serif;
    font-size: 13px;
    line-height: 1.5;
    color: var(--text-primary);
    background: var(--bg-base);
}

/* Monospace — log lines, code, raw fields */
.mono, code, pre {
    font-family: 'JetBrains Mono', 'IBM Plex Mono', 'Fira Code', monospace;
    font-size: 12px;
}
```

Sizes:
- Page headings: 18px / 500 weight
- Section headings: 13px / 600 weight / uppercase / letter-spacing 0.05em
- Body: 13px / 400 weight
- Secondary/metadata: 12px / var(--text-secondary)
- Badges: 11px / 600 weight / uppercase

---

## Navigation

```
┌──────────┬───────────────────────────────────────────────────────────────┐
│          │                         topbar                                  │
│  sidenav │───────────────────────────────────────────────────────────────│
│          │                         main content                            │
│          │                                                                  │
│          │                                                                  │
└──────────┴───────────────────────────────────────────────────────────────┘
```

**Sidenav:** 52px wide, icon-only by default. Expands to 180px with icon + label on hover (or locked open via toggle at bottom of nav). Dark bg always, regardless of theme.

**Nav item:**
```css
.nav-link {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
    border-radius: 6px;
    color: var(--text-secondary);
    text-decoration: none;
    font-size: 13px;
    transition: background 120ms, color 120ms;
}
.nav-link:hover, .nav-link.active {
    background: var(--accent-subtle);
    color: var(--text-primary);
}
.nav-link.active {
    color: var(--accent);
}
```

**Active state:** determined by `window.location.pathname`. Accent-colored icon, no bold.

**Topbar:** 48px height. Page title on left. Right side: user avatar/name + role badge + theme toggle + logout.

---

## Tables

Data tables are the primary UI component. Key rules:

- No outer border on the table itself — let rows breathe
- Alternating row bg: `--bg-surface` and `--bg-raised` (subtle, 2% opacity difference)
- Row hover: `--accent-subtle` background
- Sticky header
- Cells: 12px padding top/bottom, 16px left/right
- Column headers: 11px / uppercase / `--text-secondary` / letter-spacing 0.06em

```css
table {
    width: 100%;
    border-collapse: collapse;
    table-layout: fixed;
}
thead th {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-secondary);
    padding: 8px 16px;
    border-bottom: 1px solid var(--bg-border);
    position: sticky;
    top: 0;
    background: var(--bg-surface);
}
tbody tr {
    border-bottom: 1px solid var(--bg-border);
    transition: background 80ms;
}
tbody tr:hover {
    background: var(--accent-subtle);
    cursor: pointer;
}
td {
    padding: 10px 16px;
    font-size: 13px;
}
```

---

## Severity Badges

```css
.badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}
.badge-critical { background: var(--sev-critical)22; color: var(--sev-critical); }
.badge-high     { background: var(--sev-high)22;     color: var(--sev-high); }
.badge-medium   { background: var(--sev-medium)22;   color: var(--sev-medium); }
.badge-low      { background: var(--sev-low)22;      color: var(--sev-low); }
```

Status dot (for log source health):
```css
.status-dot {
    width: 7px;
    height: 7px;
    border-radius: 50%;
    display: inline-block;
}
.status-dot.active  { background: var(--status-active); box-shadow: 0 0 0 2px var(--status-active)33; }
.status-dot.stale   { background: var(--status-stale); }
.status-dot.silent  { background: var(--status-silent); }
```

---

## Buttons

```css
/* Primary */
.btn {
    padding: 6px 14px;
    border-radius: 6px;
    font-size: 13px;
    font-weight: 500;
    cursor: pointer;
    border: 1px solid transparent;
    transition: background 120ms, border-color 120ms;
}
.btn-primary {
    background: var(--btn-bg);
    color: var(--btn-text);
    border-color: var(--btn-bg);
}
.btn-primary:hover { background: var(--btn-hover); border-color: var(--btn-hover); }

/* Secondary — ghost */
.btn-secondary {
    background: transparent;
    color: var(--text-primary);
    border-color: var(--bg-border);
}
.btn-secondary:hover { background: var(--bg-raised); }

/* Danger */
.btn-danger {
    background: var(--sev-critical);
    color: #fff;
    border-color: var(--sev-critical);
}
```

Icon-only button: 28px × 28px, no label, tooltip via `title` attribute.

---

## Inputs and Filters

```css
.input {
    height: 32px;
    padding: 0 10px;
    border: 1px solid var(--input-border);
    border-radius: 6px;
    background: var(--input-bg);
    color: var(--text-primary);
    font-size: 13px;
    outline: none;
    transition: border-color 120ms;
}
.input:focus {
    border-color: var(--input-focus);
    box-shadow: 0 0 0 3px var(--accent-subtle);
}
```

Search inputs get a magnifying glass icon via `background-image` or an inline SVG wrapper.

Filter chips (active filter tags below the filter bar):
```css
.chip {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 8px;
    background: var(--accent-subtle);
    border: 1px solid var(--accent)44;
    border-radius: 100px;
    font-size: 12px;
    color: var(--accent);
}
.chip .chip-remove { cursor: pointer; opacity: 0.6; }
.chip .chip-remove:hover { opacity: 1; }
```

---

## Modals and Panels

Side panel (used for case detail):
- Width: 700px on desktop, 100% on mobile
- Slides in from right: `transform: translateX(100%) → translateX(0)` with 200ms ease
- Overlay: `rgba(0,0,0,0.6)` backdrop, click dismisses
- Header: 56px, title + close button
- Body: scrollable, 24px padding
- Footer (if needed): 64px, border-top, action buttons right-aligned

Modals (used for "New Case", "Escalate to Case"):
- Max width: 480px, centered
- Backdrop: same as panel
- Animation: `scale(0.96) → scale(1)` with 150ms ease, slight fade-in
- `Escape` key dismisses

---

## Charts

All charts use the browser's native Canvas API via a minimal charting helper (no Chart.js, no D3 — they're too heavy for a no-build project). Implement a lightweight `drawLine()`, `drawBar()`, `drawDonut()` in `ui/lib/charts.js` shared across pages.

Chart color palette (for multiple series):
```js
const CHART_COLORS = ['#7b61ff', '#3fb950', '#d29922', '#f85149', '#58a6ff', '#e09b6a'];
```

---

## Animations

Keep animations minimal and purposeful:

| Interaction | Animation |
|---|---|
| Row expand | `max-height: 0 → auto` with 150ms ease |
| Panel slide-in | `translateX(100%) → 0` with 200ms ease |
| Modal appear | `scale(0.96) + opacity 0 → scale(1) + opacity 1` with 150ms ease |
| Badge / chip appear | `opacity 0 → 1` with 100ms |
| Button state change | `background` transition 120ms |
| Loading spinner | simple 24px CSS border spinner, 0.8s linear infinite |

No scroll animations. No parallax. No entrance animations on page load.

---

## Loading States

Every async operation shows a loading state. Two patterns:

**Table skeleton:** while data loads, show 6 rows of gray placeholder bars (same height as real rows, animated shimmer):
```css
@keyframes shimmer {
    0%   { background-position: -200% 0; }
    100% { background-position: 200% 0; }
}
.skeleton {
    background: linear-gradient(90deg, var(--bg-border) 25%, var(--bg-raised) 50%, var(--bg-border) 75%);
    background-size: 200% 100%;
    animation: shimmer 1.2s infinite;
    border-radius: 4px;
    height: 14px;
}
```

**Inline spinner:** for widget refreshes and button-triggered operations.

**Empty state:** when a query returns 0 results, show a centered icon + text message (not just blank space). Example:
```
     📋
  No cases found
  Try clearing your filters
  or create the first case.

  [+ New Case]
```

Use simple Unicode or inline SVG icons — no icon library.

---

## Per-Page Polish Items

### events.html
- Replace raw text timestamps with relative time (`2h ago`) + absolute on hover
- Truncate `uri` column to 60 chars with ellipsis + full path on hover
- Add column resize handles (optional — drag to resize columns)

### alerts.html
- Add a mini-sparkline (7-day) in the alert summary header showing daily alert volume
- Status badges (open/investigating/closed) in consistent badge style

### cases.html (new)
- Build from scratch using this design system
- Case title truncates at 60 chars

### audit.html
- Monospace font for `detail` column values (they contain JSON-like content)
- Highlight `status: fail` rows in subtle red tint

### parsers.html / rules.html
- YAML code editors: add syntax highlighting via a lightweight tokenizer (no CodeMirror in v1.2 — just color keywords with regex in a `<pre contenteditable>`)

### configuration.html
- Tab navigation within the page for General / Log Sources / Baselines / Integrations / Users

---

## What NOT to Change

- Navigation structure (order of nav items, which pages exist)
- URL paths
- API response shapes
- Any behavioral functionality
- Loading sequences / data fetch patterns

Polish is purely CSS + minor DOM additions (skeleton loaders, empty states). No behavioral refactors during polish passes.
