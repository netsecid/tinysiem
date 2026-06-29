# TinySIEM — UI Design Prompt

## Task

Generate a complete, self-contained **single HTML file** that is a high-fidelity
interactive mockup of TinySIEM — a lightweight, AI-native SIEM dashboard. This is
a visual prototype with simulated data. No backend required. All data is hardcoded
or randomly generated in JavaScript.

The output must be **one single `.html` file** with all CSS and JavaScript inline.
No external dependencies except Google Fonts and CDN-hosted chart libraries.

---

## Product Context

**TinySIEM** is a minimal, composable SIEM built for small security teams, solo
analysts, and developers who want a clean alternative to bloated platforms like
Wazuh or Splunk. It ingests logs, decodes them, evaluates detection rules, and
surfaces alerts — with an AI layer that understands threats semantically, not just
by keyword matching.

The UI should feel like a **precision instrument**: purposeful, fast, information-
dense without being cluttered. Think: a terminal that grew up into a proper app.

---

## Design System

### Typography

- **UI font:** `IBM Plex Sans` (Google Fonts) — weights 300, 400, 500, 600
- **Mono font:** `IBM Plex Mono` (Google Fonts) — weight 400, 500
  Use mono font for: IP addresses, log lines, rule names, event IDs, timestamps,
  any code or data values
- **Base size:** 14px body, 12px secondary/meta, 11px labels/badges
- **Line height:** 1.5 for body, 1.3 for headings

### Color Palette — Dark Mode (Default)

```css
--bg-base:        #080D17;   /* deepest background */
--bg-surface:     #0D1424;   /* sidebar, cards */
--bg-elevated:    #121B31;   /* modals, dropdowns */
--bg-subtle:      #1A2540;   /* hover states, table rows */
--border:         #1E2D47;   /* dividers, card borders */
--border-strong:  #2A3F5F;   /* focused inputs */

--text-primary:   #E4EAF4;   /* headings, primary content */
--text-secondary: #6B7FA3;   /* labels, meta, captions */
--text-muted:     #3D5070;   /* placeholders, disabled */

--accent:         #3B82F6;   /* primary CTA, links, active nav */
--accent-glow:    rgba(59,130,246,0.15);  /* soft glow behind accent */
--accent-hover:   #2563EB;

--sev-critical:   #EF4444;   /* critical alerts */
--sev-high:       #F97316;   /* high severity */
--sev-medium:     #F59E0B;   /* medium severity */
--sev-low:        #22C55E;   /* low severity / ok */
--sev-info:       #3B82F6;   /* informational */

--chart-1:        #3B82F6;
--chart-2:        #8B5CF6;
--chart-3:        #22C55E;
--chart-4:        #F59E0B;
```

### Color Palette — Light Mode

```css
--bg-base:        #F0F4FA;
--bg-surface:     #FFFFFF;
--bg-elevated:    #FFFFFF;
--bg-subtle:      #F1F5FD;
--border:         #D9E2F0;
--border-strong:  #93AED4;

--text-primary:   #0D1424;
--text-secondary: #4A5F82;
--text-muted:     #8CA0BF;

--accent:         #2563EB;
--accent-glow:    rgba(37,99,235,0.10);
--accent-hover:   #1D4ED8;

/* severity colors same as dark */
```

### Spacing

Use 4px base grid. Common values: 4, 8, 12, 16, 20, 24, 32, 40, 48px.

### Shadows (Dark)

```css
--shadow-card:  0 1px 3px rgba(0,0,0,0.4), 0 0 0 1px var(--border);
--shadow-glow:  0 0 20px rgba(59,130,246,0.08);
```

### Border Radius

- Cards: 8px
- Badges/pills: 4px
- Buttons: 6px
- Inputs: 6px
- Modals: 10px

---

## Layout

```
┌─────────────────────────────────────────────────────────┐
│  Sidebar (220px fixed) │  Main Content Area (flex-1)    │
│                        │  ┌─────────────────────────┐   │
│  [TinySIEM wordmark]   │  │  Topbar                 │   │
│                        │  └─────────────────────────┘   │
│  Nav items             │                                 │
│  (with icons)          │  Page content                   │
│                        │                                 │
│                        │                                 │
│  ─────────────────     │                                 │
│  Profile (bottom)      │                                 │
└─────────────────────────────────────────────────────────┘
```

### Sidebar

- Fixed left, full viewport height, `--bg-surface` background
- Right border: 1px solid `--border`
- **Logo:** `TinySIEM` wordmark at top-left, padding 20px 16px
  - "Tiny" in `--text-secondary` weight 300
  - "SIEM" in `--accent` weight 600
  - Below it: a green pulsing dot + text `● LIVE` in 11px `--sev-low`
    (the dot pulses with a subtle CSS animation)
- **Navigation items** (each with a Lucide SVG icon inline):
  - Home (LayoutDashboard icon)
  - Alerts (Bell icon) — with badge showing count `12`
  - Events (List icon)
  - Rules (Shield icon)
  - Decoders (Code2 icon)
  - Settings (Settings icon)
  - (divider)
- **Bottom of sidebar:**
  - Profile item (User icon + "analyst@local")
  - Dark/light toggle (Moon/Sun icon, animated switch)
- Active nav item: left 3px accent border + `--accent-glow` background + text in
  `--accent`
- Hover: `--bg-subtle` background, text `--text-primary`
- Transition on all hover states: 150ms ease

### Topbar (per page)

- Height: 52px
- Content: page title left, right side has: search input + notification bell +
  avatar circle
- Bottom border: 1px solid `--border`
- Search input: rounded, `--bg-subtle` background, placeholder "Search events,
  IPs, rules..."

---

## Pages

Implement all 7 pages as JavaScript-driven view switches (no page reload).
Only one view visible at a time.

---

### Page 1: Home (Dashboard)

Show a bento-style grid of widgets. All charts use Chart.js from CDN.

#### Row 1 — Stat Cards (4 columns)

Each card has: icon, label, large number, and a trend indicator (↑/↓ + %).

| Card | Value | Trend | Icon |
|------|-------|-------|------|
| Events Today | 24,831 | ↑ 12% | Activity |
| Active Alerts | 12 | ↑ 3 new | Bell |
| Rules Loaded | 23 | — | Shield |
| Avg Ingest Rate | 4.2/s | ↓ 0.8/s | Zap |

Card style: `--bg-surface` background, border, shadow-card, 16px padding.
Large number in 28px IBM Plex Sans weight 600.
Trend positive = `--sev-low`, trend negative = `--sev-critical`.

#### Row 2 — Two charts side by side

**Left (60% width): Events per Minute — Animated Line Chart**
- Time axis: last 30 minutes (x-axis labels every 5 min)
- Two datasets: `Total Events` (blue) and `Alerts Triggered` (orange)
- Smooth curve, filled area with gradient (from accent color to transparent)
- Y-axis hidden, grid lines subtle (`--border`)
- Data auto-refreshes (simulated): every 3 seconds, append a new random data
  point and shift the oldest off the left
- Chart.js line chart with `tension: 0.4`
- Title: "Event Stream" — subtitle: "Live · last 30 min"

**Right (40% width): Alert Severity — Donut Chart**
- Segments: Critical (2), High (4), Medium (6), Low (0)
- Colors: sev-critical, sev-high, sev-medium, sev-low
- Center text: "12" large + "Active Alerts" small
- Legend below: colored dots + label + count
- Animate on load (Chart.js animation)

#### Row 3 — Two panels side by side

**Left: Top Source IPs**
- Table: IP address (mono), Event Count, Alert Count, Last Seen
- 5 rows of sample data (mix of private and public IPs)
- Clicking a row highlights it
- Horizontal mini-bar behind event count column (CSS width trick)

**Right: Recent Alerts Feed**
- Scrollable list of 8 alert items
- Each item: severity badge (colored pill) | rule name (mono) | source IP (mono)
  | time ago
- Severity badges: colored background + text (CRITICAL / HIGH / MEDIUM / LOW)
- Subtle divider between items
- "View all →" link at bottom

---

### Page 2: Alerts

Full alert management table.

**Filter bar above table:**
- Severity filter: All | Critical | High | Medium | Low (pill toggles)
- Status filter: All | New | Acknowledged | Closed (pill toggles)
- Date range input (simulated)
- Search input

**Table columns:**
`Severity` | `Rule` | `Source IP` | `URI` | `Triggered At` | `Status` | `Actions`

- 15 rows of mock data
- Severity column: colored badge
- Rule column: mono font, link style
- Status column: pill badge (New = blue, Acknowledged = yellow, Closed = gray)
- Actions column: Acknowledge button + Close button (small, ghost style)
- Row hover: `--bg-subtle`
- Clicking a row opens a **slide-in detail panel** from the right (400px wide):
  - Header: severity + rule name
  - Sections: Event Details, Raw Log (mono code block styled), Rule Details,
    MITRE ATT&CK (tactic + technique badge), Recommended Action
  - Close button (X) at top right
  - Panel slides in with CSS transition (300ms ease)

---

### Page 3: Events

Raw event log browser.

**Filter bar:** Source (nginx / all), Status Code filter, Time range, Search

**Table columns:**
`Time` | `Source` | `Source IP` | `Method` | `URI` | `Status` | `Size` | `User Agent`

- 20 rows of mock nginx log data
- Time in mono
- Status column: colored badge (2xx = green, 3xx = blue, 4xx = orange, 5xx = red)
- URI truncated with ellipsis if long, full on hover tooltip
- Clicking row: slide-in panel showing full decoded event as JSON code block
  (syntax-highlighted manually with spans, no library needed)

**Pagination bar** at bottom: Previous | 1 2 3 ... | Next

---

### Page 4: Rules

Detection rules management.

**Header:** "Rules" title + "Load Rule" button (accent, right side)

**Rule cards grid (2 columns):**

Each card shows:
- Top: Rule name (mono, bold) + severity badge (right)
- Source tag: `nginx` `windows` etc. (pill)
- Description: one line of text
- Stats row: Triggers (count) | Last Triggered (time ago) | MITRE technique
- Footer: toggle switch (enabled/disabled) + Edit button + Preview button

Sample rules:
1. `http_404_spike` — Medium — Multiple 404s from same IP — 47 triggers
2. `http_500_error` — High — Server-side errors — 8 triggers
3. `large_response_body` — Low — Unusually large response — 3 triggers
4. `suspicious_user_agent` — High — Known bad UA strings — 12 triggers
5. `rapid_post_requests` — Critical — POST flood pattern — 1 trigger
6. `directory_traversal` — Critical — Path traversal attempt — 0 triggers

Toggle switch: animate smoothly 200ms, thumb slides.
"Preview" opens a modal with the YAML rule definition in a code block (mono, dark
bg even in light mode, subtle syntax coloring).

---

### Page 5: Decoders

Log decoder management.

**Header:** "Decoders" title + "New Decoder" button

**Decoder cards (list style, full width):**

Each row/card:
- Left: decoder icon (Code2) + name (mono) + source type pill
- Middle: field count, pattern type (regex / json / kv), last matched time
- Right: Test button + View YAML button + Active toggle

Sample decoders:
1. `nginx_access` — regex — 9 fields — matched 2 minutes ago — Active
2. `syslog_auth` — regex — 6 fields — matched 1 hour ago — Active
3. `json_generic` — json — dynamic — matched 5 min ago — Active
4. `windows_evtx` — kv — 11 fields — never matched — Inactive

"View YAML" opens a modal showing the YAML definition in a styled code block.

**"Test Decoder" modal** (for "Test" button):
- Textarea to paste a raw log line
- "Run Test" button
- Output area showing: matched decoder name, extracted fields as a formatted
  JSON-style table

---

### Page 6: Settings

Clean settings layout with sections.

**Section: Storage**
- DuckDB path: `/app/data/tinysiem.duckdb` (mono) — Size: `142 MB`
- ChromaDB path: `/app/data/chroma_store` (mono) — Vectors: `24,831`
- Progress bars showing used/available (simulated 28% used)

**Section: Alert Destinations**
- Current: File — `alerts/alerts.log` — Status: Active (green dot)
- Greyed out future options: Slack webhook, Email SMTP (with "Coming soon" badge)

**Section: Ingestion**
- Max file upload: 50 MB
- API rate limit: Unlimited (v0.1)
- Log retention: 90 days

**Section: Application**
- Debug mode toggle (currently off)
- TinySIEM version: `0.1.0`
- API docs: Disabled (toggle)

**Section: Danger Zone** (red border card)
- "Flush All Events" button (destructive, red outline)
- "Reset ChromaDB Index" button (destructive, red outline)
- Both show a confirmation modal before "executing"

---

### Page 7: Profile

Simple centered card layout.

**User card:**
- Avatar circle: initials `AL` (analyst local) — `--accent` background
- Name: `analyst`
- Role badge: `SOC Analyst` (blue pill)
- Host: `localhost`

**API Key section:**
- Label: "API Key"
- Masked display: `●●●●●●●●●●●●●●●● abc1` (mono)
- Show/Hide toggle button
- Copy to clipboard button (shows "Copied!" toast on click)
- Regenerate button (shows confirmation modal)

**Theme section:**
- Dark / Light toggle (same as sidebar)
- Current theme label

**TinySIEM info:**
- Version: 0.1.0
- Storage: DuckDB + ChromaDB
- Uptime: 2d 4h 12m (simulated, counting up live)

---

## Animations & Live Feel

1. **Sidebar LIVE indicator:** green dot pulses every 2s (`@keyframes pulse`)
2. **Event stream chart:** new data appended every 3 seconds, smooth scroll-left
3. **Stat cards on load:** count up from 0 to their value over 800ms on page load
4. **Alert feed:** new item appears at top every 15 seconds with a fade-in + slide-
   down animation (simulate live incoming alert)
5. **Toast notifications:** when copying API key or acknowledging an alert, show a
   small toast (bottom-right, slides up, auto-dismisses after 2.5s)
6. **Page transitions:** switching between pages fades out/in (150ms opacity)
7. **Slide-in panels:** `transform: translateX(100%)` → `translateX(0)`, 300ms ease
8. **Ingest rate counter in topbar:** small blinking cursor `_` next to event count
9. **All hover states:** 150ms ease transition on background and color
10. **Dark/light toggle:** smooth transition on all color variables (250ms)

---

## Dark / Light Toggle Behavior

- Default: dark mode
- Toggle in sidebar bottom and profile page
- On toggle: add/remove `light` class on `<html>` element
- All colors via CSS variables — switch the variables at `:root.light { ... }`
- Transition all colors: `transition: background-color 250ms ease, color 250ms ease,
  border-color 250ms ease`
- Persist preference in `localStorage` and apply on load (no flash)

---

## Chart.js CDN

Load from:
```html
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
```

Chart global defaults:
```javascript
Chart.defaults.color = 'var(--text-secondary)';
Chart.defaults.font.family = 'IBM Plex Sans';
Chart.defaults.font.size = 12;
```

---

## Component Library (Inline, No Framework)

Implement these as reusable HTML/CSS patterns:

- **Badge/pill:** `<span class="badge badge-critical">CRITICAL</span>`
- **Button variants:** primary (accent fill), ghost (transparent + border), danger
- **Toggle switch:** CSS-only sliding thumb
- **Modal:** fixed overlay + centered card + close button
- **Slide panel:** fixed right, 400px, scrollable content
- **Toast:** fixed bottom-right stack
- **Code block:** `--bg-base` background, mono font, copy button top-right,
  horizontal scroll for long lines
- **Table:** hover rows, sticky header, alternating subtle row tint option
- **Stat card:** icon + number + trend + label

---

## Sample Data

Use realistic-looking fake data throughout:

**IPs:** Mix of private (192.168.x.x, 10.x.x.x) and public (45.33.32.156,
185.234.219.45, 203.0.113.42, 103.21.244.12)

**URIs:** `/api/v1/auth`, `/api/v1/users`, `/admin/login`, `/.env`,
`/wp-admin/`, `/api/v1/transactions`, `/health`, `/static/app.js`

**User Agents:** Mix of legitimate browsers and suspicious strings
(`sqlmap/1.7`, `curl/7.88.1`, `Mozilla/5.0 ...Chrome...`, `python-requests/2.31`)

**Rule names (mono):** `http_404_spike`, `http_500_error`, `directory_traversal`,
`rapid_post_requests`, `suspicious_user_agent`, `large_response_body`

**Alert timestamps:** relative ("2 min ago", "14 min ago", "1h 3m ago")

---

## Deliverable Requirements

- Single `.html` file, all inline
- Works offline except Google Fonts and Chart.js CDN
- No React, no Vue, no build tools — vanilla HTML + CSS + JS only
- JavaScript organized in clearly commented sections
- Default to dark mode, respects localStorage preference
- All 7 pages navigable via sidebar
- Minimum 1280px wide design (no mobile responsiveness needed for mockup)
- No placeholder "Lorem ipsum" — use realistic SIEM data throughout
- Console must be clean (no JS errors)