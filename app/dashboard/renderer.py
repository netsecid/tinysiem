"""HTML export renderer — fetches widget data and produces a self-contained HTML snapshot."""
import json
from datetime import datetime, timedelta
from typing import Optional

from app.dashboard.store import get_dashboard


def _time_range_to_start(time_range: str) -> datetime:
    now = datetime.utcnow()
    delta_map = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800}
    return now - timedelta(seconds=delta_map.get(time_range, 86400))


def _fetch_widget_data(widget: dict) -> dict:
    wtype = widget.get("type", "")
    cfg = widget.get("config", {})
    time_range = cfg.get("time_range", "24h")
    start = _time_range_to_start(time_range)
    now = datetime.utcnow()

    try:
        if wtype == "event_volume":
            from app.storage.duckdb_store import get_event_histogram
            buckets = cfg.get("buckets", 48)
            return {"histogram": get_event_histogram(start, now, buckets)}

        if wtype in ("top_sources", "top_ips"):
            from app.storage.duckdb_store import get_event_facets
            facets = get_event_facets(start=start, end=now)
            key = "source" if wtype == "top_sources" else "source_ip"
            limit = cfg.get("limit", 10)
            return {"items": (facets.get(key) or [])[:limit]}

        if wtype == "alert_severity":
            from app.alerts.router import _read_alerts  # type: ignore
            alerts = _read_alerts(start=start, end=now, limit=5000)
            counts: dict[str, int] = {}
            for a in alerts:
                counts[a.get("severity", "unknown")] = counts.get(a.get("severity", "unknown"), 0) + 1
            return {"counts": counts}

        if wtype == "recent_alerts":
            from app.alerts.router import _read_alerts  # type: ignore
            limit = cfg.get("limit", 5)
            alerts = _read_alerts(limit=limit)
            return {"alerts": alerts}

        if wtype == "case_status":
            from app.cases import store as case_store
            return {"facets": case_store.get_case_facets()}

        if wtype == "baseline_health":
            from app.baselines import store as bs
            result = bs.query_violations(acknowledged=False, limit=100)
            sev_counts: dict[str, int] = {}
            for v in result.get("violations", []):
                s = v.get("severity", "unknown")
                sev_counts[s] = sev_counts.get(s, 0) + 1
            return {"total_unacked": result.get("total", 0), "by_severity": sev_counts}

    except Exception as exc:
        return {"error": str(exc)}

    return {}


def build_html_export(owner: str) -> str:
    dash = get_dashboard(owner)
    widget_data = {}
    for w in dash.get("widgets", []):
        widget_data[w["widget_id"]] = _fetch_widget_data(w)

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    data_json = json.dumps({
        "dashboard": dash,
        "widgetData": widget_data,
        "exportedAt": ts,
    })

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>TinySIEM Dashboard — {ts}</title>
<style>
body{{font-family:sans-serif;margin:24px;background:#0d0e17;color:#cdd0eb}}
h1{{font-size:18px;margin-bottom:8px}}
.ts{{font-size:11px;color:#7b7fa8;margin-bottom:24px}}
.grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}}
.widget{{background:#12131f;border:1px solid #252840;border-radius:6px;padding:14px}}
.widget h3{{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#7b7fa8;margin-bottom:10px}}
pre{{font-size:11px;color:#cdd0eb;white-space:pre-wrap;word-break:break-all}}
</style>
</head>
<body>
<h1>{dash.get('title','Dashboard')}</h1>
<div class="ts">Exported {ts}</div>
<div class="grid">
{"".join(
    f'<div class="widget"><h3>{w.get("title","Widget")}</h3><pre>{json.dumps(widget_data.get(w["widget_id"],{}), indent=2, default=str)}</pre></div>'
    for w in dash.get("widgets", [])
)}
</div>
<script>window.__DASHBOARD_DATA__={data_json};</script>
</body>
</html>"""
