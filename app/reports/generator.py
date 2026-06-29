import html
import logging
import threading
import time
from collections import Counter
from datetime import datetime, timedelta

from app.storage import duckdb_store

logger = logging.getLogger(__name__)


def _parse_dt(ts):
    if not ts:
        return datetime.min
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return datetime.min


def generate_report(period: str = "daily") -> dict:
    from app.alerts.router import _read_all_alerts
    now = datetime.utcnow()
    window_start = now - timedelta(days=7 if period == "weekly" else 1)

    alerts = _read_all_alerts()
    window_alerts = [a for a in alerts if _parse_dt(a.get("triggered_at")) >= window_start]

    sev_counts: dict = Counter((a.get("severity") or "unknown").lower() for a in window_alerts)
    status_counts: dict = Counter(a.get("status", "open") for a in window_alerts)
    rule_counts: dict = Counter(a.get("rule_name") or "unknown" for a in window_alerts)

    top_rules = [{"rule": r, "count": c} for r, c in rule_counts.most_common(10)]

    facets = duckdb_store.get_event_facets(start=window_start)
    top_ips = [{"ip": x["value"], "count": x["count"]} for x in facets.get("source_ip", [])[:10]]

    total_events = duckdb_store.count_events_in_window_range(window_start, now)

    recent_critical = sorted(
        [a for a in window_alerts if (a.get("severity") or "").lower() in ("critical", "high")],
        key=lambda a: a.get("triggered_at", ""),
        reverse=True,
    )[:5]

    return {
        "period": period,
        "generated_at": now.isoformat(),
        "window_start": window_start.isoformat(),
        "window_end": now.isoformat(),
        "summary": {
            "total_events": total_events,
            "total_alerts": len(window_alerts),
            "alerts_by_severity": dict(sev_counts),
            "alerts_by_status": dict(status_counts),
        },
        "top_source_ips": top_ips,
        "top_rules": top_rules,
        "recent_high_critical_alerts": recent_critical,
    }


def render_html(report: dict) -> str:
    esc = html.escape
    period_label = "Weekly" if report["period"] == "weekly" else "Daily"
    s = report["summary"]
    rows_ips = "".join(
        f"<tr><td>{esc(str(x['ip']))}</td><td>{esc(str(x['count']))}</td></tr>"
        for x in report["top_source_ips"]
    )
    rows_rules = "".join(
        f"<tr><td>{esc(str(x['rule']))}</td><td>{esc(str(x['count']))}</td></tr>"
        for x in report["top_rules"]
    )
    rows_alerts = "".join(
        f"<tr><td>{esc(str(a.get('triggered_at', '')))}</td>"
        f"<td>{esc(str(a.get('severity', '')))}</td>"
        f"<td>{esc(str(a.get('rule_name', '')))}</td>"
        f"<td>{esc(str(a.get('source_ip', '')))}</td></tr>"
        for a in report["recent_high_critical_alerts"]
    )
    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>TinySIEM {esc(period_label)} Report</title>
<style>
body {{ font-family: sans-serif; max-width: 900px; margin: 40px auto; color: #1f2937; }}
h1 {{ color: #111827; }}
h2 {{ color: #374151; border-bottom: 1px solid #e5e7eb; padding-bottom: 4px; }}
table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
th, td {{ border: 1px solid #e5e7eb; padding: 8px 12px; text-align: left; }}
th {{ background: #f9fafb; font-weight: 600; }}
.stat {{ display: inline-block; background: #f3f4f6; border-radius: 8px;
         padding: 12px 24px; margin: 8px; text-align: center; }}
.stat-num {{ font-size: 28px; font-weight: 700; }}
.stat-lbl {{ font-size: 13px; color: #6b7280; }}
</style></head>
<body>
<h1>TinySIEM {esc(period_label)} Report</h1>
<p>Generated: {esc(report['generated_at'])} UTC &nbsp;|&nbsp;
   Window: {esc(report['window_start'])} → {esc(report['window_end'])}</p>
<h2>Summary</h2>
<div>
  <div class="stat"><div class="stat-num">{esc(str(s['total_events']))}</div><div class="stat-lbl">Events</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['total_alerts']))}</div><div class="stat-lbl">Alerts</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['alerts_by_severity'].get('critical', 0)))}</div><div class="stat-lbl">Critical</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['alerts_by_severity'].get('high', 0)))}</div><div class="stat-lbl">High</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['alerts_by_status'].get('open', 0)))}</div><div class="stat-lbl">Open</div></div>
  <div class="stat"><div class="stat-num">{esc(str(s['alerts_by_status'].get('resolved', 0)))}</div><div class="stat-lbl">Resolved</div></div>
</div>
<h2>Top Source IPs</h2>
<table><tr><th>IP</th><th>Event Count</th></tr>
{rows_ips or '<tr><td colspan="2">No data</td></tr>'}
</table>
<h2>Top Rules Triggered</h2>
<table><tr><th>Rule</th><th>Alert Count</th></tr>
{rows_rules or '<tr><td colspan="2">No data</td></tr>'}
</table>
<h2>Recent High / Critical Alerts</h2>
<table><tr><th>Triggered At</th><th>Severity</th><th>Rule</th><th>Source IP</th></tr>
{rows_alerts or '<tr><td colspan="4">No high/critical alerts in this window</td></tr>'}
</table>
</body></html>"""


def _send_report_email(period: str) -> None:
    from app.config import settings
    if not settings.tinysiem_report_email or not settings.tinysiem_smtp_host:
        return
    try:
        import smtplib
        import ssl
        from email.mime.text import MIMEText
        report = generate_report(period)
        body = render_html(report)
        subject = f"[TinySIEM] {period.capitalize()} Report — {report['generated_at'][:10]}"
        msg = MIMEText(body, "html")
        msg["Subject"] = subject
        msg["From"] = settings.tinysiem_smtp_from or settings.tinysiem_smtp_user
        msg["To"] = settings.tinysiem_report_email
        recipients = [r.strip() for r in settings.tinysiem_report_email.split(",") if r.strip()]
        if settings.tinysiem_smtp_tls:
            ctx = ssl.create_default_context()
            with smtplib.SMTP(settings.tinysiem_smtp_host, settings.tinysiem_smtp_port) as s:
                s.starttls(context=ctx)
                if settings.tinysiem_smtp_user:
                    s.login(settings.tinysiem_smtp_user, settings.tinysiem_smtp_pass)
                s.sendmail(msg["From"], recipients, msg.as_string())
        else:
            with smtplib.SMTP(settings.tinysiem_smtp_host, settings.tinysiem_smtp_port) as s:
                if settings.tinysiem_smtp_user:
                    s.login(settings.tinysiem_smtp_user, settings.tinysiem_smtp_pass)
                s.sendmail(msg["From"], recipients, msg.as_string())
    except Exception as exc:
        logger.error(f"Report email failed: {exc}")


def start_report_scheduler() -> None:
    from app.config import settings
    schedule = settings.tinysiem_report_schedule
    if schedule == "disabled":
        return
    period = "weekly" if schedule == "weekly" else "daily"
    interval = 7 * 24 * 3600 if period == "weekly" else 24 * 3600
    target_hour = settings.tinysiem_report_hour

    def _loop():
        now = datetime.utcnow()
        seconds_until = (target_hour - now.hour) * 3600 - now.minute * 60 - now.second
        if seconds_until < 0:
            seconds_until += 24 * 3600
        time.sleep(seconds_until)
        while True:
            _send_report_email(period)
            time.sleep(interval)

    t = threading.Thread(target=_loop, daemon=True, name="report-scheduler")
    t.start()
    logger.info(f"Report scheduler started: {schedule} at hour {target_hour}")
