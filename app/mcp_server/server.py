"""MCP server for TinySIEM — mounted at /mcp when TINYSIEM_MCP_ENABLED=true.

Tools are the agent's contract with the SIEM. Each tool description documents
its params with a concrete example so agents (Claude Desktop, Claude Code,
opencode, ...) don't have to guess field names or query syntax.

Context-assembly tools (investigate_ip, get_alert_context) exist specifically
to cut multi-round-trip hunting: one call returns the whole picture instead of
an agent chaining 5-10 primitive queries.

Security:
- Every tool runs behind _JWTMiddleware (JWT required, analyst role or above)
- query_events_sql goes through the same read-only validation as the REST
  sandbox (app/query/router.py) — SELECT/WITH/SHOW/DESCRIBE/EXPLAIN/VALUES only
"""
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.auth import decode_token

logger = logging.getLogger(__name__)

_MCP_ALLOWED_ROLES = {"analyst", "admin", "superadmin"}


class _JWTMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            payload = decode_token(auth[7:])
            if payload and payload.get("role") in _MCP_ALLOWED_ROLES:
                from app.storage import duckdb_store
                user_row = duckdb_store.get_user_by_id(payload.get("sub", ""))
                if (
                    user_row is not None
                    and payload.get("epoch", 0) == user_row.get("token_epoch", 0)
                    and not user_row.get("must_change_password")
                ):
                    return await call_next(request)
        return JSONResponse({"error": "Unauthorized"}, status_code=401)


# ── Context assembly (importable, unit-testable without FastMCP) ─────────────


def build_ip_context(ip: str, days: int = 7) -> dict:
    """One-call entity pivot for an IP: summary, top activity, alerts, cases."""
    from datetime import datetime, timedelta, timezone
    from app.alerts.router import read_all_alerts
    from app.cases import store as case_store
    from app.storage import duckdb_store

    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    summary = duckdb_store.get_ip_summary(ip, start, end)

    all_alerts = read_all_alerts()
    related_alerts = [a for a in all_alerts if a.get("source_ip") == ip]
    related_alerts.sort(key=lambda a: a.get("triggered_at", ""), reverse=True)

    case_ids_seen: set = set()
    related_cases = []
    for alert in related_alerts[:50]:
        for c in case_store.get_cases_for_alert(alert.get("alert_id", "")):
            if c["case_id"] not in case_ids_seen:
                case_ids_seen.add(c["case_id"])
                related_cases.append(c)

    return {
        "ip": ip,
        **summary,
        "related_alerts": related_alerts[:50],
        "related_cases": related_cases,
    }


def build_alert_context(alert_id: str) -> dict:
    """One-call context for an alert: alert + event + cases + playbook + IP."""
    from datetime import datetime, timedelta, timezone
    from app.alerts.router import read_all_alerts
    from app.cases import store as case_store
    from app.rules import engine as rule_engine
    from app.storage import duckdb_store

    alerts = read_all_alerts()
    alert = next((a for a in alerts if a.get("alert_id") == alert_id), None)
    if alert is None:
        return {"alert_id": alert_id, "error": "alert not found"}

    ctx = {"alert": alert}

    event_id = alert.get("event_id")
    if event_id:
        ctx["event"] = duckdb_store.get_event_by_id(event_id)

    ctx["cases"] = case_store.get_cases_for_alert(alert_id)

    rule = next((r for r in rule_engine._rules if r.get("name") == alert.get("rule_name")), None)
    if rule:
        ctx["rule"] = {
            "name": rule.get("name"),
            "severity": rule.get("severity"),
            "source": rule.get("source"),
            "mitre_tactic": rule.get("mitre_tactic"),
            "mitre_technique": rule.get("mitre_technique"),
            "playbook": rule.get("playbook"),
        }

    src_ip = alert.get("source_ip")
    if src_ip:
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=7)
        ctx["ip_summary"] = duckdb_store.get_ip_summary(src_ip, start, end)

    return ctx


def build_mcp_app():
    from mcp.server.fastmcp import FastMCP
    from app.alerts.router import read_all_alerts
    from app.config import settings
    from app.decoder import engine as decoder_engine
    from app.query.router import _execute, validate_read_only
    from app.rules import engine as rule_engine
    from app.storage import duckdb_store

    mcp = FastMCP("TinySIEM")

    @mcp.tool()
    def list_events(
        source: str = "",
        source_ip: str = "",
        method: str = "",
        uri: str = "",
        q: str = "",
        limit: int = 50,
    ) -> dict:
        """Search ingested events.

        Params (all optional):
          source    log source name, e.g. "sshd", "nginx", "aws_cloudtrail"
          source_ip filter by IP (substring match), e.g. "45.153.34.161"
          method    exact method/action, e.g. "Failed password" (for sshd events
                    the action is stored in method), "GET", "POST"
          uri       substring match on request URI (web logs)
          q         full-text search of the raw log line
          limit     max events to return (1-200)

        Example: list_events(source="sshd", source_ip="45.153.34.161",
                             method="Failed password", limit=20)
        """
        result = duckdb_store.query_events(
            source=source or None,
            source_ip=source_ip or None,
            method=method or None,
            uri=uri or None,
            q=q or None,
            limit=min(limit, 200),
        )
        return result

    @mcp.tool()
    def get_alerts(
        severity: str = "",
        rule_name: str = "",
        source_ip: str = "",
        limit: int = 50,
    ) -> dict:
        """Search alerts.

        Params (all optional):
          severity   one of: low, medium, high, critical
          rule_name  substring of the rule name, e.g. "ssh-bruteforce",
                     "watchlist:" for IOC watchlist hits
          source_ip  exact attacker/source IP
          limit      max alerts to return (1-200)

        Example: get_alerts(severity="high", rule_name="ssh-bruteforce",
                            limit=10)
        """
        alerts = read_all_alerts()
        if severity:
            alerts = [a for a in alerts if (a.get("severity") or "").lower() == severity.lower()]
        if rule_name:
            alerts = [a for a in alerts if rule_name.lower() in (a.get("rule_name") or "").lower()]
        if source_ip:
            alerts = [a for a in alerts if a.get("source_ip") == source_ip]
        alerts.sort(key=lambda a: a.get("triggered_at", ""), reverse=True)
        return {"total": len(alerts), "alerts": alerts[:min(limit, 200)]}

    @mcp.tool()
    def list_parsers() -> dict:
        """List all loaded log parsers (built-in and custom).

        Use this before ingesting a new log type to find the exact `source`
        name to pass to /ingest. Example output: {"parsers": [{"name":
        "nginx_access", "source": "nginx", "type": "regex"}, ...]}
        """
        result = []
        for source, decoder in decoder_engine._decoders.items():
            result.append({
                "name": decoder.get("name", source),
                "source": source,
                "type": decoder.get("type", "regex"),
            })
        return {"parsers": result}

    @mcp.tool()
    def list_rules() -> dict:
        """List all loaded detection rules with severity and MITRE mapping.

        Use this to find rule names for get_alerts(rule_name=...) or to check
        detection coverage. Example: {"rules": [{"name": "ssh-bruteforce",
        "severity": "high", "source": "sshd"}, ...]}
        """
        result = [
            {
                "name": r.get("name", ""),
                "severity": r.get("severity", ""),
                "source": r.get("source", ""),
            }
            for r in rule_engine._rules
        ]
        return {"rules": result}

    @mcp.tool()
    def get_health() -> dict:
        """Return instance health, event count and alert count.

        Cheap sanity check before deeper queries.
        """
        event_data = duckdb_store.query_events(limit=1)
        alert_count = len(read_all_alerts())
        return {
            "status": "ok",
            "version": settings.tinysiem_version,
            "event_count": event_data.get("total", 0),
            "alert_count": alert_count,
        }

    @mcp.tool()
    def investigate_ip(ip: str, days: int = 7) -> dict:
        """Full-context investigation for one IP address.

        Returns first/last seen, event volume, top methods and sources,
        hourly activity histogram, up to 50 related alerts and any cases
        linked to those alerts. Use this when an alert references an IP or
        when asked 'what do we know about this IP?'.

        Example: investigate_ip(ip="45.153.34.161", days=7)
        """
        return build_ip_context(ip, days)

    @mcp.tool()
    def get_alert_context(alert_id: str) -> dict:
        """Full context for one alert: the alert record, its triggering
        event, linked cases, the rule's MITRE mapping and playbook, and a
        summary of the alert's source IP.

        Use this as the FIRST step of any alert investigation.

        Example: get_alert_context(alert_id="49034630-1b3c-4dc0-90e1-a16c7")
        """
        return build_alert_context(alert_id)

    @mcp.tool()
    def query_events_sql(query: str, params: Optional[list] = None) -> dict:
        """Run a READ-ONLY SQL query against the events database.

        Allowed statements: SELECT, WITH, SHOW, DESCRIBE, EXPLAIN, VALUES.
        INSERT/UPDATE/DELETE/DROP/ALTER/CREATE/COPY/PRAGMA are rejected.
        Rows are capped at 1000, cells at 500 chars, queries time out.

        Useful for aggregations the API can't express, e.g.
        query_events_sql(query="SELECT source_ip, COUNT(*) AS n FROM events
        WHERE method = 'Failed password' GROUP BY source_ip ORDER BY n DESC
        LIMIT 10")
        """
        validate_read_only(query)
        columns, rows = _execute(query, params)
        return {"columns": columns, "rows": rows[:1000], "total_rows": len(rows)}

    raw_app = mcp.asgi_app()
    raw_app.add_middleware(_JWTMiddleware)
    return raw_app
