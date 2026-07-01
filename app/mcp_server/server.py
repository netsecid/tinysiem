import logging

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
                return await call_next(request)
        return JSONResponse({"error": "Unauthorized"}, status_code=401)


def build_mcp_app():
    from mcp.server.fastmcp import FastMCP
    from app.storage import duckdb_store
    from app.alerts.router import _read_all_alerts
    from app.decoder import engine as decoder_engine
    from app.rules import engine as rule_engine
    from app.config import settings

    mcp = FastMCP("TinySIEM")

    @mcp.tool()
    def list_events(
        source: str = "",
        source_ip: str = "",
        q: str = "",
        limit: int = 50,
    ) -> dict:
        """Search events. Returns list of matching events."""
        result = duckdb_store.query_events(
            source=source or None,
            source_ip=source_ip or None,
            q=q or None,
            limit=min(limit, 200),
        )
        return result

    @mcp.tool()
    def get_alerts(
        severity: str = "",
        rule_name: str = "",
        limit: int = 50,
    ) -> dict:
        """Search alerts. Returns list of matching alerts."""
        alerts = _read_all_alerts()
        if severity:
            alerts = [a for a in alerts if (a.get("severity") or "").lower() == severity.lower()]
        if rule_name:
            alerts = [a for a in alerts if rule_name.lower() in (a.get("rule_name") or "").lower()]
        alerts.sort(key=lambda a: a.get("triggered_at", ""), reverse=True)
        return {"total": len(alerts), "alerts": alerts[:min(limit, 200)]}

    @mcp.tool()
    def list_parsers() -> dict:
        """List all loaded parsers (built-in and custom)."""
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
        """List all loaded detection rules."""
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
        """Return instance health and summary stats."""
        event_data = duckdb_store.query_events(limit=1)
        alert_count = len(_read_all_alerts())
        return {
            "status": "ok",
            "version": settings.tinysiem_version,
            "event_count": event_data.get("total", 0),
            "alert_count": alert_count,
        }

    raw_app = mcp.asgi_app()
    raw_app.add_middleware(_JWTMiddleware)
    return raw_app
