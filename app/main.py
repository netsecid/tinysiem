import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.exceptions import HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from app.config import parse_cors_origins, settings
from app.startup_checks import (
    validate_jwt_secret,
    warn_if_default_superadmin_password,
    warn_if_integrations_missing_master_key,
)
from app.decoder import engine as decoder_engine
from app.listeners import syslog as syslog_listener
from app.ai.router import router as ai_router
from app.alerts.router import router as alerts_router
from app.dashboard.router import router as dashboard_router
from app.integrations.router import router as integrations_router
from app.audit.router import router as audit_router
from app.auth_router import router as auth_router
from app.baselines.router import router as baselines_router
from app.cases.router import router as cases_router
from app.events.router import router as events_router
from app.ingest.router import router as ingest_router
from app.parsers.router import router as parsers_router
from app.rules.router import router as rules_crud_router
from app.sbom.router import router as sbom_router
from app.sources.router import router as sources_router
from app.users.router import router as users_router
from app.password import hash_password
from app.rules import engine as rule_engine
from app.storage import duckdb_store

logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":"%(message)s"}',
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_jwt_secret(settings.tinysiem_jwt_secret)
    logger.info("TinySIEM starting up")
    duckdb_store.init_db()
    duckdb_store.init_alert_triage_table()
    duckdb_store.init_audit_table()
    duckdb_store.init_cases_tables()
    duckdb_store.init_baselines_tables()
    duckdb_store.init_integrations_tables()
    duckdb_store.init_dashboard_tables()
    duckdb_store.init_playbook_table()
    decoder_engine.load_decoders()
    rule_engine.load_rules()
    duckdb_store.ensure_superadmin(hash_password(settings.tinysiem_superadmin_password))
    warn_if_default_superadmin_password()
    warn_if_integrations_missing_master_key()
    from app.retention.archiver import start_retention_thread
    from app.reports.generator import start_report_scheduler
    start_retention_thread()
    start_report_scheduler()
    from app.listeners.syslog import start_syslog_listeners, stop_syslog_listeners
    _syslog_servers = await start_syslog_listeners()
    from app.baselines import engine as baseline_engine

    async def _baseline_loop():
        while True:
            try:
                await baseline_engine.run_once()
            except Exception as exc:
                logger.error(f"Baseline job error: {exc}")
            await asyncio.sleep(settings.tinysiem_baseline_interval_minutes * 60)

    asyncio.create_task(_baseline_loop())

    from app.integrations import runner as integration_runner

    async def _integration_loop():
        while True:
            try:
                await integration_runner.run_due()
            except Exception as exc:
                logger.error(f"Integration scheduler error: {exc}")
            await asyncio.sleep(60)

    asyncio.create_task(_integration_loop())
    yield
    logger.info("TinySIEM shutting down")
    stop_syslog_listeners(_syslog_servers)
    duckdb_store.close_db()


app = FastAPI(
    title="TinySIEM",
    version=settings.tinysiem_version,
    docs_url="/docs" if settings.tinysiem_debug else None,
    redoc_url="/redoc" if settings.tinysiem_debug else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=parse_cors_origins(settings.tinysiem_cors_origins),
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


@app.exception_handler(HTTPException)
async def audit_http_exception(request: Request, exc: HTTPException):
    """Log 4xx/5xx errors to audit log (except auth/health/ui noise)."""
    path = request.url.path
    skip = path.startswith("/ui") or path == "/health" or path == "/auth/login"
    if exc.status_code >= 400 and not skip:
        from app.audit import store as audit
        audit.log_event(
            "error.api",
            "error",
            "error",
            detail={
                "method": request.method,
                "path": path,
                "status_code": exc.status_code,
                "error": str(exc.detail)[:500],
            },
            error_msg=str(exc.detail)[:500],
        )
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


from app.notifications.router import router as notifications_router
from app.retention.router import router as retention_router
from app.reports.router import router as reports_router

app.include_router(ingest_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(cases_router)
app.include_router(sources_router)
app.include_router(baselines_router)
app.include_router(ai_router)
app.include_router(auth_router)
app.include_router(users_router)
app.include_router(parsers_router)
app.include_router(rules_crud_router)
app.include_router(notifications_router)
app.include_router(retention_router)
app.include_router(reports_router)
app.include_router(audit_router)
app.include_router(integrations_router)
app.include_router(dashboard_router)
app.include_router(sbom_router)

app.mount("/ui", StaticFiles(directory="/app/ui"), name="ui")


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse(url="/ui/dashboard.html")


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": settings.tinysiem_version,
        "listeners": {
            "syslog_udp": {
                "enabled": settings.tinysiem_syslog_udp_port > 0,
                "port": settings.tinysiem_syslog_udp_port,
            },
            "syslog_tcp": {
                "enabled": settings.tinysiem_syslog_tcp_port > 0,
                "port": settings.tinysiem_syslog_tcp_port,
            },
            "beats_http": {
                "enabled": settings.tinysiem_beats_enabled,
                "path": "/ingest/beats",
            },
            "syslog_dropped": syslog_listener.get_dropped_counts(),
        },
    }


if settings.tinysiem_mcp_enabled:
    from app.mcp_server.server import build_mcp_app
    app.mount("/mcp", build_mcp_app())
