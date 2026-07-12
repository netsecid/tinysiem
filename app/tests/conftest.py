"""
conftest.py — must set env vars before pydantic-settings reads them.
pytest loads this file first, so module-level side-effects execute before test collection.
"""
import os
import tempfile

# ── 1. Set env vars before pydantic-settings reads them ──────────────────────
_tmp = tempfile.mkdtemp()
os.environ["TINYSIEM_API_KEY"] = "test-api-key"
os.environ["TINYSIEM_DUCKDB_PATH"] = _tmp + "/test.duckdb"
os.environ["TINYSIEM_ALERTS_PATH"] = _tmp + "/alerts/alerts.log"
os.environ["TINYSIEM_DEBUG"] = "false"
os.environ["TINYSIEM_JWT_SECRET"] = "test-jwt-secret-for-tests-padded-to-be-compliant"
os.environ["TINYSIEM_SUPERADMIN_PASSWORD"] = "admin"
os.environ["TINYSIEM_CLAUDE_API_KEY"] = ""
os.environ["TINYSIEM_MCP_ENABLED"] = "false"
os.environ["TINYSIEM_ARCHIVE_PATH"] = _tmp + "/archive"
os.environ["TINYSIEM_SMTP_HOST"] = ""
os.environ["TINYSIEM_WEBHOOK_URL"] = ""
os.environ["TINYSIEM_REPORT_SCHEDULE"] = "disabled"
os.environ["TINYSIEM_SYSLOG_UDP_PORT"] = "0"
os.environ["TINYSIEM_SYSLOG_TCP_PORT"] = "0"
os.environ["TINYSIEM_BEATS_ENABLED"] = "true"
import base64
os.environ["TINYSIEM_MASTER_KEY"] = base64.urlsafe_b64encode(b"tinysiem-test-master-key-paddin!").decode()

# ── 2. Fixtures ───────────────────────────────────────────────────────────────
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

TEST_KEY = "test-api-key"
AUTH_HEADERS = {"Authorization": f"Bearer {TEST_KEY}"}


@pytest.fixture(scope="session", autouse=True)
def _init_db():
    """Initialize DuckDB once per session so tests can use duckdb_store directly."""
    from app.password import hash_password
    from app.storage import duckdb_store
    from app.decoder import engine as decoder_engine
    from app.rules import engine as rule_engine
    duckdb_store.init_db(os.environ["TINYSIEM_DUCKDB_PATH"])
    duckdb_store.init_alert_triage_table()
    duckdb_store.init_audit_table()
    duckdb_store.init_cases_tables()
    duckdb_store.init_baselines_tables()
    duckdb_store.init_integrations_tables()
    duckdb_store.init_dashboard_tables()
    duckdb_store.init_playbook_table()
    duckdb_store.init_watchlist_table()
    duckdb_store.init_saved_searches_table()
    duckdb_store.init_rule_exceptions_table()
    from app.watchlists import matcher as watchlist_matcher
    watchlist_matcher.reload_cache()
    decoder_engine.load_decoders()
    rule_engine.load_rules()
    duckdb_store.ensure_superadmin(hash_password(os.environ["TINYSIEM_SUPERADMIN_PASSWORD"]))


@pytest_asyncio.fixture(scope="session")
async def client():
    from app.main import app

    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest.fixture
def auth_headers():
    return AUTH_HEADERS


def _get_or_create_fixture_user(username: str, role: str) -> dict:
    from app.password import hash_password
    from app.storage import duckdb_store
    existing = duckdb_store.get_user_by_username(username)
    if existing:
        return existing
    return duckdb_store.create_user(username, hash_password("fixture-only-never-logged-in-with"), role)


@pytest.fixture
def superadmin_headers():
    from app.auth import create_token
    user = _get_or_create_fixture_user("fixture-superadmin", "superadmin")
    token = create_token(user["id"], user["username"], user["role"], epoch=user["token_epoch"])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    from app.auth import create_token
    user = _get_or_create_fixture_user("fixture-analyst", "analyst")
    token = create_token(user["id"], user["username"], user["role"], epoch=user["token_epoch"])
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers():
    from app.auth import create_token
    user = _get_or_create_fixture_user("fixture-admin", "admin")
    token = create_token(user["id"], user["username"], user["role"], epoch=user["token_epoch"])
    return {"Authorization": f"Bearer {token}"}
