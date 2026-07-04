"""
conftest.py — must set env vars and mock chromadb BEFORE any app module is imported.
pytest loads this file first, so module-level side-effects execute before test collection.
"""
import os
import sys
import tempfile
from unittest.mock import MagicMock

# ── 1. Set env vars before pydantic-settings reads them ──────────────────────
_tmp = tempfile.mkdtemp()
os.environ["TINYSIEM_API_KEY"] = "test-api-key"
os.environ["TINYSIEM_DUCKDB_PATH"] = _tmp + "/test.duckdb"
os.environ["TINYSIEM_CHROMA_PATH"] = _tmp + "/chroma"
os.environ["TINYSIEM_ALERTS_PATH"] = _tmp + "/alerts/alerts.log"
os.environ["TINYSIEM_DEBUG"] = "false"
os.environ["TINYSIEM_JWT_SECRET"] = "test-jwt-secret-for-tests"
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

# ── 2. Stub chromadb before any import resolves it ───────────────────────────
_mock_collection = MagicMock()
_mock_collection.upsert = MagicMock()
_mock_collection.query = MagicMock(
    return_value={"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}
)
_mock_client = MagicMock()
_mock_client.get_or_create_collection.return_value = _mock_collection
_mock_chroma_module = MagicMock()
_mock_chroma_module.PersistentClient.return_value = _mock_client
sys.modules["chromadb"] = _mock_chroma_module

# ── 3. Fixtures ───────────────────────────────────────────────────────────────
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
    duckdb_store.init_db(os.environ["TINYSIEM_DUCKDB_PATH"])
    duckdb_store.init_alert_triage_table()
    duckdb_store.init_audit_table()
    duckdb_store.init_cases_tables()
    duckdb_store.init_baselines_tables()
    duckdb_store.init_integrations_tables()
    duckdb_store.init_dashboard_tables()
    duckdb_store.init_playbook_table()
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


@pytest.fixture
def superadmin_headers():
    from app.auth import create_token
    token = create_token("test-superadmin", "admin", "superadmin")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def analyst_headers():
    from app.auth import create_token
    token = create_token("test-analyst", "analyst", "analyst")
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def admin_headers():
    from app.auth import create_token
    token = create_token("test-admin", "admin", "admin")
    return {"Authorization": f"Bearer {token}"}
