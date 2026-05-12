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
