"""Tests for scheduled reports."""
import json
import uuid
from datetime import datetime, timezone
from unittest.mock import patch

import pytest


@pytest.fixture
def empty_alerts_file(tmp_path):
    log_path = tmp_path / "alerts.log"
    log_path.write_text("")
    with patch("app.config.settings.tinysiem_alerts_path", str(log_path)):
        yield log_path


async def test_generate_report_returns_structure(client, analyst_headers, empty_alerts_file):
    resp = await client.get("/reports/generate", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "period" in data
    assert "summary" in data
    assert "top_source_ips" in data
    assert "top_rules" in data
    assert "generated_at" in data


async def test_generate_report_daily(client, analyst_headers, empty_alerts_file):
    resp = await client.get("/reports/generate?period=daily", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["period"] == "daily"


async def test_generate_report_weekly(client, analyst_headers, empty_alerts_file):
    resp = await client.get("/reports/generate?period=weekly", headers=analyst_headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["period"] == "weekly"


async def test_generate_report_requires_auth(client, empty_alerts_file):
    resp = await client.get("/reports/generate")
    assert resp.status_code == 401


async def test_download_report(client, analyst_headers, empty_alerts_file):
    resp = await client.get("/reports/download?period=daily", headers=analyst_headers)
    assert resp.status_code == 200
    assert "text/html" in resp.headers.get("content-type", "")
    assert "attachment" in resp.headers.get("content-disposition", "")
    assert "<!DOCTYPE html>" in resp.text


async def test_send_report_requires_admin(client, analyst_headers, empty_alerts_file):
    resp = await client.post("/reports/send", headers=analyst_headers)
    assert resp.status_code == 403
