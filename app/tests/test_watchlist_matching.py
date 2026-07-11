import json
import uuid
from datetime import datetime
from pathlib import Path

from app.storage import duckdb_store
from app.watchlists import matcher as watchlist_matcher
from app.watchlists import store as watchlist_store


def _make_event(source_ip=None, user_agent=None, uri=None) -> dict:
    return {
        "id": str(uuid.uuid4()),
        "source": "nginx",
        "ingested_at": datetime.utcnow(),
        "event_time": None,
        "source_ip": source_ip,
        "method": "GET",
        "uri": uri or "/",
        "status_code": 200,
        "response_size": 100,
        "user_agent": user_agent,
        "referer": None,
        "raw": "test",
        "extra": {},
    }


def _last_alert_lines(n=1):
    from app.config import settings
    path = Path(settings.tinysiem_alerts_path)
    lines = [ln for ln in path.read_text().splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines[-n:]]


def test_exact_ip_match_fires_alert():
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 1}"
    watchlist_store.add_entry("match-test-ip", "ip", ip, "critical", "known bad actor", "tester")
    watchlist_matcher.reload_cache()
    ev = _make_event(source_ip=ip)
    duckdb_store.insert_event(ev)
    watchlist_matcher.check_event(ev)
    alert = _last_alert_lines(1)[0]
    assert alert["rule_name"] == "watchlist:match-test-ip"
    assert alert["severity"] == "critical"
    assert "known bad actor" in alert["summary"]
    assert alert["source_ip"] == ip


def test_cidr_match_fires_alert():
    watchlist_store.add_entry("match-test-cidr", "cidr", "203.0.113.0/24", "high", None, "tester")
    watchlist_matcher.reload_cache()
    ev = _make_event(source_ip="203.0.113.77")
    duckdb_store.insert_event(ev)
    watchlist_matcher.check_event(ev)
    alert = _last_alert_lines(1)[0]
    assert alert["rule_name"] == "watchlist:match-test-cidr"


def test_uri_substring_match_fires_alert():
    watchlist_store.add_entry("match-test-uri", "uri_substring", "/phpmyadmin", "medium", None, "tester")
    watchlist_matcher.reload_cache()
    ev = _make_event(source_ip="10.0.0.1", uri="/phpmyadmin/index.php")
    duckdb_store.insert_event(ev)
    watchlist_matcher.check_event(ev)
    alert = _last_alert_lines(1)[0]
    assert alert["rule_name"] == "watchlist:match-test-uri"


def test_inactive_entry_does_not_match():
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 1}"
    entry = watchlist_store.add_entry("match-test-inactive", "ip", ip, "low", None, "tester")
    watchlist_store.set_active(entry["id"], False)
    watchlist_matcher.reload_cache()
    ev = _make_event(source_ip=ip)
    duckdb_store.insert_event(ev)
    before = _last_alert_lines(1)
    watchlist_matcher.check_event(ev)
    after = _last_alert_lines(1)
    assert before == after  # no new alert appended


def test_non_matching_event_does_not_fire():
    watchlist_store.add_entry("match-test-nomiss", "ip", "192.0.2.55", "low", None, "tester")
    watchlist_matcher.reload_cache()
    ev = _make_event(source_ip="192.0.2.99")
    duckdb_store.insert_event(ev)
    before = _last_alert_lines(1)
    watchlist_matcher.check_event(ev)
    after = _last_alert_lines(1)
    assert before == after
