import pytest


def test_add_and_list_entry():
    from app.watchlists import store as watchlist_store
    entry = watchlist_store.add_entry(
        "test-list-1", "ip", "203.0.113.5", "high", "known scanner", "tester",
    )
    assert entry["list_name"] == "test-list-1"
    assert entry["indicator_type"] == "ip"
    assert entry["value"] == "203.0.113.5"
    assert entry["active"] is True
    entries = watchlist_store.list_entries("test-list-1")
    assert any(e["id"] == entry["id"] for e in entries)


def test_add_entry_rejects_invalid_indicator_type():
    from app.watchlists import store as watchlist_store
    with pytest.raises(ValueError):
        watchlist_store.add_entry("test-list-2", "not-a-type", "x", "low", None, "tester")


def test_add_entry_rejects_invalid_severity():
    from app.watchlists import store as watchlist_store
    with pytest.raises(ValueError):
        watchlist_store.add_entry("test-list-3", "ip", "1.2.3.4", "not-a-severity", None, "tester")


def test_set_active_toggle_and_get_active_entries():
    from app.watchlists import store as watchlist_store
    entry = watchlist_store.add_entry("test-list-4", "ip", "203.0.113.9", "low", None, "tester")
    assert any(e["id"] == entry["id"] for e in watchlist_store.get_active_entries())
    ok = watchlist_store.set_active(entry["id"], False)
    assert ok is True
    assert not any(e["id"] == entry["id"] for e in watchlist_store.get_active_entries())


def test_delete_entry():
    from app.watchlists import store as watchlist_store
    entry = watchlist_store.add_entry("test-list-5", "cidr", "203.0.113.0/24", "medium", None, "tester")
    assert watchlist_store.delete_entry(entry["id"]) is True
    assert not any(e["id"] == entry["id"] for e in watchlist_store.list_entries("test-list-5"))
    assert watchlist_store.delete_entry(entry["id"]) is False


def test_entry_cap_enforced(monkeypatch):
    from app.watchlists import store as watchlist_store
    monkeypatch.setattr(watchlist_store, "_MAX_ENTRIES", watchlist_store.count_entries() + 1)
    watchlist_store.add_entry("test-list-cap", "ip", "198.51.100.200", "low", None, "tester")
    with pytest.raises(ValueError, match="cap"):
        watchlist_store.add_entry("test-list-cap", "ip", "198.51.100.201", "low", None, "tester")
