import ipaddress
import logging
import threading
from typing import Optional

from app.alerts import file_writer

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_exact_ips: dict[str, dict] = {}
_cidrs: list[tuple[object, dict]] = []
_user_agent_substrings: list[tuple[str, dict]] = []
_uri_substrings: list[tuple[str, dict]] = []


def reload_cache() -> None:
    global _exact_ips, _cidrs, _user_agent_substrings, _uri_substrings
    from app.watchlists import store as watchlist_store
    entries = watchlist_store.get_active_entries()
    exact_ips: dict[str, dict] = {}
    cidrs: list[tuple[object, dict]] = []
    ua_subs: list[tuple[str, dict]] = []
    uri_subs: list[tuple[str, dict]] = []
    for entry in entries:
        itype = entry["indicator_type"]
        if itype == "ip":
            exact_ips[entry["value"]] = entry
        elif itype == "cidr":
            try:
                cidrs.append((ipaddress.ip_network(entry["value"], strict=False), entry))
            except ValueError:
                logger.warning(f"Skipping invalid CIDR in watchlist: {entry['value']!r}")
        elif itype == "user_agent_substring":
            ua_subs.append((entry["value"], entry))
        elif itype == "uri_substring":
            uri_subs.append((entry["value"], entry))
    with _lock:
        _exact_ips = exact_ips
        _cidrs = cidrs
        _user_agent_substrings = ua_subs
        _uri_substrings = uri_subs


def _match(event: dict) -> Optional[dict]:
    source_ip = event.get("source_ip")
    with _lock:
        if source_ip and source_ip in _exact_ips:
            return _exact_ips[source_ip]
        if source_ip:
            try:
                ip_obj = ipaddress.ip_address(source_ip)
                for network, entry in _cidrs:
                    if ip_obj in network:
                        return entry
            except ValueError:
                pass
        user_agent = event.get("user_agent") or ""
        for substring, entry in _user_agent_substrings:
            if substring in user_agent:
                return entry
        uri = event.get("uri") or ""
        for substring, entry in _uri_substrings:
            if substring in uri:
                return entry
    return None


def check_event(event: dict) -> None:
    """Called from the ingest pipeline for every stored event. Fires an alert on a hit."""
    entry = _match(event)
    if entry is None:
        return
    fake_rule = {
        "name": f"watchlist:{entry['list_name']}",
        "severity": entry["severity"],
        "mitre_tactic": None,
        "mitre_technique": None,
    }
    note_part = f" — {entry['note']}" if entry.get("note") else ""
    summary = f"Watchlist hit: {entry['list_name']} ({entry['indicator_type']}={entry['value']}){note_part}"
    file_writer.write_alert(fake_rule, event, summary_override=summary)
    logger.info(f"Watchlist hit: list={entry['list_name']!r} indicator_type={entry['indicator_type']!r}")
