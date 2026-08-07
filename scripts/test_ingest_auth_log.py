"""Unit tests for scripts/ingest_auth_log.py parse_line().

Run from repo root:  .venv/bin/python -m pytest scripts/test_ingest_auth_log.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from ingest_auth_log import parse_line

SAMPLES = [
    # (line, expected_action, expected_user, expected_ip)
    ("2026-08-02T00:00:01.838299+08:00 localhost sshd[3870763]: Failed password for invalid user www from 45.153.34.161 port 34914 ssh2",
     "Failed password", "www", "45.153.34.161"),
    ("2026-08-02T00:00:06.002878+08:00 localhost sshd[3870886]: Failed password for root from 45.153.34.161 port 55878 ssh2",
     "Failed password", "root", "45.153.34.161"),
    ("2026-08-02T00:00:06.732792+08:00 localhost sshd[3870901]: Invalid user developer from 45.153.34.161 port 55890",
     "Invalid user", "developer", "45.153.34.161"),
    ("2026-08-02T00:00:03.468105+08:00 localhost sshd[3870886]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.153.34.161  user=root",
     "pam_auth_failure", "root", "45.153.34.161"),
    ("2026-08-02T00:00:06.919493+08:00 localhost sshd[3870901]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=45.153.34.161 ",
     "pam_auth_failure", None, "45.153.34.161"),
    ("2026-08-02T00:00:11.977374+08:00 localhost sshd[3870759]: Disconnected from invalid user admin 185.116.161.214 port 42700 [preauth]",
     "Disconnected", "admin", "185.116.161.214"),
    ("2026-08-02T00:00:11.977221+08:00 localhost sshd[3870759]: Received disconnect from 185.116.161.214 port 42700:11: Bye Bye [preauth]",
     "Received disconnect", None, "185.116.161.214"),
    ("2026-08-02T00:00:02.624832+08:00 localhost sshd[3870763]: Connection closed by invalid user www 45.153.34.161 port 34914 [preauth]",
     "Connection closed", "www", "45.153.34.161"),
    ("2026-08-02T00:00:23.288609+08:00 localhost sshd[3870972]: Connection closed by 185.116.161.213 port 60958 [preauth]",
     "Connection closed", None, "185.116.161.213"),
    ("2026-08-02T00:00:06.919417+08:00 localhost sshd[3870901]: pam_unix(sshd:auth): check pass; user unknown",
     "other", None, None),
    ("2026-08-02T00:00:10.000000+08:00 localhost sshd[1]: Accepted password for ubuntu from 203.0.113.7 port 51234 ssh2",
     "Accepted password", "ubuntu", "203.0.113.7"),
    ("2026-08-02T00:00:10.000000+08:00 localhost sshd[1]: Accepted publickey for deploy from 198.51.100.9 port 51235 ssh2",
     "Accepted publickey", "deploy", "198.51.100.9"),
    ("2026-08-02T00:00:10.000000+08:00 localhost sshd[1]: error: maximum authentication attempts exceeded for root from 45.153.34.161 port 51236 ssh2",
     "max_auth_attempts", "root", "45.153.34.161"),
    # non-sshd line must be skipped
    ("2026-08-02T00:00:01.000000+08:00 localhost CRON[1234]: pam_unix(cron:session): session opened for user root(uid=0) by root(uid=0)",
     None, None, None),
]


def test_parse_line():
    for line, action, user, ip in SAMPLES:
        ev = parse_line(line)
        if action is None:
            assert ev is None, f"expected skip, got {ev}"
            continue
        assert ev is not None, f"expected parse, got None for: {line}"
        assert ev["action"] == action, f"{line}\n  action: {ev['action']} != {action}"
        assert ev.get("user") == user, f"{line}\n  user: {ev.get('user')} != {user}"
        assert ev.get("source_ip") == ip, f"{line}\n  ip: {ev.get('source_ip')} != {ip}"


def test_timestamp_utc_conversion():
    ev = parse_line(SAMPLES[0][0])
    assert ev["event_time"] == "2026-08-01T16:00:01.838299", ev["event_time"]
    assert ev["message"] == SAMPLES[0][0]


def test_json_serializable():
    for line, *_ in SAMPLES:
        ev = parse_line(line)
        if ev:
            json.dumps(ev)  # must not raise
