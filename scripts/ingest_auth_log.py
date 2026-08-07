"""Parse SSH auth logs into normalized JSON events and bulk-ingest into TinySIEM.

Usage:
    sudo python scripts/ingest_auth_log.py /var/log/auth.log
    sudo python scripts/ingest_auth_log.py /var/log/auth.log /var/log/auth.log.1
    sudo python scripts/ingest_auth_log.py /var/log/auth.log*        # shell-expanded

Why this script exists
----------------------
TinySIEM decoders support one regex per source, but sshd emits many message
shapes ("Failed password for ...", "Invalid user ...", "pam_unix ... rhost= ...",
"Connection closed by ..."). This script pre-parses each line with a small set
of Python regexes, normalizes the result to a JSON event, and reuses the
batched uploader in scripts/ingest_file.py (20k lines/request, retries,
rejects file).

Normalized event fields (consumed by the `sshd` json decoder):
  event_time  naive-UTC ISO timestamp (converted from the log's local offset)
  action      canonical action ("Failed password", "Accepted password",
              "Invalid user", "pam_auth_failure", "max_auth_attempts", ...)
  user        username (may be absent)
  source_ip   peer IPv4 (may be absent)
  message     the original log line (lands in extra.message)

'action' maps to the events.method column because method is one of the few
allowlist-queryable free-text fields in the threshold engine — this lets rules
count e.g. method = "Failed password" over a time window.

Note: only sshd lines are ingested (non-sshd auth.log lines are skipped).
"""
import argparse
import datetime as dt
import json
import pathlib
import re
import sys

from ingest_file import run as run_ingest_file, DEFAULT_ENDPOINT

_TS_RE = re.compile(r"^(?P<ts>\S+) \S+ sshd\[\d+\]: (?P<msg>.*)$")
_IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"

_PATTERNS = [
    (re.compile(rf"^Failed password for (?:invalid |authenticating )?user (?P<user>\S+) from {_IP}"), "Failed password"),
    (re.compile(rf"^Failed password for (?P<user>\S+) from {_IP}"), "Failed password"),
    (re.compile(rf"^Invalid user (?P<user>\S+) from {_IP}"), "Invalid user"),
    (re.compile(rf"^Accepted (?P<auth>password|publickey) for (?P<user>\S+) from {_IP}"),
     lambda g: f"Accepted {g['auth']}"),
    (re.compile(rf"^error: maximum authentication attempts exceeded for (?P<user>\S+) from {_IP}"), "max_auth_attempts"),
    (re.compile(rf"^.*?authentication failure;.*?rhost={_IP}(?: *user=(?P<user>\S+))?"), "pam_auth_failure"),
    (re.compile(rf"^Connection (?P<how>closed|reset) by (?:invalid user |authenticating user |user )?(?P<user>\S+ )?{_IP} port \d+"),
     lambda g: f"Connection {g['how']}"),
    (re.compile(rf"^Received disconnect from {_IP}"), "Received disconnect"),
    (re.compile(rf"^Did not receive identification string from {_IP}"), "Did not receive identification string"),
    (re.compile(rf"^Disconnected from (?:invalid user |user )?(?P<user>\S+ )?{_IP}"), "Disconnected"),
    (re.compile(rf"^Connection closed by {_IP} port \d+"), "Connection closed"),
]


def parse_line(line: str):
    """Return a normalized event dict for one auth.log line, or None if the
    line is not an sshd message."""
    m = _TS_RE.match(line)
    if not m:
        return None
    ts_str, msg = m.group("ts"), m.group("msg")

    event_time = None
    try:
        ts = dt.datetime.fromisoformat(ts_str).astimezone(dt.timezone.utc)
        event_time = ts.strftime("%Y-%m-%dT%H:%M:%S.%f")
    except ValueError:
        pass

    ev = {"event_time": event_time, "message": line.strip()}
    for rx, action in _PATTERNS:
        m2 = rx.match(msg)
        if not m2:
            continue
        g = m2.groupdict()
        if g.get("ip"):
            ev["source_ip"] = g["ip"]
        if g.get("user"):
            ev["user"] = g["user"].strip()
        ev["action"] = action(g) if callable(action) else action
        return ev

    ev["action"] = "other"
    return ev


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="auth.log file(s), e.g. /var/log/auth.log*")
    ap.add_argument("--endpoint", default=None,
                    help=f"TinySIEM base URL (default {DEFAULT_ENDPOINT})")
    ap.add_argument("--api-key", default=None, help="TinySIEM API key (default: TINYSIEM_API_KEY env / .env)")
    ap.add_argument("--dry-run", action="store_true", help="Parse and print stats only, no upload")
    ap.add_argument("--out", default="/tmp/sshd_normalized.jsonl", help="Temp JSONL path (default %(default)s)")
    args = ap.parse_args()

    stats = {"lines": 0, "sshd": 0, "ip": 0, "user": 0, "other": 0, "non_sshd": 0}
    out_path = pathlib.Path(args.out)
    with out_path.open("w", encoding="utf-8") as out_f:
        for file in args.files:
            with open(file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    stats["lines"] += 1
                    ev = parse_line(line.rstrip("\n"))
                    if ev is None:
                        stats["non_sshd"] += 1
                        continue
                    stats["sshd"] += 1
                    if ev.get("source_ip"):
                        stats["ip"] += 1
                    if ev.get("user"):
                        stats["user"] += 1
                    if ev["action"] == "other":
                        stats["other"] += 1
                    out_f.write(json.dumps(ev) + "\n")

    print(f"Parsed: total={stats['lines']} sshd={stats['sshd']} "
          f"with_ip={stats['ip']} with_user={stats['user']} other={stats['other']} "
          f"non_sshd_skipped={stats['non_sshd']}")

    if args.dry_run:
        return 0
    if stats["sshd"] == 0:
        print("No sshd lines found — nothing to ingest.")
        return 1

    ingest_args = argparse.Namespace(
        source="sshd",
        file=str(out_path),
        csv=False,
        endpoint=args.endpoint or DEFAULT_ENDPOINT,
        api_key=args.api_key,
        batch_size=20000,
    )
    return run_ingest_file(ingest_args)


if __name__ == "__main__":
    sys.exit(main())
