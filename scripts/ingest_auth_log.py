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
import os
import pathlib
import re
import ssl
import sys
import time
import urllib.error
import urllib.request

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


def _make_ssl_context() -> ssl.SSLContext:
    """Trust the local self-signed cert if present; otherwise unverified.

    Endpoint is our own TinySIEM (local network), and the self-signed cert
    can't be hostname-checked against 'localhost' — so verify the signature
    against our own cert file but skip hostname verification.
    """
    cert = pathlib.Path(__file__).parent.parent / "certs" / "tinysiem.crt"
    ctx = ssl.create_default_context()
    if cert.exists():
        ctx.load_verify_locations(str(cert))
    ctx.check_hostname = False
    return ctx


def _post_event(endpoint: str, api_key: str, ev: dict) -> None:
    """POST one normalized event to /ingest/raw (source=sshd)."""
    payload = json.dumps({"source": "sshd", "raw": json.dumps(ev)}).encode("utf-8")
    req = urllib.request.Request(
        f"{endpoint}/ingest/raw",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10, context=_make_ssl_context()) as resp:
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")


def follow(path: str, endpoint: str, api_key: str, poll_interval: float = 0.5) -> None:
    """tail -F style follower: stream new auth.log lines to TinySIEM in
    real time. Handles logrotate (weekly) by inode detection: drains the old
    (renamed) file, then reopens the new one. Starts at end-of-file so only
    NEW lines are ingested."""
    sent = 0
    errors = 0

    def post_line(line: str) -> None:
        nonlocal sent, errors
        if not line.strip():
            return
        ev = parse_line(line)
        if ev is None:
            return  # non-sshd line
        for attempt in range(3):
            try:
                _post_event(endpoint, api_key, ev)
                sent += 1
                if sent % 100 == 0:
                    print(f"follow: {sent} events sent, {errors} errors", flush=True)
                return
            except Exception as exc:
                errors += 1
                if attempt == 2:
                    print(f"follow: giving up on line: {exc}", flush=True)
                    return
                time.sleep(1 + attempt)  # server restart window

    fh = open(path, "r", encoding="utf-8", errors="replace")
    fh.seek(0, os.SEEK_END)
    fd_inode = os.fstat(fh.fileno()).st_ino
    print(f"follow: tailing {path} (inode {fd_inode}) -> {endpoint}", flush=True)

    while True:
        line = fh.readline()
        if line:
            post_line(line.rstrip("\n"))
            continue
        # EOF — check rotation
        try:
            st = os.stat(path)
        except FileNotFoundError:
            time.sleep(poll_interval)
            continue
        if st.st_ino != fd_inode:
            for old_line in fh:
                post_line(old_line.rstrip("\n"))
            fh.close()
            fh = open(path, "r", encoding="utf-8", errors="replace")
            fd_inode = os.fstat(fh.fileno()).st_ino
            print(f"follow: rotated to new inode {fd_inode}", flush=True)
        time.sleep(poll_interval)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="+", help="auth.log file(s), e.g. /var/log/auth.log*")
    ap.add_argument("--endpoint", default=None,
                    help=f"TinySIEM base URL (default {DEFAULT_ENDPOINT})")
    ap.add_argument("--api-key", default=None, help="TinySIEM API key (default: TINYSIEM_API_KEY env / .env)")
    ap.add_argument("--dry-run", action="store_true", help="Parse and print stats only, no upload")
    ap.add_argument("--out", default="/tmp/sshd_normalized.jsonl", help="Temp JSONL path (default %(default)s)")
    ap.add_argument("--follow", action="store_true",
                    help="Stream new lines from the FIRST file in real time "
                         "(tail -F; starts at EOF, so history is not re-ingested)")
    args = ap.parse_args()

    if args.follow:
        api_key = args.api_key or os.environ.get("TINYSIEM_API_KEY", "")
        if not api_key:
            env_file = pathlib.Path(__file__).parent.parent / ".env"
            if env_file.exists():
                for line in env_file.read_text().splitlines():
                    if line.startswith("TINYSIEM_API_KEY="):
                        api_key = line.split("=", 1)[1].strip()
        if not api_key:
            print("Error: no API key found (pass --api-key or set TINYSIEM_API_KEY in .env)")
            return 1
        follow(args.files[0], args.endpoint or "https://localhost:8000", api_key)
        return 0

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
