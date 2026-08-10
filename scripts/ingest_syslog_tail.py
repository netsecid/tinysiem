"""Generic tailer for raw syslog-style files into TinySIEM.

Usage:
    # Real-time follow (tail -F; starts at EOF, so history is not re-ingested):
    python scripts/ingest_syslog_tail.py --source ufw --follow /var/log/ufw.log
    python scripts/ingest_syslog_tail.py --source fail2ban --follow /var/log/fail2ban.log

    # Bulk backfill of history (batched via /ingest/file):
    python scripts/ingest_syslog_tail.py --source ufw /var/log/ufw.log /var/log/ufw.log.1

Unlike scripts/ingest_auth_log.py (which pre-parses sshd's many message shapes
client-side), this tailer POSTs each raw line to /ingest/raw and lets the
decoder engine parse it server-side. Each --source needs a regex/kv decoder
registered (e.g. the `ufw` and `fail2ban` decoders in app/decoder/decoders/).

Follow mode:
  - tail -F semantics via inode detection (handles weekly logrotate: drains the
    renamed file, reopens the new one).
  - Starts at end-of-file so only NEW lines are ingested.
  - A 422 response means the line does not match the decoder — a permanent
    condition — so it is skipped and counted, NOT retried. All other errors
    (network, server restart) are retried with backoff.
"""
import argparse
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.request

from ingest_file import run as run_ingest_file, DEFAULT_ENDPOINT

FOLLOW_DEFAULT_ENDPOINT = "https://localhost:8000"


def _make_ssl_context() -> ssl.SSLContext:
    """Trust the local self-signed cert if present; otherwise unverified.

    The endpoint is our own TinySIEM (local network), and the self-signed cert
    can't be hostname-checked against 'localhost' — so verify the signature
    against our own cert file but skip hostname verification.
    """
    cert = pathlib.Path(__file__).parent.parent / "certs" / "tinysiem.crt"
    ctx = ssl.create_default_context()
    if cert.exists():
        ctx.load_verify_locations(str(cert))
    ctx.check_hostname = False
    return ctx


def _load_api_key(explicit_key):
    if explicit_key:
        return explicit_key
    env_file = pathlib.Path(__file__).parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            if line.startswith("TINYSIEM_API_KEY="):
                return line.split("=", 1)[1].strip()
    return os.environ.get("TINYSIEM_API_KEY", "")


def _post_raw(endpoint: str, api_key: str, source: str, line: str) -> None:
    """POST one raw line to /ingest/raw (source=NAME). Raises HTTPError(422)
    when the line does not match the decoder."""
    payload = json.dumps({"source": source, "raw": line}).encode("utf-8")
    req = urllib.request.Request(
        f"{endpoint}/ingest/raw",
        data=payload,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10, context=_make_ssl_context()) as resp:  # nosemgrep: dynamic-urllib-use-detected -- endpoint is operator-supplied CLI arg or hardcoded localhost, never attacker input  # nosec B310
        if resp.status != 200:
            raise RuntimeError(f"HTTP {resp.status}")


def follow(path: str, source: str, endpoint: str, api_key: str, poll_interval: float = 0.5) -> None:
    """tail -F style follower: stream new lines to TinySIEM in real time.
    Handles logrotate (weekly) by inode detection: drains the old (renamed)
    file, then reopens the new one. Starts at end-of-file so only NEW lines
    are ingested."""
    sent = 0
    errors = 0
    skipped = 0

    def post_line(line: str) -> None:
        nonlocal sent, errors, skipped
        if not line.strip():
            return
        for attempt in range(3):
            try:
                _post_raw(endpoint, api_key, source, line)
                sent += 1
                if sent % 100 == 0:
                    print(f"follow: {sent} events sent, {skipped} skipped, {errors} errors", flush=True)
                return
            except urllib.error.HTTPError as exc:
                if exc.code == 422:
                    # Line doesn't match the decoder — permanent, don't retry.
                    skipped += 1
                    return
                errors += 1
                if attempt == 2:
                    print(f"follow: giving up on line: {exc}", flush=True)
                    return
                time.sleep(1 + attempt)  # server restart window
            except Exception as exc:
                errors += 1
                if attempt == 2:
                    print(f"follow: giving up on line: {exc}", flush=True)
                    return
                time.sleep(1 + attempt)

    fh = open(path, "r", encoding="utf-8", errors="replace")
    fh.seek(0, os.SEEK_END)
    fd_inode = os.fstat(fh.fileno()).st_ino
    print(f"follow: tailing {path} (inode {fd_inode}) source={source} -> {endpoint}", flush=True)

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
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("files", nargs="+", help="log file(s), e.g. /var/log/ufw.log*")
    ap.add_argument("--source", required=True,
                    help="decoder source name (must match a registered decoder, e.g. ufw, fail2ban)")
    ap.add_argument("--endpoint", default=None,
                    help=f"TinySIEM base URL (default {FOLLOW_DEFAULT_ENDPOINT} for --follow, "
                         f"{DEFAULT_ENDPOINT} for bulk)")
    ap.add_argument("--api-key", default=None,
                    help="TinySIEM API key (default: TINYSIEM_API_KEY env / .env)")
    ap.add_argument("--follow", action="store_true",
                    help="Stream new lines from the FIRST file in real time "
                         "(tail -F; starts at EOF, so history is not re-ingested)")
    ap.add_argument("--batch-size", type=int, default=20000, help="Bulk batch size (default 20000)")
    args = ap.parse_args()

    api_key = _load_api_key(args.api_key)
    if not api_key:
        print("Error: no API key found (pass --api-key or set TINYSIEM_API_KEY in .env)")
        return 1

    if args.follow:
        follow(args.files[0], args.source, args.endpoint or FOLLOW_DEFAULT_ENDPOINT, api_key)
        return 0

    # Bulk backfill — delegate to ingest_file's batched /ingest/file uploader.
    # NOTE: only the first file is ingested by this code path today; multiple
    # files are each handled by re-invoking the same batching for each path.
    for path in args.files:
        ingest_args = argparse.Namespace(
            source=args.source,
            file=path,
            csv=False,
            endpoint=args.endpoint or FOLLOW_DEFAULT_ENDPOINT,
            api_key=api_key,
            batch_size=args.batch_size,
        )
        rc = run_ingest_file(ingest_args)
        if rc != 0:
            return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
