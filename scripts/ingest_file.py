"""Generic CLI to bulk-ingest a log/CSV file into TinySIEM via /ingest/file.

Usage:
    python scripts/ingest_file.py --source my_custom_csv --file evidence.csv --csv
    python scripts/ingest_file.py --source aws_cloudtrail --file trail.jsonl

--source must match an existing decoder name; this script does no format guessing.
--csv tells the script line 1 of the file is a header row that must be repeated at
the top of every batch it uploads (each /ingest/file call is decoded independently
server-side). Irrelevant for non-CSV sources.
"""
import argparse
import json
import os
import pathlib
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_ENDPOINT = "http://localhost:8000"
DEFAULT_BATCH_SIZE = 20000
MAX_RETRIES = 3
RETRY_BACKOFF_SECONDS = 2


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


def read_batches(path, batch_size, has_header):
    """Yield (header_line_or_None, data_lines, line_numbers) tuples, reading
    `path` line-by-line so the whole file is never held in memory at once.
    `line_numbers[i]` is the 1-indexed absolute physical line number of
    `data_lines[i]` in the original file — tracked explicitly (not derived by
    arithmetic from a single batch-start line) because blank lines are skipped
    and can appear anywhere, including inside a batch, so physical line numbers
    are not derivable from a linear offset off one start line."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        header_line = None
        line_no = 0
        if has_header:
            first = f.readline()
            if not first:
                return
            header_line = first.rstrip("\n")
            line_no = 1

        data_lines = []
        line_numbers = []
        for raw_line in f:
            line_no += 1
            line = raw_line.rstrip("\n")
            if not line.strip():
                continue
            data_lines.append(line)
            line_numbers.append(line_no)
            if len(data_lines) >= batch_size:
                yield (header_line, data_lines, line_numbers)
                data_lines = []
                line_numbers = []
        if data_lines:
            yield (header_line, data_lines, line_numbers)


def _build_multipart_body(filename, content_bytes):
    boundary = "----TinySIEMIngestBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
    ).encode() + content_bytes + f"\r\n--{boundary}--\r\n".encode()
    return boundary, body


def upload_batch(endpoint, source, api_key, filename, content_bytes):
    boundary, body = _build_multipart_body(filename, content_bytes)
    url = f"{endpoint}/ingest/file?source={urllib.parse.quote(source)}"
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120, context=_make_ssl_context()) as resp:  # nosemgrep: dynamic-urllib-use-detected -- endpoint is operator-supplied CLI arg or hardcoded localhost, never attacker input  # nosec B310
        return json.loads(resp.read().decode())


def upload_batch_with_retries(endpoint, source, api_key, filename, content_bytes):
    last_exc = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return upload_batch(endpoint, source, api_key, filename, content_bytes)
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                raise
            last_exc = exc
        except Exception as exc:
            last_exc = exc
        if attempt < MAX_RETRIES:
            time.sleep(RETRY_BACKOFF_SECONDS * attempt)
    raise RuntimeError(f"batch upload failed after {MAX_RETRIES} retries: {last_exc}")


def run(args):
    api_key = _load_api_key(args.api_key)
    if not api_key:
        print("Error: no API key found (pass --api-key or set TINYSIEM_API_KEY in .env)")
        return 1

    rejects_path = pathlib.Path(getattr(args, "rejects_path", None) or str(args.file) + ".rejects.jsonl")
    total_processed = 0
    total_failed = 0
    total_lines = 0
    batch_failures = 0
    rejects_written = 0

    with open(rejects_path, "w", encoding="utf-8") as rejects_f:
        for header_line, data_lines, line_numbers in read_batches(
            args.file, args.batch_size, args.csv
        ):
            total_lines += len(data_lines)
            upload_lines = ([header_line] if header_line is not None else []) + data_lines
            content = ("\n".join(upload_lines) + "\n").encode("utf-8")

            try:
                result = upload_batch_with_retries(
                    args.endpoint, args.source, api_key,
                    pathlib.Path(args.file).name, content,
                )
            except urllib.error.HTTPError as exc:
                print(f"Auth error (HTTP {exc.code}), aborting: {exc.read().decode()}")
                return 1
            except RuntimeError as exc:
                print(f"Warning: {exc}")
                batch_failures += 1
                for line_no, line in zip(line_numbers, data_lines):
                    rejects_f.write(json.dumps({
                        "line": line_no, "source_line_content": line, "error": str(exc),
                    }) + "\n")
                    rejects_written += 1
                total_failed += len(data_lines)
                continue

            total_processed += result.get("processed", 0)
            total_failed += result.get("failed", 0)
            for err in result.get("errors", []):
                idx = err["line"] - (2 if args.csv else 1)
                abs_line = line_numbers[idx] if 0 <= idx < len(line_numbers) else None
                source_content = data_lines[idx] if 0 <= idx < len(data_lines) else None
                rejects_f.write(json.dumps({
                    "line": abs_line, "source_line_content": source_content, "error": err["error"],
                }) + "\n")
                rejects_written += 1

            print(f"Progress: processed={total_processed} failed={total_failed}", flush=True)

    print(
        f"Done. lines={total_lines} processed={total_processed} "
        f"failed={total_failed} batch_failures={batch_failures}"
    )
    if rejects_written:
        print(f"Rejected rows written to {rejects_path}")
    else:
        rejects_path.unlink(missing_ok=True)
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--file", required=True)
    parser.add_argument("--csv", action="store_true", help="Treat line 1 as a CSV header")
    parser.add_argument("--endpoint", default=DEFAULT_ENDPOINT)
    parser.add_argument("--batch-size", type=int, default=DEFAULT_BATCH_SIZE)
    parser.add_argument("--api-key", default=None)
    args = parser.parse_args()
    sys.exit(run(args))


if __name__ == "__main__":
    main()
