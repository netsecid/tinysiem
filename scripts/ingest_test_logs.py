"""Generate random nginx logs and POST them directly to TinySIEM."""
import io
import random
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

# ── CONFIG ──────────────────────────────────────────────────────────────
ENDPOINT = "http://localhost:8000"
API_KEY  = "NgatijoGantengMaksimalditahun2009!!!"
COUNT    = int(sys.argv[1]) if len(sys.argv) > 1 else 300

# ── LOG DATA ────────────────────────────────────────────────────────────
IPS = [
    "203.0.113.42", "198.51.100.7", "192.0.2.88", "10.0.0.45", "172.16.0.12",
    "185.220.101.5", "45.33.32.156", "104.21.14.100", "8.8.8.8", "1.1.1.1",
    "91.108.4.1", "66.249.66.1", "157.55.39.107", "40.77.167.10", "207.46.13.5",
]
METHODS = [("GET",60),("POST",20),("PUT",8),("DELETE",5),("PATCH",4),("HEAD",3)]
URIS = [
    "/", "/index.html", "/login", "/logout", "/api/v1/users", "/api/v1/events",
    "/api/v1/alerts", "/api/v1/health", "/dashboard", "/admin", "/admin/users",
    "/static/main.js", "/static/style.css", "/favicon.ico", "/robots.txt",
    "/api/v1/login", "/api/v1/logout", "/api/v1/search?q=test", "/metrics",
    "/.env", "/.git/config", "/wp-admin", "/phpMyAdmin", "/api/v1/data",
    "/api/v1/reports", "/upload", "/api/v1/export", "/sitemap.xml",
]
STATUSES = [
    (200,55),(201,5),(204,3),(301,4),(302,3),
    (400,5),(401,6),(403,4),(404,8),(429,2),
    (500,3),(502,1),(503,1),
]
UAS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'python-requests/2.31.0', 'curl/8.6.0', 'Go-http-client/1.1',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'Wget/1.21.3', 'axios/1.6.0', '-',
]
REFS = ["-","-","-","https://google.com/","https://example.com/"]


def wc(pairs):
    return random.choice([v for v, w in pairs for _ in range(w)])


def gen_lines(n):
    end   = datetime.now(timezone.utc)
    start = end - timedelta(hours=2)
    items = []
    for _ in range(n):
        dt     = start + timedelta(seconds=random.uniform(0, 7200))
        ip     = random.choice(IPS)
        method = wc(METHODS)
        uri    = random.choice(URIS)
        status = wc(STATUSES)
        size   = 0 if status in (204,301,302) else random.randint(
                     100 if status >= 400 else 200,
                     800 if status >= 500 else 51200)
        ref    = random.choice(REFS)
        ua     = random.choice(UAS)
        ts     = dt.strftime("%d/%b/%Y:%H:%M:%S +0000")
        items.append((dt, f'{ip} - - [{ts}] "{method} {uri} HTTP/1.1" {status} {size} "{ref}" "{ua}"'))
    items.sort(key=lambda x: x[0])
    return [line for _, line in items]


def upload(lines):
    content = "\n".join(lines).encode("utf-8")

    boundary = "----TinySIEMBoundary7MA4YWxkTrZu0gW"
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="test.log"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
    ).encode() + content + f"\r\n--{boundary}--\r\n".encode()

    url = f"{ENDPOINT}/ingest/file?source=nginx"
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Authorization": f"Bearer {API_KEY}",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode()


if __name__ == "__main__":
    print(f"Generating {COUNT} log lines...", flush=True)
    lines = gen_lines(COUNT)
    print(f"Uploading to {ENDPOINT}...", flush=True)
    try:
        result = upload(lines)
        print(f"Done: {result}")
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode()}")
    except Exception as e:
        print(f"Error: {e}")
