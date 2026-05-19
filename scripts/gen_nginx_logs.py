"""Generate realistic nginx access logs for TinySIEM testing."""
import random
import sys
from datetime import datetime, timedelta, timezone

IPS = [
    "203.0.113.42", "198.51.100.7", "192.0.2.88", "10.0.0.45", "172.16.0.12",
    "185.220.101.5", "45.33.32.156", "104.21.14.100", "8.8.8.8", "1.1.1.1",
    "91.108.4.1", "66.249.66.1", "157.55.39.107", "40.77.167.10", "207.46.13.5",
]

METHODS_WEIGHTS = [
    ("GET", 60), ("POST", 20), ("PUT", 8), ("DELETE", 5), ("PATCH", 4), ("HEAD", 3),
]

URIS = [
    "/", "/index.html", "/login", "/logout", "/api/v1/users", "/api/v1/events",
    "/api/v1/alerts", "/api/v1/health", "/dashboard", "/admin", "/admin/users",
    "/static/main.js", "/static/style.css", "/favicon.ico", "/robots.txt",
    "/api/v1/login", "/api/v1/logout", "/api/v1/search?q=test", "/metrics",
    "/.env", "/.git/config", "/wp-admin", "/phpMyAdmin", "/api/v1/data",
    "/api/v1/reports", "/upload", "/api/v1/export", "/sitemap.xml",
]

STATUS_WEIGHTS = [
    (200, 55), (201, 5), (204, 3), (301, 4), (302, 3),
    (400, 5), (401, 6), (403, 4), (404, 8), (429, 2),
    (500, 3), (502, 1), (503, 1),
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0',
    'python-requests/2.31.0',
    'curl/8.6.0',
    'Go-http-client/1.1',
    'Googlebot/2.1 (+http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'Wget/1.21.3',
    'axios/1.6.0',
    '-',
]

REFERERS = ["-", "-", "-", "https://google.com/", "https://example.com/", "https://tinysiem.local/"]


def weighted_choice(pairs):
    population = [val for val, weight in pairs for _ in range(weight)]
    return random.choice(population)


def response_size(status):
    if status in (204, 301, 302):
        return 0
    if status >= 500:
        return random.randint(100, 800)
    if status >= 400:
        return random.randint(150, 1200)
    return random.randint(200, 51200)


def fmt_time(dt):
    # nginx time_local format: 19/May/2026:15:32:01 +0000
    return dt.strftime("%d/%b/%Y:%H:%M:%S +0000")


def gen_log_line(dt):
    ip     = random.choice(IPS)
    method = weighted_choice(METHODS_WEIGHTS)
    uri    = random.choice(URIS)
    status = weighted_choice(STATUS_WEIGHTS)
    size   = response_size(status)
    ref    = random.choice(REFERERS)
    ua     = random.choice(USER_AGENTS)
    ts     = fmt_time(dt)
    return f'{ip} - - [{ts}] "{method} {uri} HTTP/1.1" {status} {size} "{ref}" "{ua}"'


def main():
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 200
    # Spread logs over the last 2 hours
    end   = datetime.now(timezone.utc)
    start = end - timedelta(hours=2)

    lines = []
    for _ in range(count):
        offset = random.uniform(0, (end - start).total_seconds())
        dt = start + timedelta(seconds=offset)
        lines.append((dt, gen_log_line(dt)))

    # Sort chronologically
    lines.sort(key=lambda x: x[0])

    output = "\n".join(line for _, line in lines)
    print(output)


if __name__ == "__main__":
    main()
