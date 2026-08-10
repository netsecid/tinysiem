import pathlib

# Resolve the repo root the same way main.py does: app/tests/../.. = repo root
# (this also holds in the container, where the repo root is /app and ui/ is
# bind-mounted at /app/ui).
_UI_DIR = pathlib.Path(__file__).resolve().parents[2] / "ui"


def test_no_cdn_chartjs_references_in_ui():
    for html_file in _UI_DIR.glob("*.html"):
        content = html_file.read_text()
        assert "cdnjs.cloudflare.com" not in content, f"{html_file.name} still references Chart.js CDN"


def test_chartjs_vendor_file_exists():
    f = _UI_DIR / "vendor" / "chart.umd.min.js"
    assert f.exists() and f.stat().st_size > 100_000, "vendored chart.umd.min.js missing or too small"
