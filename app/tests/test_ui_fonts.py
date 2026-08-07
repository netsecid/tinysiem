import pathlib

# Resolve the repo root the same way main.py does: app/tests/../.. = repo root
# (this also holds in the container, where the repo root is /app and ui/ is
# bind-mounted at /app/ui).
_UI_DIR = pathlib.Path(__file__).resolve().parents[2] / "ui"


def test_no_external_font_references_in_ui():
    for html_file in _UI_DIR.glob("*.html"):
        content = html_file.read_text()
        assert "fonts.googleapis.com" not in content, f"{html_file.name} still references Google Fonts"
        assert "fonts.gstatic.com" not in content, f"{html_file.name} still references Google Fonts CDN"


def test_font_files_exist():
    expected = [
        "IBMPlexSans-Regular.ttf", "IBMPlexSans-Medium.ttf", "IBMPlexSans-SemiBold.ttf",
        "IBMPlexMono-Regular.ttf", "IBMPlexMono-Medium.ttf",
    ]
    for name in expected:
        f = _UI_DIR / "fonts" / name
        assert f.exists() and f.stat().st_size > 1000, f"{name} missing or too small"
