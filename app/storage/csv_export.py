"""Shared CSV export helper.

Used by app/events/router.py and app/alerts/router.py to render
query results as CSV for the "export" (format=csv) code path.

Sanitizes cell values against CSV/Excel formula injection: spreadsheet
applications (Excel, Google Sheets, LibreOffice) may interpret a cell
as a formula rather than literal text if its value starts with one of
`= + - @ \t \r`. Any exported column can carry attacker-influenced
content (e.g. ingested log lines), so every string cell is sanitized
here rather than relying on individual call sites to remember to do it.
"""
import csv
import io

_FORMULA_TRIGGER_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _sanitize_cell(value):
    """Prefix formula-trigger-looking strings with a leading single quote.

    Only string values are sanitized; other types (int, None, bool, etc.)
    are returned untouched. A leading `'` forces spreadsheet applications
    to render the cell as literal text while csv.DictWriter still quotes
    the resulting value correctly if it contains commas/quotes/newlines.
    """
    if isinstance(value, str) and value.startswith(_FORMULA_TRIGGER_PREFIXES):
        return "'" + value
    return value


def rows_to_csv(rows: list[dict], fieldnames: list[str]) -> str:
    """Render a list of dict rows to a CSV string, sanitized against
    formula injection.

    Extra keys in each row not present in `fieldnames` are ignored
    (matching the prior per-router helpers' `extrasaction="ignore"`
    behavior).
    """
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        sanitized = {key: _sanitize_cell(value) for key, value in row.items()}
        writer.writerow(sanitized)
    return buf.getvalue()
