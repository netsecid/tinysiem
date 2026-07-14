"""CRUD for the ai_config table (single row: active provider/model/base_url/API key)."""
from datetime import datetime
from typing import Optional

from app.storage.duckdb_store import _get_conn, _lock
from app.crypto import decrypt, encrypt

_ROW_ID = "default"
_COLS = ["id", "provider", "model", "base_url", "api_key_encrypted", "updated_at", "updated_by"]


def _row_to_dict(row: tuple) -> dict:
    d = dict(zip(_COLS, row))
    if d["updated_at"] and hasattr(d["updated_at"], "isoformat"):
        d["updated_at"] = d["updated_at"].isoformat()
    return d


def _get_raw_row() -> Optional[dict]:
    with _lock:
        row = _get_conn().execute(
            f"SELECT {','.join(_COLS)} FROM ai_config WHERE id = ?", [_ROW_ID],
        ).fetchone()
    return _row_to_dict(row) if row else None


def get_ai_config() -> Optional[dict]:
    """Public view: never returns the API key itself, only whether one is stored."""
    row = _get_raw_row()
    if not row:
        return None
    return {
        "provider": row["provider"],
        "model": row["model"],
        "base_url": row["base_url"],
        "has_api_key": row["api_key_encrypted"] is not None,
        "updated_at": row["updated_at"],
        "updated_by": row["updated_by"],
    }


def get_decrypted_api_key() -> Optional[str]:
    """Internal use only (the provider factory) — decrypts the stored key, if any."""
    row = _get_raw_row()
    if not row or not row["api_key_encrypted"]:
        return None
    return decrypt(row["api_key_encrypted"])


def save_ai_config(
    provider: str,
    model: str,
    base_url: Optional[str],
    api_key: Optional[str],
    updated_by: str,
) -> dict:
    """Upsert via DELETE+INSERT (matches the `dashboards` table's documented pattern for
    avoiding DuckDB 1.1.3's UPDATE-with-secondary-index bug). A falsy api_key leaves the
    existing encrypted key unchanged ONLY when the provider is not changing — switching
    to a different provider without supplying a new key clears it instead, so a key never
    silently leaks from one provider's config into another's."""
    existing = _get_raw_row()
    if api_key:
        enc_key = encrypt(api_key)
    elif existing and existing["provider"] == provider:
        enc_key = existing["api_key_encrypted"]
    else:
        enc_key = None
    now = datetime.utcnow()
    with _lock:
        conn = _get_conn()
        conn.execute("DELETE FROM ai_config WHERE id = ?", [_ROW_ID])
        conn.execute(
            "INSERT INTO ai_config VALUES (?,?,?,?,?,?,?)",
            [_ROW_ID, provider, model, base_url, enc_key, now, updated_by],
        )
    return get_ai_config()
