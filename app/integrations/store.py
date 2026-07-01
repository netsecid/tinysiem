"""CRUD for integrations and integration_runs tables."""
import json
import uuid
from datetime import datetime
from typing import Optional

from app.storage.duckdb_store import _get_conn, _lock  # noqa: PLC2701
from app.crypto import decrypt, encrypt


def _encrypt_credentials(creds: dict) -> str:
    return json.dumps({k: encrypt(v) for k, v in creds.items()})


def _decrypt_credentials(json_str: str) -> dict:
    raw = json.loads(json_str) if isinstance(json_str, str) else json_str
    return {k: decrypt(v) for k, v in raw.items()}


def _mask_credentials(creds: dict) -> dict:
    """Return last-4 chars of each plaintext credential value."""
    return {k: "**..." + v[-4:] if len(v) > 4 else "****" for k, v in creds.items()}


def _row_to_dict(row: tuple, cols: list[str]) -> dict:
    d = dict(zip(cols, row))
    for f in ("created_at", "updated_at", "last_run_at", "started_at", "finished_at"):
        if f in d and d[f] and hasattr(d[f], "isoformat"):
            d[f] = d[f].isoformat()
    return d


_INTEGRATION_COLS = [
    "integration_id", "name", "integration_type", "enabled",
    "config", "credentials", "schedule_minutes", "created_by",
    "created_at", "updated_at", "last_run_at", "last_run_status",
]

_RUN_COLS = [
    "run_id", "integration_id", "started_at", "finished_at",
    "status", "events_pulled", "events_ingested", "error_message", "next_cursor",
]


def create_integration(
    name: str,
    integration_type: str,
    config: dict,
    credentials: dict,
    schedule_minutes: int,
    created_by: str,
) -> dict:
    iid = str(uuid.uuid4())
    now = datetime.utcnow()
    enc_creds = _encrypt_credentials(credentials)
    config_json = json.dumps(config)
    with _lock:
        _get_conn().execute(
            "INSERT INTO integrations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            [iid, name, integration_type, True, config_json, enc_creds,
             schedule_minutes, created_by, now, now, None, None],
        )
    return get_integration(iid, masked=True)


def get_integration(integration_id: str, masked: bool = True) -> Optional[dict]:
    with _lock:
        row = _get_conn().execute(
            f"SELECT {','.join(_INTEGRATION_COLS)} FROM integrations WHERE integration_id = ?",
            [integration_id],
        ).fetchone()
    if not row:
        return None
    d = _row_to_dict(row, _INTEGRATION_COLS)
    d["config"] = json.loads(d["config"]) if isinstance(d["config"], str) else d["config"]
    raw_creds = json.loads(d["credentials"]) if isinstance(d["credentials"], str) else d["credentials"]
    if masked:
        decrypted = _decrypt_credentials(json.dumps(raw_creds))
        d["credentials"] = _mask_credentials(decrypted)
    else:
        d["credentials"] = _decrypt_credentials(json.dumps(raw_creds))
    return d


def list_integrations() -> list[dict]:
    with _lock:
        rows = _get_conn().execute(
            "SELECT integration_id, name, integration_type, enabled, schedule_minutes, "
            "created_by, created_at, last_run_at, last_run_status FROM integrations ORDER BY created_at",
        ).fetchall()
    cols = ["integration_id", "name", "integration_type", "enabled", "schedule_minutes",
            "created_by", "created_at", "last_run_at", "last_run_status"]
    result = []
    for row in rows:
        d = _row_to_dict(row, cols)
        # attach latest run stats
        with _lock:
            run_row = _get_conn().execute(
                "SELECT events_pulled, events_ingested FROM integration_runs "
                "WHERE integration_id = ? ORDER BY started_at DESC LIMIT 1",
                [d["integration_id"]],
            ).fetchone()
        d["events_pulled_last_run"] = run_row[0] if run_row else 0
        result.append(d)
    return result


def update_integration(
    integration_id: str,
    name: Optional[str] = None,
    enabled: Optional[bool] = None,
    config: Optional[dict] = None,
    credentials: Optional[dict] = None,
    schedule_minutes: Optional[int] = None,
) -> Optional[dict]:
    sets, params = [], []
    if name is not None:
        sets.append("name = ?"); params.append(name)
    if enabled is not None:
        sets.append("enabled = ?"); params.append(enabled)
    if config is not None:
        sets.append("config = ?"); params.append(json.dumps(config))
    if credentials is not None:
        sets.append("credentials = ?"); params.append(_encrypt_credentials(credentials))
    if schedule_minutes is not None:
        sets.append("schedule_minutes = ?"); params.append(schedule_minutes)
    if not sets:
        return get_integration(integration_id)
    sets.append("updated_at = ?"); params.append(datetime.utcnow())
    params.append(integration_id)
    with _lock:
        _get_conn().execute(
            f"UPDATE integrations SET {', '.join(sets)} WHERE integration_id = ?", params
        )
    return get_integration(integration_id)


def update_run_status(integration_id: str, status: str, last_run_at: datetime) -> None:
    with _lock:
        _get_conn().execute(
            "UPDATE integrations SET last_run_at = ?, last_run_status = ?, updated_at = ? "
            "WHERE integration_id = ?",
            [last_run_at, status, last_run_at, integration_id],
        )


def delete_integration(integration_id: str) -> bool:
    with _lock:
        conn = _get_conn()
        conn.execute("DELETE FROM integration_runs WHERE integration_id = ?", [integration_id])
        changed = conn.execute(
            "DELETE FROM integrations WHERE integration_id = ? RETURNING integration_id",
            [integration_id],
        ).fetchone()
    return changed is not None


def insert_run(integration_id: str) -> str:
    run_id = str(uuid.uuid4())
    now = datetime.utcnow()
    with _lock:
        _get_conn().execute(
            "INSERT INTO integration_runs (run_id, integration_id, started_at, status) VALUES (?,?,?,?)",
            [run_id, integration_id, now, "running"],
        )
    return run_id


def finish_run(
    run_id: str,
    status: str,
    events_pulled: int = 0,
    events_ingested: int = 0,
    error_message: Optional[str] = None,
    next_cursor: Optional[str] = None,
) -> None:
    now = datetime.utcnow()
    with _lock:
        _get_conn().execute(
            "UPDATE integration_runs SET finished_at=?, status=?, events_pulled=?, "
            "events_ingested=?, error_message=?, next_cursor=? WHERE run_id=?",
            [now, status, events_pulled, events_ingested, error_message, next_cursor, run_id],
        )


def get_last_cursor(integration_id: str) -> Optional[str]:
    with _lock:
        row = _get_conn().execute(
            "SELECT next_cursor FROM integration_runs WHERE integration_id = ? "
            "AND status = 'ok' ORDER BY finished_at DESC LIMIT 1",
            [integration_id],
        ).fetchone()
    return row[0] if row else None


def list_runs(integration_id: str, limit: int = 20, status: Optional[str] = None) -> list[dict]:
    params: list = [integration_id]
    where = "WHERE integration_id = ?"
    if status:
        where += " AND status = ?"; params.append(status)
    with _lock:
        rows = _get_conn().execute(
            f"SELECT {','.join(_RUN_COLS)} FROM integration_runs {where} "
            f"ORDER BY started_at DESC LIMIT ?",
            params + [limit],
        ).fetchall()
    return [_row_to_dict(r, _RUN_COLS) for r in rows]
