import json
import uuid
from datetime import datetime, timezone
from typing import Optional

from app.storage.duckdb_store import _get_conn, _lock  # noqa: PLC2701 — intentional internal access

_COLS = [
    "case_id", "title", "description", "severity", "status", "resolution",
    "assignee", "created_by", "created_at", "updated_at", "closed_at",
    "mitre_tactic", "mitre_technique", "tags",
]

_VALID_STATUSES = {"open", "investigating", "resolved"}
_VALID_RESOLUTIONS = {"true_positive", "false_positive", "benign", "undetermined"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


def _row_to_case(row: tuple) -> dict:
    d = dict(zip(_COLS, row))
    for ts_field in ("created_at", "updated_at", "closed_at"):
        v = d.get(ts_field)
        if v and hasattr(v, "isoformat"):
            d[ts_field] = v.isoformat() + "Z"
    if isinstance(d.get("tags"), str):
        try:
            d["tags"] = json.loads(d["tags"])
        except Exception:
            d["tags"] = []
    d["tags"] = d["tags"] or []
    return d


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def insert_case(
    title: str,
    created_by: str,
    description: Optional[str] = None,
    severity: str = "medium",
    assignee: Optional[str] = None,
    mitre_tactic: Optional[str] = None,
    mitre_technique: Optional[str] = None,
    tags: Optional[list] = None,
) -> dict:
    case_id = str(uuid.uuid4())
    now = _now()
    tags_json = json.dumps(tags or [])
    conn = _get_conn()
    with _lock:
        conn.execute(
            "INSERT INTO cases (case_id,title,description,severity,status,resolution,"
            "assignee,created_by,created_at,updated_at,closed_at,mitre_tactic,mitre_technique,tags) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            [case_id, title, description, severity, "open", None,
             assignee, created_by, now, now, None, mitre_tactic, mitre_technique, tags_json],
        )
        row = conn.execute(
            f"SELECT {','.join(_COLS)} FROM cases WHERE case_id = ?", [case_id]
        ).fetchone()
    return _row_to_case(row)


def query_cases(
    status: Optional[str] = None,
    severity: Optional[str] = None,
    assignee: Optional[str] = None,
    q: Optional[str] = None,
    start: Optional[datetime] = None,
    end: Optional[datetime] = None,
    limit: int = 50,
    offset: int = 0,
) -> dict:
    conditions: list[str] = []
    params: list = []
    if status:
        conditions.append("status = ?")
        params.append(status)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    if assignee:
        conditions.append("assignee = ?")
        params.append(assignee)
    if q:
        conditions.append("(title ILIKE ? OR description ILIKE ?)")
        params += [f"%{q}%", f"%{q}%"]
    if start:
        s = start.replace(tzinfo=None) if start.tzinfo else start
        conditions.append("created_at >= ?")
        params.append(s)
    if end:
        e = end.replace(tzinfo=None) if end.tzinfo else end
        conditions.append("created_at <= ?")
        params.append(e)
    where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
    conn = _get_conn()
    with _lock:
        total = conn.execute(f"SELECT COUNT(*) FROM cases {where}", params).fetchone()[0]
        rows = conn.execute(
            f"SELECT {','.join(_COLS)} FROM cases {where} ORDER BY updated_at DESC LIMIT ? OFFSET ?",
            params + [limit, offset],
        ).fetchall()
        # get alert + comment counts per case
        case_ids = [r[0] for r in rows]
        alert_counts: dict[str, int] = {}
        comment_counts: dict[str, int] = {}
        if case_ids:
            placeholders = ",".join("?" * len(case_ids))
            ac_rows = conn.execute(
                f"SELECT case_id, COUNT(*) FROM case_alerts WHERE case_id IN ({placeholders}) GROUP BY case_id",
                case_ids,
            ).fetchall()
            alert_counts = {r[0]: r[1] for r in ac_rows}
            cc_rows = conn.execute(
                f"SELECT case_id, COUNT(*) FROM case_comments WHERE case_id IN ({placeholders}) AND is_system = FALSE GROUP BY case_id",
                case_ids,
            ).fetchall()
            comment_counts = {r[0]: r[1] for r in cc_rows}
    cases = []
    for row in rows:
        c = _row_to_case(row)
        c["alert_count"] = alert_counts.get(c["case_id"], 0)
        c["comment_count"] = comment_counts.get(c["case_id"], 0)
        cases.append(c)
    return {"total": total, "cases": cases}


def get_case(case_id: str) -> Optional[dict]:
    conn = _get_conn()
    with _lock:
        row = conn.execute(
            f"SELECT {','.join(_COLS)} FROM cases WHERE case_id = ?", [case_id]
        ).fetchone()
        if not row:
            return None
        c = _row_to_case(row)
        # linked alert_ids
        al_rows = conn.execute(
            "SELECT alert_id, linked_at, linked_by FROM case_alerts WHERE case_id = ? ORDER BY linked_at",
            [case_id],
        ).fetchall()
        c["linked_alert_ids"] = [
            {"alert_id": r[0], "linked_at": r[1].isoformat() + "Z" if r[1] else None, "linked_by": r[2]}
            for r in al_rows
        ]
        ev_rows = conn.execute(
            "SELECT event_id, linked_at, linked_by FROM case_events WHERE case_id = ? ORDER BY linked_at",
            [case_id],
        ).fetchall()
        c["linked_event_ids"] = [
            {"event_id": r[0], "linked_at": r[1].isoformat() + "Z" if r[1] else None, "linked_by": r[2]}
            for r in ev_rows
        ]
        # comments + timeline
        cm_rows = conn.execute(
            "SELECT comment_id,author,body,created_at,edited_at,is_system "
            "FROM case_comments WHERE case_id = ? ORDER BY created_at",
            [case_id],
        ).fetchall()
        c["comments"] = [
            {
                "comment_id": r[0],
                "author": r[1],
                "body": r[2],
                "created_at": r[3].isoformat() + "Z" if r[3] else None,
                "edited_at": r[4].isoformat() + "Z" if r[4] else None,
                "is_system": bool(r[5]),
            }
            for r in cm_rows
        ]
    return c


def update_case(case_id: str, updates: dict) -> Optional[dict]:
    conn = _get_conn()
    allowed = {"title", "description", "severity", "status", "resolution",
               "assignee", "mitre_tactic", "mitre_technique", "tags"}
    sets = []
    params = []
    for k, v in updates.items():
        if k not in allowed:
            continue
        if k == "tags":
            v = json.dumps(v or [])
        sets.append(f"{k} = ?")
        params.append(v)
    if not sets:
        return get_case(case_id)
    now = _now()
    sets.append("updated_at = ?")
    params.append(now)
    if updates.get("status") == "resolved":
        sets.append("closed_at = ?")
        params.append(now)
    params.append(case_id)
    with _lock:
        conn.execute(f"UPDATE cases SET {', '.join(sets)} WHERE case_id = ?", params)
    return get_case(case_id)


def delete_case(case_id: str) -> bool:
    conn = _get_conn()
    with _lock:
        existing = conn.execute("SELECT case_id FROM cases WHERE case_id = ?", [case_id]).fetchone()
        if not existing:
            return False
        conn.execute("DELETE FROM case_comments WHERE case_id = ?", [case_id])
        conn.execute("DELETE FROM case_alerts WHERE case_id = ?", [case_id])
        conn.execute("DELETE FROM cases WHERE case_id = ?", [case_id])
    return True


def insert_comment(case_id: str, author: str, body: str, is_system: bool = False) -> dict:
    comment_id = str(uuid.uuid4())
    now = _now()
    conn = _get_conn()
    with _lock:
        conn.execute(
            "INSERT INTO case_comments (comment_id,case_id,author,body,created_at,edited_at,is_system) "
            "VALUES (?,?,?,?,?,?,?)",
            [comment_id, case_id, author, body, now, None, is_system],
        )
    return {
        "comment_id": comment_id,
        "case_id": case_id,
        "author": author,
        "body": body,
        "created_at": now.isoformat() + "Z",
        "edited_at": None,
        "is_system": is_system,
    }


def update_comment(comment_id: str, body: str) -> Optional[dict]:
    conn = _get_conn()
    now = _now()
    with _lock:
        row = conn.execute(
            "SELECT comment_id,case_id,author,body,created_at,edited_at,is_system "
            "FROM case_comments WHERE comment_id = ?",
            [comment_id],
        ).fetchone()
        if not row:
            return None
        conn.execute("UPDATE case_comments SET body = ?, edited_at = ? WHERE comment_id = ?",
                     [body, now, comment_id])
    return {
        "comment_id": row[0],
        "case_id": row[1],
        "author": row[2],
        "body": body,
        "created_at": row[4].isoformat() + "Z" if row[4] else None,
        "edited_at": now.isoformat() + "Z",
        "is_system": bool(row[6]),
    }


def delete_comment(comment_id: str) -> bool:
    conn = _get_conn()
    with _lock:
        existing = conn.execute(
            "SELECT comment_id FROM case_comments WHERE comment_id = ?", [comment_id]
        ).fetchone()
        if not existing:
            return False
        conn.execute("DELETE FROM case_comments WHERE comment_id = ?", [comment_id])
    return True


def get_comment(comment_id: str) -> Optional[dict]:
    conn = _get_conn()
    with _lock:
        row = conn.execute(
            "SELECT comment_id,case_id,author,body,created_at,edited_at,is_system "
            "FROM case_comments WHERE comment_id = ?",
            [comment_id],
        ).fetchone()
    if not row:
        return None
    return {
        "comment_id": row[0],
        "case_id": row[1],
        "author": row[2],
        "body": row[3],
        "created_at": row[4].isoformat() + "Z" if row[4] else None,
        "edited_at": row[5].isoformat() + "Z" if row[5] else None,
        "is_system": bool(row[6]),
    }


def link_alerts(case_id: str, alert_ids: list[str], linked_by: str) -> list[str]:
    now = _now()
    conn = _get_conn()
    linked = []
    with _lock:
        for aid in alert_ids:
            existing = conn.execute(
                "SELECT 1 FROM case_alerts WHERE case_id = ? AND alert_id = ?", [case_id, aid]
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO case_alerts (case_id,alert_id,linked_at,linked_by) VALUES (?,?,?,?)",
                    [case_id, aid, now, linked_by],
                )
                linked.append(aid)
    return linked


def unlink_alert(case_id: str, alert_id: str) -> bool:
    conn = _get_conn()
    with _lock:
        existing = conn.execute(
            "SELECT 1 FROM case_alerts WHERE case_id = ? AND alert_id = ?", [case_id, alert_id]
        ).fetchone()
        if not existing:
            return False
        conn.execute("DELETE FROM case_alerts WHERE case_id = ? AND alert_id = ?", [case_id, alert_id])
    return True


def link_events(case_id: str, event_ids: list[str], linked_by: str) -> list[str]:
    now = _now()
    conn = _get_conn()
    linked = []
    with _lock:
        for eid in event_ids:
            existing = conn.execute(
                "SELECT 1 FROM case_events WHERE case_id = ? AND event_id = ?", [case_id, eid]
            ).fetchone()
            if not existing:
                conn.execute(
                    "INSERT INTO case_events (case_id,event_id,linked_at,linked_by) VALUES (?,?,?,?)",
                    [case_id, eid, now, linked_by],
                )
                linked.append(eid)
    return linked


def unlink_event(case_id: str, event_id: str) -> bool:
    conn = _get_conn()
    with _lock:
        existing = conn.execute(
            "SELECT 1 FROM case_events WHERE case_id = ? AND event_id = ?", [case_id, event_id]
        ).fetchone()
        if not existing:
            return False
        conn.execute("DELETE FROM case_events WHERE case_id = ? AND event_id = ?", [case_id, event_id])
    return True


def get_cases_for_event(event_id: str) -> list[dict]:
    conn = _get_conn()
    with _lock:
        rows = conn.execute(
            """SELECT c.case_id, c.title, c.status, c.severity, ce.linked_at
               FROM case_events ce JOIN cases c ON ce.case_id = c.case_id
               WHERE ce.event_id = ?
               ORDER BY ce.linked_at DESC""",
            [event_id],
        ).fetchall()
    result = []
    for row in rows:
        linked_at = row[4]
        result.append({
            "case_id": row[0], "title": row[1], "status": row[2], "severity": row[3],
            "linked_at": linked_at.isoformat() + "Z" if linked_at and hasattr(linked_at, "isoformat") else None,
        })
    return result


def get_case_facets() -> dict:
    conn = _get_conn()

    def _counts(col: str) -> list[dict]:
        rows = conn.execute(
            f"SELECT {col}, COUNT(*) FROM cases GROUP BY {col} ORDER BY COUNT(*) DESC"
        ).fetchall()
        return [{"value": r[0], "count": r[1]} for r in rows if r[0] is not None]

    with _lock:
        return {
            "status": _counts("status"),
            "severity": _counts("severity"),
            "assignee": _counts("assignee"),
            "resolution": _counts("resolution"),
        }


# ── Playbook step completions ─────────────────────────────────────────────────

def get_step_completion(case_id: str, rule_name: str, step_id: str) -> Optional[dict]:
    conn = _get_conn()
    with _lock:
        row = conn.execute(
            "SELECT id, case_id, rule_name, step_id, completed_by, completed_at, note "
            "FROM case_playbook_steps WHERE case_id = ? AND rule_name = ? AND step_id = ?",
            [case_id, rule_name, step_id],
        ).fetchone()
    if not row:
        return None
    cols = ["id", "case_id", "rule_name", "step_id", "completed_by", "completed_at", "note"]
    d = dict(zip(cols, row))
    if d.get("completed_at") and hasattr(d["completed_at"], "isoformat"):
        d["completed_at"] = d["completed_at"].isoformat() + "Z"
    return d


def complete_step(
    case_id: str,
    rule_name: str,
    step_id: str,
    completed_by: str,
    note: Optional[str] = None,
) -> tuple[dict, bool]:
    row_id = str(uuid.uuid4())
    now = _now()
    conn = _get_conn()
    with _lock:
        existing = conn.execute(
            "SELECT id, case_id, rule_name, step_id, completed_by, completed_at, note "
            "FROM case_playbook_steps WHERE case_id = ? AND rule_name = ? AND step_id = ?",
            [case_id, rule_name, step_id],
        ).fetchone()
        if existing:
            cols = ["id", "case_id", "rule_name", "step_id", "completed_by", "completed_at", "note"]
            d = dict(zip(cols, existing))
            if d.get("completed_at") and hasattr(d["completed_at"], "isoformat"):
                d["completed_at"] = d["completed_at"].isoformat() + "Z"
            return d, False
        conn.execute(
            "INSERT INTO case_playbook_steps "
            "(id, case_id, rule_name, step_id, completed_by, completed_at, note) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [row_id, case_id, rule_name, step_id, completed_by, now, note],
        )
    return {
        "id": row_id, "case_id": case_id, "rule_name": rule_name,
        "step_id": step_id, "completed_by": completed_by,
        "completed_at": now.isoformat() + "Z", "note": note,
    }, True


def uncomplete_step(case_id: str, rule_name: str, step_id: str) -> bool:
    conn = _get_conn()
    with _lock:
        existing = conn.execute(
            "SELECT 1 FROM case_playbook_steps WHERE case_id = ? AND rule_name = ? AND step_id = ?",
            [case_id, rule_name, step_id],
        ).fetchone()
        if not existing:
            return False
        conn.execute(
            "DELETE FROM case_playbook_steps WHERE case_id = ? AND rule_name = ? AND step_id = ?",
            [case_id, rule_name, step_id],
        )
    return True


def get_completed_steps(case_id: str) -> list[dict]:
    conn = _get_conn()
    with _lock:
        rows = conn.execute(
            "SELECT id, case_id, rule_name, step_id, completed_by, completed_at, note "
            "FROM case_playbook_steps WHERE case_id = ? ORDER BY completed_at",
            [case_id],
        ).fetchall()
    cols = ["id", "case_id", "rule_name", "step_id", "completed_by", "completed_at", "note"]
    result = []
    for row in rows:
        d = dict(zip(cols, row))
        if d.get("completed_at") and hasattr(d["completed_at"], "isoformat"):
            d["completed_at"] = d["completed_at"].isoformat() + "Z"
        result.append(d)
    return result


def get_cases_for_alert(alert_id: str) -> list[dict]:
    conn = _get_conn()
    with _lock:
        rows = conn.execute(
            """SELECT c.case_id, c.title, c.status, c.severity, ca.linked_at
               FROM case_alerts ca JOIN cases c ON ca.case_id = c.case_id
               WHERE ca.alert_id = ?
               ORDER BY ca.linked_at DESC""",
            [alert_id],
        ).fetchall()
    result = []
    for row in rows:
        linked_at = row[4]
        result.append({
            "case_id": row[0],
            "title": row[1],
            "status": row[2],
            "severity": row[3],
            "linked_at": linked_at.isoformat() + "Z" if linked_at and hasattr(linked_at, "isoformat") else None,
        })
    return result
