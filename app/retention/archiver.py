import gzip
import json
import logging
import threading
import time
from datetime import datetime, timedelta
from pathlib import Path

from app.config import settings
from app.storage import duckdb_store

logger = logging.getLogger(__name__)
_last_run: dict = {"time": None, "archived": 0}


def archive_old_events() -> dict:
    cutoff = datetime.utcnow() - timedelta(days=settings.tinysiem_retention_days)
    archive_dir = Path(settings.tinysiem_archive_path)
    archive_dir.mkdir(parents=True, exist_ok=True)
    chunk_bytes = settings.tinysiem_archive_chunk_mb * 1024 * 1024
    batch_size = 5000
    total_archived = 0
    files_written = []

    while True:
        rows = duckdb_store.query_events_for_archive(cutoff, limit=batch_size)
        if not rows:
            break

        existing = sorted(archive_dir.glob("*.jsonl.gz"))
        seq = len(existing) + 1
        date_str = cutoff.strftime("%Y-%m-%d")
        out_path = archive_dir / f"archive-{date_str}-{seq:03d}.jsonl.gz"

        ids_to_delete = []
        byte_count = 0
        with gzip.open(out_path, "wt", encoding="utf-8") as gz:
            for row in rows:
                line = json.dumps(row) + "\n"
                gz.write(line)
                byte_count += len(line.encode())
                ids_to_delete.append(row["id"])
                if byte_count >= chunk_bytes:
                    break

        duckdb_store.delete_events_by_ids(ids_to_delete)
        total_archived += len(ids_to_delete)
        files_written.append(out_path.name)
        logger.info(f"Archived {len(ids_to_delete)} events to {out_path.name}")

        if len(ids_to_delete) < batch_size:
            break

    _last_run["time"] = datetime.utcnow().isoformat()
    _last_run["archived"] = total_archived
    return {"archived": total_archived, "files": files_written}


def get_retention_status() -> dict:
    archive_dir = Path(settings.tinysiem_archive_path)
    files = []
    if archive_dir.exists():
        for f in sorted(archive_dir.glob("*.jsonl.gz")):
            stat = f.stat()
            files.append({
                "name": f.name,
                "size_mb": round(stat.st_size / (1024 * 1024), 2),
                "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            })
    return {
        "online_events": duckdb_store.count_all_events(),
        "retention_days": settings.tinysiem_retention_days,
        "archive_path": str(archive_dir),
        "archive_files": files,
        "last_run": _last_run.get("time"),
        "last_archived": _last_run.get("archived", 0),
    }


def _retention_loop() -> None:
    while True:
        time.sleep(6 * 3600)
        try:
            archive_old_events()
        except Exception as exc:
            logger.error(f"Retention archiver error: {exc}")


def start_retention_thread() -> None:
    t = threading.Thread(target=_retention_loop, daemon=True, name="retention-archiver")
    t.start()
    logger.info("Retention archiver thread started")
