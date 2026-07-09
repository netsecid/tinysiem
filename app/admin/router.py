import io
import shutil
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends
from fastapi.responses import StreamingResponse

from app.audit import store as audit
from app.auth import AuthUser, require_superadmin
from app.config import settings
from app.storage import duckdb_store

router = APIRouter(prefix="/admin", tags=["admin"])


@router.post("/backup")
def create_backup(actor: AuthUser = Depends(require_superadmin)):
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        db_export_dir = tmp_path / "duckdb_export"
        duckdb_store.export_database(str(db_export_dir))

        alerts_src = Path(settings.tinysiem_alerts_path).parent
        if alerts_src.exists():
            shutil.copytree(alerts_src, tmp_path / "alerts")

        rules_src = Path(__file__).resolve().parent.parent / "rules" / "rules" / "custom"
        if rules_src.exists() and any(rules_src.iterdir()):
            shutil.copytree(rules_src, tmp_path / "rules_custom")

        decoders_src = Path(__file__).resolve().parent.parent / "decoder" / "decoders" / "custom"
        if decoders_src.exists() and any(decoders_src.iterdir()):
            shutil.copytree(decoders_src, tmp_path / "decoders_custom")

        archive_buf = io.BytesIO()
        with tarfile.open(fileobj=archive_buf, mode="w:gz") as tar:
            tar.add(tmp_path, arcname="tinysiem-backup")
        archive_buf.seek(0)

    audit.log_event(
        "admin.backup", "created", "success",
        actor=actor.username, actor_role=actor.role,
    )

    filename = f"tinysiem-backup-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.tar.gz"
    return StreamingResponse(
        archive_buf,
        media_type="application/gzip",
        headers={"Content-Disposition": f"attachment; filename={filename}"},
    )
