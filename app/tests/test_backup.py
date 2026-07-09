import io
import tarfile


def test_export_database_writes_parquet_files(tmp_path):
    from app.storage import duckdb_store
    export_dir = tmp_path / "export"
    duckdb_store.export_database(str(export_dir))
    assert export_dir.exists()
    assert any(export_dir.glob("*.parquet"))


async def test_backup_returns_tar_gz(client, superadmin_headers):
    resp = await client.post("/admin/backup", headers=superadmin_headers)
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/gzip"
    buf = io.BytesIO(resp.content)
    with tarfile.open(fileobj=buf, mode="r:gz") as tar:
        names = tar.getnames()
    assert any("duckdb_export" in n for n in names)


async def test_backup_requires_superadmin(client, admin_headers):
    resp = await client.post("/admin/backup", headers=admin_headers)
    assert resp.status_code == 403


async def test_backup_requires_auth(client):
    resp = await client.post("/admin/backup")
    assert resp.status_code == 401
