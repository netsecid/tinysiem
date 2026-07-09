# Backup & Restore

## Backup

`POST /admin/backup` (superadmin only) streams a `tar.gz` containing:
- `duckdb_export/` — a consistent Parquet export of every DuckDB table (`EXPORT DATABASE`)
- `alerts/` — the alerts JSONL file(s), including any rotated `.log` files
- `rules_custom/` — any custom detection rules
- `decoders_custom/` — any custom parsers

```bash
curl -H "Authorization: Bearer <superadmin-jwt>" -o backup.tar.gz \
  http://localhost:8000/admin/backup
```

There is no scheduled/automatic backup — trigger this manually (e.g. via cron on the host calling `curl` against the API) as often as your recovery point objective requires.

## Restore

Restoring a live database is out of scope for a "tiny" SIEM — there is no `/admin/restore` endpoint. To restore manually:

1. Stop the stack: `docker-compose down`
2. Extract the backup: `tar xzf backup.tar.gz`
3. Copy `tinysiem-backup/duckdb_export/` into a fresh DuckDB instance:
   ```bash
   python3 -c "
   import duckdb
   conn = duckdb.connect('/path/to/tinysiem_data/tinysiem.duckdb')
   conn.execute(\"IMPORT DATABASE 'tinysiem-backup/duckdb_export'\")
   "
   ```
4. Copy `tinysiem-backup/alerts/*` back into the `TINYSIEM_ALERTS_PATH` directory.
5. Copy `tinysiem-backup/rules_custom/*` and `tinysiem-backup/decoders_custom/*` back into
   `app/rules/rules/custom/` and `app/decoder/decoders/custom/` respectively (these are
   bind-mounted or baked into the image depending on your deployment — adjust the target
   path to match).
6. `docker-compose up -d` and confirm `GET /health` returns `200`.
