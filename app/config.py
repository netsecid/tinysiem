from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    tinysiem_api_key: str
    tinysiem_debug: bool = False
    tinysiem_version: str = "1.0.0"
    tinysiem_duckdb_path: str = "/app/data/tinysiem.duckdb"
    tinysiem_alerts_path: str = "/app/data/alerts/alerts.log"
    tinysiem_alert_max_mb: int = 50
    tinysiem_jwt_secret: str
    tinysiem_jwt_expiry_hours: int = 24
    tinysiem_superadmin_password: str = "admin"
    tinysiem_mcp_enabled: bool = False
    tinysiem_ai_daily_call_limit: int = 100

    # Notifications
    tinysiem_smtp_host: str = ""
    tinysiem_smtp_port: int = 587
    tinysiem_smtp_user: str = ""
    tinysiem_smtp_pass: str = ""
    tinysiem_smtp_from: str = ""
    tinysiem_smtp_to: str = ""
    tinysiem_smtp_tls: bool = True
    tinysiem_webhook_url: str = ""
    tinysiem_notify_min_sev: str = "high"

    # Retention
    tinysiem_retention_days: int = 30
    tinysiem_archive_path: str = "/app/data/archive"
    tinysiem_archive_chunk_mb: int = 500

    # Reports
    tinysiem_report_schedule: str = "disabled"
    tinysiem_report_email: str = ""
    tinysiem_report_hour: int = 8

    # Listeners (v0.8)
    tinysiem_syslog_udp_port: int = 5140   # 0 = disabled
    tinysiem_syslog_tcp_port: int = 5141   # 0 = disabled
    tinysiem_beats_enabled: bool = True
    tinysiem_syslog_allow_cidrs: str = ""   # comma-separated CIDRs; empty = allow all
    tinysiem_syslog_max_bytes: int = 8192

    # Smart Baselines (v1.1)
    tinysiem_baseline_interval_minutes: int = 5
    tinysiem_baseline_z_threshold: float = 3.0
    tinysiem_baseline_min_samples: int = 4

    # API Integrations (v1.2)
    tinysiem_master_key: str = ""  # Fernet key; required when integrations are configured

    # CORS (v1.4)
    tinysiem_cors_origins: str = ""   # comma-separated allowed origins; empty = same-origin only

    # UI static dir (native-run override; empty = resolve repo ui/ relative to app/)
    tinysiem_ui_dir: str = ""

    # Read-only SQL sandbox (/query/sql)
    tinysiem_sql_enabled: bool = True
    tinysiem_sql_max_rows: int = 1000
    tinysiem_sql_timeout_ms: int = 5000

    # TLS (documented in .env.example + used by docker-entrypoint; declare here
    # so pydantic-settings accepts them when they appear in .env)
    tinysiem_tls_cert: str = ""
    tinysiem_tls_key: str = ""

    # GeoIP enrichment (v1.6) — offline IP → country/city/ASN lookup
    # Supported formats: db-ip lite CSV (.csv / .csv.gz, stdlib only) or
    # MaxMind GeoLite2 .mmdb (requires `pip install geoip2`). Empty = disabled.
    # Fetch a fresh db-ip lite DB: python scripts/fetch_geoip_db.py
    tinysiem_geoip_db_path: str = ""
    # Optional second .mmdb (MaxMind GeoLite2-ASN) to populate the `asn` field
    tinysiem_geoip_asn_path: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()


def parse_cors_origins(raw: str) -> list[str]:
    return [o.strip() for o in raw.split(",") if o.strip()]
