from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    tinysiem_api_key: str
    tinysiem_debug: bool = False
    tinysiem_version: str = "0.9.0"
    tinysiem_duckdb_path: str = "/app/data/tinysiem.duckdb"
    tinysiem_chroma_path: str = "/app/data/chroma_store"
    tinysiem_alerts_path: str = "/app/data/alerts/alerts.log"
    tinysiem_alert_max_mb: int = 50
    tinysiem_jwt_secret: str
    tinysiem_jwt_expiry_hours: int = 24
    tinysiem_superadmin_password: str = "admin"
    tinysiem_claude_api_key: str = ""
    tinysiem_mcp_enabled: bool = False

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

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
