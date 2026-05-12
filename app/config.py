from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    tinysiem_api_key: str
    tinysiem_debug: bool = False
    tinysiem_version: str = "0.1.0"
    tinysiem_duckdb_path: str = "/app/data/tinysiem.duckdb"
    tinysiem_chroma_path: str = "/app/data/chroma_store"
    tinysiem_alerts_path: str = "/app/data/alerts/alerts.log"
    tinysiem_alert_max_mb: int = 50

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
