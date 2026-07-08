import logging

logger = logging.getLogger(__name__)

MIN_JWT_SECRET_LENGTH = 32


def validate_jwt_secret(secret: str) -> None:
    """Raise RuntimeError if the JWT signing secret is too weak to use safely."""
    if len(secret) < MIN_JWT_SECRET_LENGTH:
        raise RuntimeError(
            f"TINYSIEM_JWT_SECRET must be at least {MIN_JWT_SECRET_LENGTH} characters "
            f"(got {len(secret)}). Generate one with: openssl rand -hex 32"
        )


def warn_if_default_superadmin_password() -> None:
    """Log a loud warning if any superadmin still has must_change_password set."""
    from app.storage import duckdb_store
    for user in duckdb_store.list_users():
        if user["role"] == "superadmin" and user.get("must_change_password"):
            logger.warning(
                f"Superadmin '{user['username']}' still has the default password — "
                "log in and change it immediately."
            )


def warn_if_integrations_missing_master_key() -> None:
    """Log a warning if integrations are configured but TINYSIEM_MASTER_KEY is unset."""
    from app.config import settings
    from app.storage import duckdb_store
    if settings.tinysiem_master_key:
        return
    with duckdb_store._lock:
        count = duckdb_store._conn.execute("SELECT COUNT(*) FROM integrations").fetchone()[0]
    if count > 0:
        logger.warning(
            "Integrations are configured but TINYSIEM_MASTER_KEY is not set — "
            "integration polling will fail with 503 until it is."
        )
