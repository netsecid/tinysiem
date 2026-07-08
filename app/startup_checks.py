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
