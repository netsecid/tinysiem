from cryptography.fernet import Fernet
from app.config import settings


class MasterKeyNotConfigured(Exception):
    pass


def _fernet() -> Fernet:
    key = settings.tinysiem_master_key
    if not key:
        raise MasterKeyNotConfigured(
            "TINYSIEM_MASTER_KEY is not configured. "
            "Generate one with: python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    return Fernet(key.encode())


def encrypt(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode()).decode()
