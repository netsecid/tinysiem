"""
Password hashing via passlib/bcrypt.

bcrypt >= 4.0 raises ValueError for passwords > 72 bytes, which breaks passlib 1.7.4's
internal wrap-bug detection (it tests with a 255-byte password). The patch below wraps
bcrypt.hashpw to silently truncate at 72 bytes — restoring the behavior that was implicit
in bcrypt < 4.0. Real passwords in this app are always well under 72 bytes.
"""
import bcrypt as _bcrypt_module

_orig_hashpw = _bcrypt_module.hashpw


def _patched_hashpw(password: bytes, salt: bytes) -> bytes:
    if isinstance(password, bytes) and len(password) > 72:
        password = password[:72]
    return _orig_hashpw(password, salt)


_bcrypt_module.hashpw = _patched_hashpw

from passlib.context import CryptContext  # noqa: E402 — must come after bcrypt patch

_pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(plain: str) -> str:
    return _pwd.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    return _pwd.verify(plain, hashed)
