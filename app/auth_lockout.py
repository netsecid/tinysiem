import threading
import time

MAX_ATTEMPTS = 5
BASE_BACKOFF_SECONDS = 60
MAX_BACKOFF_SECONDS = 900

_lock = threading.Lock()
_failures: dict[tuple[str, str], dict] = {}  # key -> {"count": int, "locked_until": float}


def _now() -> float:
    return time.monotonic()


def is_locked(key: tuple[str, str]) -> float:
    """Return seconds remaining if the key is locked out, else 0.0."""
    with _lock:
        entry = _failures.get(key)
        if not entry:
            return 0.0
        remaining = entry["locked_until"] - _now()
        return max(0.0, remaining)


def record_failure(key: tuple[str, str]) -> None:
    with _lock:
        entry = _failures.setdefault(key, {"count": 0, "locked_until": 0.0})
        entry["count"] += 1
        if entry["count"] >= MAX_ATTEMPTS:
            extra = entry["count"] - MAX_ATTEMPTS
            backoff = min(BASE_BACKOFF_SECONDS * (2 ** extra), MAX_BACKOFF_SECONDS)
            entry["locked_until"] = _now() + backoff


def record_success(key: tuple[str, str]) -> None:
    with _lock:
        _failures.pop(key, None)


def reset_all() -> None:
    """Test-only: clear all lockout state."""
    with _lock:
        _failures.clear()
