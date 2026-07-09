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


def _evict_stale(skip_key: tuple[str, str]) -> None:
    """Remove entries that are neither actively counting toward a fresh lockout
    window nor currently serving an active lockout. Caller must hold `_lock`.
    `skip_key` (the key just processed by record_failure) is never evicted here,
    since its own state was just written and hasn't been re-checked yet.
    """
    now = _now()
    stale_keys = [
        k for k, entry in _failures.items()
        if k != skip_key and now >= entry["locked_until"] and entry["count"] < MAX_ATTEMPTS
    ]
    for k in stale_keys:
        del _failures[k]


def record_failure(key: tuple[str, str]) -> None:
    with _lock:
        entry = _failures.setdefault(key, {"count": 0, "locked_until": 0.0})
        entry["count"] += 1
        if entry["count"] >= MAX_ATTEMPTS:
            extra = entry["count"] - MAX_ATTEMPTS
            backoff = min(BASE_BACKOFF_SECONDS * (2 ** extra), MAX_BACKOFF_SECONDS)
            entry["locked_until"] = _now() + backoff
        _evict_stale(skip_key=key)


def record_success(key: tuple[str, str]) -> None:
    with _lock:
        _failures.pop(key, None)


def reset_all() -> None:
    """Test-only: clear all lockout state."""
    with _lock:
        _failures.clear()
