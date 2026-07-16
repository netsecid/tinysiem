"""In-memory per-user rolling-window call counter for AI endpoints, to bound the cost
impact of a compromised or abusive low-privilege account looping paid AI calls. Mirrors
the design of app/auth_lockout.py (module-level dict + lock; resets on container
restart — an accepted trade-off for a cost control, not a security boundary)."""
import threading
import time

_lock = threading.Lock()
_calls: dict[str, list[float]] = {}
_WINDOW_SECONDS = 86400  # 24 hours


def check_and_record(username: str, limit: int) -> bool:
    """Return True and record this call if the user is under their daily limit,
    else return False without recording."""
    now = time.monotonic()
    with _lock:
        timestamps = _calls.setdefault(username, [])
        cutoff = now - _WINDOW_SECONDS
        while timestamps and timestamps[0] < cutoff:
            timestamps.pop(0)
        if len(timestamps) >= limit:
            return False
        timestamps.append(now)
        return True


def reset_all() -> None:
    """Test-only: clear all counters."""
    with _lock:
        _calls.clear()
