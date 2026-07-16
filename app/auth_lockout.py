import threading
import time

MAX_ATTEMPTS = 5
BASE_BACKOFF_SECONDS = 60
MAX_BACKOFF_SECONDS = 900

_lock = threading.Lock()
_failures: dict[tuple[str, str], dict] = {}  # key -> {"count", "locked_until", "last_seen"}


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


def _evict_stale(now: float) -> None:
    """Remove entries that have not been touched in over MAX_BACKOFF_SECONDS.
    Caller must hold `_lock`.

    Staleness is measured purely from `last_seen` (the last time this key had a
    failure recorded), never from `locked_until` or `count` alone:
    - A sub-threshold entry that's actively accumulating failures has its
      `last_seen` refreshed on every attempt, so it survives sweeps triggered by
      *other* keys failing in between (this is what the old `now >=
      locked_until` check got wrong: `locked_until` stays 0.0 for sub-threshold
      entries, so that check was trivially true for every one of them on every
      call, letting an attacker interleave cheap decoy failures against unrelated
      keys to wipe out a target's in-progress count before it ever reached
      MAX_ATTEMPTS).
    - A currently-locked entry was necessarily touched within the last
      MAX_BACKOFF_SECONDS (its backoff is capped at MAX_BACKOFF_SECONDS), so it
      can never be evicted while the lockout is still active — by the time it's
      been idle long enough to be considered stale, any lockout on it has long
      since expired anyway.
    """
    stale_keys = [
        k for k, entry in _failures.items()
        if now - entry["last_seen"] > MAX_BACKOFF_SECONDS
    ]
    for k in stale_keys:
        del _failures[k]


def record_failure(key: tuple[str, str]) -> None:
    with _lock:
        now = _now()
        entry = _failures.setdefault(
            key, {"count": 0, "locked_until": 0.0, "last_seen": now}
        )
        entry["count"] += 1
        entry["last_seen"] = now
        if entry["count"] >= MAX_ATTEMPTS:
            extra = entry["count"] - MAX_ATTEMPTS
            backoff = min(BASE_BACKOFF_SECONDS * (2 ** extra), MAX_BACKOFF_SECONDS)
            entry["locked_until"] = now + backoff
        _evict_stale(now)


def check_and_note_attempt(key: tuple[str, str]) -> float:
    """Atomically check lockout status and, if not locked, immediately record this
    attempt as a provisional failure. Returns seconds remaining if locked (0.0 if the
    attempt was allowed and recorded). Callers MUST call record_success(key) on
    successful auth to clear the provisional failure — this closes the TOCTOU window
    where concurrent requests could all pass a separate is_locked() check before any
    of them called record_failure() (the expensive bcrypt verify in between gave
    concurrent requests time to stack up past MAX_ATTEMPTS)."""
    with _lock:
        now = _now()
        entry = _failures.get(key)
        if entry:
            remaining = entry["locked_until"] - now
            if remaining > 0:
                return remaining
        entry = _failures.setdefault(
            key, {"count": 0, "locked_until": 0.0, "last_seen": now}
        )
        entry["count"] += 1
        entry["last_seen"] = now
        if entry["count"] >= MAX_ATTEMPTS:
            extra = entry["count"] - MAX_ATTEMPTS
            backoff = min(BASE_BACKOFF_SECONDS * (2 ** extra), MAX_BACKOFF_SECONDS)
            entry["locked_until"] = now + backoff
        _evict_stale(now)
        return 0.0


def record_success(key: tuple[str, str]) -> None:
    with _lock:
        _failures.pop(key, None)


def reset_all() -> None:
    """Test-only: clear all lockout state."""
    with _lock:
        _failures.clear()
