"""Login lockout per account, plus request counters per key (per IP, per username).

Everything is kept in memory, which has two limits:
  - It is forgotten when the server restarts. Redis or a database table would fix that.
  - If someone floods it with random names, the oldest entries are dropped once
    MAX_TRACKED is reached. The per-IP limits in the routes keep that flood small.
"""
import threading
import time

from flask import current_app

MAX_TRACKED = 10000  # most entries kept per table

_lock = threading.Lock()
_failures = {}  # username -> (failure_count, first_failure_timestamp)
_hits = {}      # key -> list of request timestamps


def _trim(table, age_of):
    """Drop the oldest entries once a table passes MAX_TRACKED. Call this with the lock held."""
    if len(table) <= MAX_TRACKED:
        return
    keep = int(MAX_TRACKED * 0.9)  # cut down in one batch so we do not re-sort on every call
    for key in sorted(table, key=lambda k: age_of(table[k]))[: len(table) - keep]:
        del table[key]


def is_locked(username):
    cfg = current_app.config
    with _lock:
        count, first = _failures.get(username, (0, 0.0))
        if count >= cfg["MAX_FAILED_LOGINS"]:
            if time.time() - first < cfg["LOCKOUT_SECONDS"]:
                return True
            _failures.pop(username, None)
    return False


def register_failure(username):
    with _lock:
        count, first = _failures.get(username, (0, time.time()))
        _failures[username] = (count + 1, first)
        _trim(_failures, lambda value: value[1])


def clear_failures(username):
    with _lock:
        _failures.pop(username, None)


def too_many_requests(key, limit, window_seconds):
    """Count one request for `key`. Returns True if it is over `limit` within the window."""
    now = time.time()
    with _lock:
        recent = [t for t in _hits.get(key, []) if now - t < window_seconds]
        if len(recent) >= limit:
            _hits[key] = recent
            return True
        recent.append(now)
        _hits[key] = recent
        _trim(_hits, lambda stamps: stamps[-1] if stamps else 0)
        return False


def clear_all():
    """Forget everything. Only the tests use this."""
    with _lock:
        _failures.clear()
        _hits.clear()
