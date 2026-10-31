"""Login lockout per account, plus request counters per key (per IP, per username).

Both are kept in the database instead of in memory, so a server restart does not
reset a lockout or a counter that an attacker is part-way through. Old rows are
deleted as a side effect of normal use, so the tables do not grow forever.
"""
import time

from flask import current_app, has_app_context

from app.db import get_db

# Rows older than this are deleted when touched, even if nothing else bounds
# the table. It is far bigger than any lockout or counting window the app uses.
MAX_AGE_SECONDS = 24 * 3600


def is_locked(username):
    cfg = current_app.config
    db = get_db()
    row = db.execute(
        "SELECT count, first_failure_at FROM login_failures WHERE username = ?", (username,)
    ).fetchone()
    if row is None:
        return False
    if row["count"] < cfg["MAX_FAILED_LOGINS"]:
        return False
    if time.time() - row["first_failure_at"] < cfg["LOCKOUT_SECONDS"]:
        return True
    db.execute("DELETE FROM login_failures WHERE username = ?", (username,))
    db.commit()
    return False


def register_failure(username):
    db = get_db()
    row = db.execute(
        "SELECT count, first_failure_at FROM login_failures WHERE username = ?", (username,)
    ).fetchone()
    now = time.time()
    if row is None:
        db.execute(
            "INSERT INTO login_failures (username, count, first_failure_at) VALUES (?, 1, ?)",
            (username, now),
        )
    else:
        db.execute(
            "UPDATE login_failures SET count = count + 1 WHERE username = ?", (username,)
        )
    # Forget failures nobody followed up on, so a flood of made-up usernames
    # does not grow this table without bound.
    db.execute("DELETE FROM login_failures WHERE first_failure_at < ?", (now - MAX_AGE_SECONDS,))
    db.commit()


def clear_failures(username):
    db = get_db()
    db.execute("DELETE FROM login_failures WHERE username = ?", (username,))
    db.commit()


def too_many_requests(key, limit, window_seconds):
    """Count one request for `key`. Returns True if it is over `limit` within the window."""
    db = get_db()
    now = time.time()
    recent = db.execute(
        "SELECT COUNT(*) FROM rate_hits WHERE rkey = ? AND ts > ?", (key, now - window_seconds)
    ).fetchone()[0]
    if recent >= limit:
        return True
    db.execute("INSERT INTO rate_hits (rkey, ts) VALUES (?, ?)", (key, now))
    db.execute("DELETE FROM rate_hits WHERE ts < ?", (now - MAX_AGE_SECONDS,))
    db.commit()
    return False


def clear_all():
    """Forget every lockout and counter. Nothing in the app calls this; it exists
    so a test can start a clean slate partway through, inside an app context."""
    if not has_app_context():
        return
    db = get_db()
    db.execute("DELETE FROM login_failures")
    db.execute("DELETE FROM rate_hits")
    db.commit()
