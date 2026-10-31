"""Audit log: who did what, when, from where.

Each row is chained to the one before it (the "hash chain" idea from secure
logging designs, e.g. Schneier & Kelsey): its hash covers its own fields PLUS
the previous row's hash. Changing or deleting an old row, or inserting one in
the middle, breaks every hash after it. verify_chain() walks the table and
says whether that chain still holds.

Known limitation: this process does not run with multiple writers at once in
this project (the dev server and the test suite are single-threaded), so the
read-then-insert below is not wrapped in its own transaction. Under real
concurrent writers two entries could race for the same previous hash; that
would still not let anyone forge or silently drop an entry, only reorder two
log lines written at almost the same instant.

Rows written before this feature existed have no hash (an older database,
upgraded in place by app/db.py's migration). Those rows are not part of the
chain; the chain simply starts at the first row that has one.
"""
import hashlib
from datetime import datetime, timezone

from flask import request

from app.db import get_db

GENESIS_HASH = "0" * 64  # the "previous hash" of the very first row


def _row_hash(prev_hash, ts, event, username, ip):
    material = "|".join([prev_hash, ts, event, username or "", ip or ""])
    return hashlib.sha256(material.encode()).hexdigest()


def log_event(event, username=None):
    db = get_db()
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    ip = request.remote_addr

    prev = db.execute(
        "SELECT hash FROM audit_log WHERE hash IS NOT NULL ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_hash = prev["hash"] if prev else GENESIS_HASH
    row_hash = _row_hash(prev_hash, ts, event, username, ip)

    db.execute(
        "INSERT INTO audit_log (ts, event, username, ip, prev_hash, hash) VALUES (?, ?, ?, ?, ?, ?)",
        (ts, event, username, ip, prev_hash, row_hash),
    )
    db.commit()


def verify_chain(db):
    """Recompute every row's hash and compare it against what is stored.

    Returns a dict: {"ok": bool, "checked": N, "broken_at": id_or_None}.
    "broken_at" is the id of the first row whose stored hash does not match
    what its fields (and the row before it) say it should be - the first
    point where the log could have been tampered with.
    """
    rows = db.execute(
        "SELECT id, ts, event, username, ip, prev_hash, hash FROM audit_log "
        "WHERE hash IS NOT NULL ORDER BY id ASC"
    ).fetchall()

    expected_prev = GENESIS_HASH
    for row in rows:
        if row["prev_hash"] != expected_prev:
            return {"ok": False, "checked": len(rows), "broken_at": row["id"]}
        recomputed = _row_hash(expected_prev, row["ts"], row["event"], row["username"], row["ip"])
        if recomputed != row["hash"]:
            return {"ok": False, "checked": len(rows), "broken_at": row["id"]}
        expected_prev = row["hash"]

    return {"ok": True, "checked": len(rows), "broken_at": None}
