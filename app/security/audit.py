"""Audit log: who did what, when, from where."""
from flask import request

from app.db import get_db
from app.helpers import now_iso


def log_event(event, username=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (ts, event, username, ip) VALUES (?, ?, ?, ?)",
        (now_iso(), event, username, request.remote_addr),
    )
    db.commit()
