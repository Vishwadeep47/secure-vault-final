"""Audit log: who did what, when, from where."""
from datetime import datetime, timezone

from flask import request

from app.db import get_db


def log_event(event, username=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (ts, event, username, ip) VALUES (?, ?, ?, ?)",
        (
            datetime.now(timezone.utc).isoformat(timespec="seconds"),
            event,
            username,
            request.remote_addr,
        ),
    )
    db.commit()
