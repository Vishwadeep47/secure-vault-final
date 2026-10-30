"""Small functions that several route files need."""
from datetime import datetime, timezone

from flask import current_app, request


def now_iso():
    """Current UTC time as text, e.g. 2026-10-30T11:58:00+00:00."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def json_body():
    """The request's JSON as a dict. Anything else (bad JSON, a list, nothing) gives {}."""
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def password_length_error(password):
    """Return an error message if the password length is not allowed, else None."""
    low = current_app.config["MIN_PASSWORD_LEN"]
    high = current_app.config["MAX_PASSWORD_LEN"]
    if not low <= len(password) <= high:
        return f"Password must be {low}-{high} characters"
    return None
