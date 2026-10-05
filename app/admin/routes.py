"""Admin-only routes: audit log viewer, user list, summary numbers.

Every route needs a valid token AND the 'admin' role (checked against the
database on each request). A normal user gets 403 and the attempt is logged.

What admins can NOT see: password hashes, MFA secrets, note text, images, or
card data. The user list only shows counts of stored items.
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, jsonify, request

from app.auth.decorators import require_auth
from app.db import get_db

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


def _int_arg(name, default, minimum, maximum=None):
    """Read an integer query parameter. Returns (value, error_message)."""
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default, None
    try:
        value = int(raw)
    except ValueError:
        return None, f"{name} must be a whole number"
    if value < minimum:
        return None, f"{name} must be at least {minimum}"
    if maximum is not None:
        value = min(value, maximum)  # quietly cap oversized requests
    return value, None


@admin_bp.get("/logs")
@require_auth(role="admin")
def audit_logs():
    """Newest first. Optional filters: ?event=login_failed&username=bob&limit=50&offset=0"""
    limit, error = _int_arg("limit", DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE)
    if error:
        return jsonify(error=error), 400
    offset, error = _int_arg("offset", 0, 0)
    if error:
        return jsonify(error=error), 400

    # Only fixed SQL fragments are joined; every value goes in as a parameter.
    where, params = [], []
    event = request.args.get("event", "").strip()
    if event:
        where.append("event = ?")
        params.append(event)
    username = request.args.get("username", "").strip().lower()
    if username:
        where.append("username = ?")
        params.append(username)
    clause = ("WHERE " + " AND ".join(where)) if where else ""

    db = get_db()
    total = db.execute(f"SELECT COUNT(*) FROM audit_log {clause}", params).fetchone()[0]
    rows = db.execute(
        f"SELECT id, ts, event, username, ip FROM audit_log {clause} "
        "ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [limit, offset],
    ).fetchall()
    return jsonify(logs=[dict(r) for r in rows], total=total, limit=limit, offset=offset)


@admin_bp.get("/users")
@require_auth(role="admin")
def list_users():
    rows = get_db().execute(
        """
        SELECT u.id, u.username, u.role, u.mfa_enabled, u.created_at,
               (SELECT COUNT(*) FROM notes  n WHERE n.user_id = u.id) AS notes_count,
               (SELECT COUNT(*) FROM images i WHERE i.user_id = u.id) AS images_count,
               (SELECT COUNT(*) FROM cards  c WHERE c.user_id = u.id) AS cards_count
        FROM users u
        ORDER BY u.id
        """
    ).fetchall()
    users = []
    for row in rows:
        user = dict(row)
        user["mfa_enabled"] = bool(user["mfa_enabled"])
        users.append(user)
    return jsonify(users=users)


@admin_bp.get("/stats")
@require_auth(role="admin")
def stats():
    db = get_db()

    def count(sql, params=()):
        return db.execute(sql, params).fetchone()[0]

    since = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat(timespec="seconds")
    events = db.execute(
        "SELECT event, COUNT(*) AS n FROM audit_log WHERE ts >= ? GROUP BY event ORDER BY n DESC",
        (since,),
    ).fetchall()

    return jsonify(
        users=count("SELECT COUNT(*) FROM users"),
        admins=count("SELECT COUNT(*) FROM users WHERE role = 'admin'"),
        mfa_enabled_users=count("SELECT COUNT(*) FROM users WHERE mfa_enabled = 1"),
        notes=count("SELECT COUNT(*) FROM notes"),
        images=count("SELECT COUNT(*) FROM images"),
        cards=count("SELECT COUNT(*) FROM cards"),
        events_last_24h={row["event"]: row["n"] for row in events},
    )
