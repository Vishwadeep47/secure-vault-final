"""Admin-only routes: audit log viewer, user list, summary numbers.

Every route needs a valid token AND the 'admin' role (checked against the
database on each request). A normal user gets 403 and the attempt is logged.

What admins can NOT see: password hashes, MFA secrets, images, card
data, or message text. The user list only shows counts of stored items.
"""
from datetime import datetime, timedelta, timezone

from flask import Blueprint, g, jsonify, request

from app.auth.decorators import require_auth
from app.db import get_db
from app.pagination import int_arg
from app.security import ratelimit
from app.security.audit import log_event, verify_chain

admin_bp = Blueprint("admin", __name__, url_prefix="/api/admin")

MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50


@admin_bp.get("/logs")
@require_auth(role="admin")
def audit_logs():
    """Newest first. Optional filters: ?event=login_failed&username=bob&limit=50&offset=0"""
    limit, error = int_arg("limit", DEFAULT_PAGE_SIZE, 1, MAX_PAGE_SIZE)
    if error:
        return jsonify(error=error), 400
    offset, error = int_arg("offset", 0, 0)
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


@admin_bp.get("/logs/verify")
@require_auth(role="admin")
def audit_logs_verify():
    """Checks the audit log's hash chain for signs of tampering (an edited,
    deleted, or inserted-out-of-order row). See app/security/audit.py."""
    result = verify_chain(get_db())
    return jsonify(**result)


@admin_bp.get("/users")
@require_auth(role="admin")
def list_users():
    rows = get_db().execute(
        """
        SELECT u.id, u.username, u.role, u.mfa_enabled, u.disabled, u.created_at,
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
        user["disabled"] = bool(user["disabled"])
        users.append(user)
    return jsonify(users=users)


def _target_user(user_id):
    return get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


@admin_bp.post("/users/<int:user_id>/disable")
@require_auth(role="admin")
def disable_user(user_id):
    """Blocks all login and ends any session already open, right away."""
    if user_id == g.user["id"]:
        return jsonify(error="You cannot disable your own account"), 400

    target = _target_user(user_id)
    if target is None:
        return jsonify(error="User not found"), 404

    db = get_db()
    db.execute(
        "UPDATE users SET disabled = 1, token_version = token_version + 1 WHERE id = ?", (user_id,)
    )
    db.commit()
    log_event("admin_disabled_user", target["username"])
    return jsonify(message=f"{target['username']} is disabled")


@admin_bp.post("/users/<int:user_id>/enable")
@require_auth(role="admin")
def enable_user(user_id):
    target = _target_user(user_id)
    if target is None:
        return jsonify(error="User not found"), 404

    db = get_db()
    db.execute("UPDATE users SET disabled = 0 WHERE id = ?", (user_id,))
    db.commit()
    log_event("admin_enabled_user", target["username"])
    return jsonify(message=f"{target['username']} is enabled")


@admin_bp.post("/users/<int:user_id>/unlock")
@require_auth(role="admin")
def unlock_user(user_id):
    """Clears a login lockout without touching the password or disabling anything."""
    target = _target_user(user_id)
    if target is None:
        return jsonify(error="User not found"), 404

    ratelimit.clear_failures(target["username"])
    log_event("admin_unlocked_user", target["username"])
    return jsonify(message=f"{target['username']} is unlocked")


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
        images=count("SELECT COUNT(*) FROM images"),
        cards=count("SELECT COUNT(*) FROM cards"),
        messages=count("SELECT COUNT(*) FROM messages"),
        events_last_24h={row["event"]: row["n"] for row in events},
    )
