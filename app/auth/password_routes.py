"""Forgot-password, reset and change-password routes (internship Task 6, part 3).

Reset works in two steps:
  1. POST /api/auth/password/forgot  {username}
     Gives the same answer whether or not the account exists. For a real account it
     makes a random token, stores only its SHA-256 hash, and sends the token through
     security/mailer.py. The token is valid for 15 minutes.
  2. POST /api/auth/password/reset   {token, new_password}
     The token works once. It sets the new password and logs out all older sessions.

Other points:
  - A new "forgot" request replaces any older token for that account.
  - Both steps are rate limited, and unknown usernames are limited the same way as
    real ones, so the limit does not reveal which accounts exist.
  - A reset only changes the password. If the account has MFA, login still needs the code.
"""
import hashlib
import secrets
import time

from flask import Blueprint, current_app, g, jsonify, request

from app.auth import mfa
from app.auth.decorators import require_auth
from app.auth.passwords import hash_password, verify_password
from app.auth.tokens import create_token
from app.db import get_db
from app.helpers import json_body, now_iso, password_length_error
from app.security import mailer, ratelimit
from app.security.audit import log_event

password_bp = Blueprint("password", __name__, url_prefix="/api/auth/password")

FORGOT_MESSAGE = "If that account exists, a reset token has been issued."


def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


@password_bp.post("/forgot")
def forgot_password():
    username = str(json_body().get("username", "")).strip().lower()[:64]
    cfg = current_app.config

    if ratelimit.too_many_requests(
        f"reset-request:{username}", cfg["RESET_REQUESTS_PER_WINDOW"], cfg["RESET_WINDOW_SECONDS"]
    ):
        log_event("reset_rate_limited", username)
        return jsonify(error="Too many reset requests. Try again later."), 429

    db = get_db()
    user = db.execute("SELECT id, username FROM users WHERE username = ?", (username,)).fetchone()
    if user is None:
        log_event("reset_requested_unknown", username)
    else:
        token = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + cfg["RESET_TOKEN_MINUTES"] * 60
        db.execute("DELETE FROM password_resets WHERE user_id = ?", (user["id"],))  # drop older tokens
        db.execute(
            "INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], _hash_token(token), expires_at, now_iso()),
        )
        db.commit()
        mailer.send_reset_token(user["username"], token)
        log_event("reset_requested", user["username"])  # the token itself is never logged

    return jsonify(message=FORGOT_MESSAGE)


@password_bp.post("/reset")
def reset_password():
    data = json_body()
    token = str(data.get("token", "")).strip()
    new_password = str(data.get("new_password", ""))
    cfg = current_app.config

    if ratelimit.too_many_requests(
        f"reset-attempt:{request.remote_addr}", cfg["RESET_ATTEMPTS_PER_WINDOW"], cfg["RESET_WINDOW_SECONDS"]
    ):
        log_event("reset_attempts_limited")
        return jsonify(error="Too many attempts. Try again later."), 429

    # Check the password before the token, so a typo does not use the token up.
    error = password_length_error(new_password)
    if error:
        return jsonify(error=error), 400

    db = get_db()
    row = db.execute(
        "SELECT * FROM password_resets WHERE token_hash = ?", (_hash_token(token),)
    ).fetchone()
    if row is None or row["used"] or row["expires_at"] < time.time():
        log_event("reset_failed")
        return jsonify(error="Invalid or expired reset token"), 400

    user = db.execute("SELECT * FROM users WHERE id = ?", (row["user_id"],)).fetchone()
    if verify_password(user["password_hash"], new_password):
        return jsonify(error="New password must be different from the current one"), 400

    db.execute(
        "UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
        (hash_password(new_password), user["id"]),
    )
    db.execute("UPDATE password_resets SET used = 1 WHERE id = ?", (row["id"],))
    db.commit()

    ratelimit.clear_failures(user["username"])  # so a locked-out user can log in again
    log_event("password_reset", user["username"])
    return jsonify(message="Password updated. Please log in with your new password.")


@password_bp.post("/change")
@require_auth()
def change_password():
    """Change the password while logged in. Needs the current password, and the MFA code if MFA is on."""
    user = g.user
    username = user["username"]
    data = json_body()

    if ratelimit.is_locked(username):
        log_event("password_change_locked", username)
        return jsonify(error="Too many failed attempts. Try again later."), 429

    current = str(data.get("current_password", ""))
    new_password = str(data.get("new_password", ""))

    if not verify_password(user["password_hash"], current):
        ratelimit.register_failure(username)
        log_event("password_change_denied", username)
        return jsonify(error="Current password is incorrect"), 401

    if user["mfa_enabled"]:
        code = str(data.get("totp", "")).strip()
        if not code:
            return jsonify(mfa_required=True), 401
        if not mfa.code_matches(user, code):
            ratelimit.register_failure(username)
            log_event("password_change_denied", username)
            return jsonify(error="Invalid MFA code"), 401

    error = password_length_error(new_password)
    if error:
        return jsonify(error=error), 400
    if new_password == current:
        return jsonify(error="New password must be different from the current one"), 400

    db = get_db()
    db.execute(
        "UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?",
        (hash_password(new_password), user["id"]),
    )
    db.commit()
    log_event("password_changed", username)

    # Older sessions are dead now, so give this one a fresh token.
    new_token = create_token(
        user["id"], user["role"], current_app.config["JWT_SECRET"],
        current_app.config["TOKEN_MINUTES"], user["token_version"] + 1,
    )
    return jsonify(message="Password changed", token=new_token)
