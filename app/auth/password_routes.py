"""Password reset ("forgot password") and password change (Task 6, part 3).

Reset flow
  1. POST /api/auth/password/forgot  {username}
        Always answers with the same message, whether or not the account exists.
        Creates a random token, stores ONLY its SHA-256 hash, valid 15 minutes.
        The token is delivered through security/mailer.py (console in development).
  2. POST /api/auth/password/reset   {token, new_password}
        Token works once. Sets the new password and ends all older sessions.

Safety rules
  - Token is 256 bits of randomness and is stored hashed, like a password.
  - A new "forgot" request replaces any older token for that account.
  - Requests are rate limited per username and per IP; unknown and real usernames
    are limited identically, so limits reveal nothing.
  - Reset changes only the password. If the account has MFA, login still needs the code.
  - Changing a password raises token_version, so stolen/old session tokens stop working.
"""
import hashlib
import secrets
import time
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request

from app.auth import mfa
from app.auth.decorators import require_auth
from app.auth.passwords import hash_password, verify_password
from app.auth.tokens import create_token
from app.crypto import aes
from app.db import get_db
from app.security import mailer, ratelimit
from app.security.audit import log_event

password_bp = Blueprint("password", __name__, url_prefix="/api/auth/password")

GENERIC_FORGOT_MESSAGE = "If that account exists, a reset token has been issued."


def _json():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hash_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


def _password_error(password):
    cfg = current_app.config
    if not (cfg["MIN_PASSWORD_LEN"] <= len(password) <= cfg["MAX_PASSWORD_LEN"]):
        return f"Password must be {cfg['MIN_PASSWORD_LEN']}-{cfg['MAX_PASSWORD_LEN']} characters"
    return None


@password_bp.post("/forgot")
def forgot_password():
    username = str(_json().get("username", "")).strip().lower()[:64]
    cfg = current_app.config

    # Same limit for real and unknown usernames, so it leaks nothing.
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
        db.execute("DELETE FROM password_resets WHERE user_id = ?", (user["id"],))  # replaces older tokens
        db.execute(
            "INSERT INTO password_resets (user_id, token_hash, expires_at, created_at) VALUES (?, ?, ?, ?)",
            (user["id"], _hash_token(token), expires_at, _now_iso()),
        )
        db.commit()
        mailer.send_reset_token(user["username"], token)
        log_event("reset_requested", user["username"])  # the token itself is never logged

    return jsonify(message=GENERIC_FORGOT_MESSAGE)


@password_bp.post("/reset")
def reset_password():
    data = _json()
    token = str(data.get("token", "")).strip()
    new_password = str(data.get("new_password", ""))
    cfg = current_app.config

    if ratelimit.too_many_requests(
        f"reset-attempt:{request.remote_addr}", cfg["RESET_ATTEMPTS_PER_WINDOW"], cfg["RESET_WINDOW_SECONDS"]
    ):
        log_event("reset_attempts_limited")
        return jsonify(error="Too many attempts. Try again later."), 429

    # Check the password first so a typo does not use up the token.
    error = _password_error(new_password)
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

    ratelimit.clear_failures(user["username"])  # a locked-out user can get back in
    log_event("password_reset", user["username"])
    return jsonify(message="Password updated. Please log in with your new password.")


@password_bp.post("/change")
@require_auth()
def change_password():
    """Logged-in password change. Needs the current password (and MFA code if MFA is on)."""
    user = g.user
    username = user["username"]
    data = _json()

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
        secret = aes.decrypt_text(  # same AAD format as app/auth/routes.py
            current_app.config["AES_KEY"], user["mfa_secret"], f"mfa:{user['id']}"
        )
        if not mfa.verify_code(secret, code):
            ratelimit.register_failure(username)
            log_event("password_change_denied", username)
            return jsonify(error="Invalid MFA code"), 401

    error = _password_error(new_password)
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

    # Older sessions are now invalid; hand back a fresh token for this one.
    new_token = create_token(
        user["id"], user["role"], current_app.config["JWT_SECRET"],
        current_app.config["TOKEN_MINUTES"], user["token_version"] + 1,
    )
    return jsonify(message="Password changed", token=new_token)
