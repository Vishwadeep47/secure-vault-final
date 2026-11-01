"""Authentication routes: register, login, MFA, current user."""
import re
import sqlite3
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request

from app.auth import mfa
from app.auth.decorators import require_auth
from app.auth.passwords import hash_password, verify_password
from app.auth.tokens import create_token
from app.crypto import aes
from app.crypto import userkeys
from app.db import get_db
from app.pagination import int_arg
from app.security import ratelimit
from app.security.audit import log_event
from app.security.password_policy import password_error

auth_bp = Blueprint("auth", __name__, url_prefix="/api")

USERNAME_RE = re.compile(r"[a-z0-9_]{3,32}")


def _json():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _mfa_aad(user_id):
    return f"mfa:{user_id}"


def _issue_recovery_codes(user_id):
    """Replace a user's recovery codes with a fresh set. Returns the plaintext
    codes, which are shown to the user exactly once and never stored."""
    db = get_db()
    codes = mfa.generate_recovery_codes(current_app.config["RECOVERY_CODE_COUNT"])
    db.execute("DELETE FROM recovery_codes WHERE user_id = ?", (user_id,))
    created_at = _now()
    db.executemany(
        "INSERT INTO recovery_codes (user_id, code_hash, used, created_at) VALUES (?, ?, 0, ?)",
        [(user_id, mfa.hash_recovery_code(code), created_at) for code in codes],
    )
    db.commit()
    return codes


def _consume_recovery_code(user_id, code):
    """Use a recovery code once. Returns True and marks it used, or False if it
    does not exist, was already used, or does not belong to this user."""
    db = get_db()
    row = db.execute(
        "SELECT id FROM recovery_codes WHERE user_id = ? AND code_hash = ? AND used = 0",
        (user_id, mfa.hash_recovery_code(code)),
    ).fetchone()
    if row is None:
        return False
    db.execute("UPDATE recovery_codes SET used = 1 WHERE id = ?", (row["id"],))
    db.commit()
    return True


@auth_bp.post("/register")
def register():
    cfg_limits = current_app.config
    if ratelimit.too_many_requests(
        f"register-ip:{request.remote_addr}", cfg_limits["REGISTER_PER_WINDOW"], cfg_limits["REGISTER_WINDOW_SECONDS"]
    ):
        log_event("register_rate_limited")
        return jsonify(error="Too many sign-ups from this address. Try again later."), 429

    data = _json()
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))

    if not USERNAME_RE.fullmatch(username):
        return jsonify(error="Username must be 3-32 characters: a-z, 0-9, underscore"), 400
    error = password_error(password, username=username)
    if error:
        return jsonify(error=error), 400

    db = get_db()
    is_first = db.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    role = "admin" if is_first else "user"  # first account becomes admin
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, _now()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="Username already taken"), 409

    new_user_id = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()[0]
    userkeys.issue_new_key(new_user_id)  # this account's own data-encryption key, not the shared server key

    log_event("register", username)
    return jsonify(message="Registered", role=role), 201


@auth_bp.post("/login")
def login():
    data = _json()
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    totp_code = str(data.get("totp", "")).strip()
    recovery_code = str(data.get("recovery_code", "")).strip()

    # Stops one address from trying thousands of different usernames.
    if ratelimit.too_many_requests(
        f"login-ip:{request.remote_addr}", current_app.config["LOGIN_PER_IP"], current_app.config["LOGIN_IP_WINDOW_SECONDS"]
    ):
        log_event("login_ip_limited")
        return jsonify(error="Too many login attempts from this address. Try again later."), 429

    if ratelimit.is_locked(username):
        log_event("login_locked", username)
        return jsonify(error="Too many failed attempts. Try again later."), 429

    user = get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username,)
    ).fetchone()

    # Same error + same work for "no such user" and "wrong password".
    if not verify_password(user["password_hash"] if user else None, password):
        ratelimit.register_failure(username)
        log_event("login_failed", username)
        return jsonify(error="Invalid credentials"), 401

    if user["disabled"]:
        log_event("login_denied_disabled", username)
        return jsonify(error="This account has been disabled. Contact an administrator."), 403

    if user["mfa_enabled"]:
        if recovery_code:
            if not _consume_recovery_code(user["id"], recovery_code):
                ratelimit.register_failure(username)
                log_event("mfa_recovery_failed", username)
                return jsonify(error="Invalid or already-used recovery code"), 401
            log_event("mfa_recovery_used", username)
        elif not totp_code:
            return jsonify(mfa_required=True), 401
        else:
            secret = aes.decrypt_text(
                current_app.config["AES_KEY"], user["mfa_secret"], _mfa_aad(user["id"])
            )
            if not mfa.verify_code(secret, totp_code):
                ratelimit.register_failure(username)
                log_event("mfa_failed", username)
                return jsonify(error="Invalid MFA code"), 401

    ratelimit.clear_failures(username)
    log_event("login_success", username)
    token = create_token(
        user["id"],
        user["role"],
        current_app.config["JWT_SECRET"],
        current_app.config["TOKEN_MINUTES"],
        user["token_version"],
    )
    return jsonify(token=token, role=user["role"])


@auth_bp.post("/logout")
@require_auth()
def logout():
    """Ends this session AND any other open session of the same account.

    Tokens carry a version number; raising it makes every older token invalid.
    """
    db = get_db()
    db.execute("UPDATE users SET token_version = token_version + 1 WHERE id = ?", (g.user["id"],))
    db.commit()
    log_event("logout", g.user["username"])
    return jsonify(message="Logged out")


@auth_bp.get("/me")
@require_auth()
def me():
    return jsonify(
        username=g.user["username"],
        role=g.user["role"],
        mfa_enabled=bool(g.user["mfa_enabled"]),
    )


@auth_bp.get("/me/activity")
@require_auth()
def my_activity():
    """This account's own recent activity - a user-facing slice of the audit
    log, scoped to events about them and nobody else."""
    limit, error = int_arg("limit", 20, 1, 100)
    if error:
        return jsonify(error=error), 400
    offset, error = int_arg("offset", 0, 0)
    if error:
        return jsonify(error=error), 400

    db = get_db()
    username = g.user["username"]
    total = db.execute("SELECT COUNT(*) FROM audit_log WHERE username = ?", (username,)).fetchone()[0]
    rows = db.execute(
        "SELECT ts, event, ip FROM audit_log WHERE username = ? ORDER BY id DESC LIMIT ? OFFSET ?",
        (username, limit, offset),
    ).fetchall()
    return jsonify(events=[dict(r) for r in rows], total=total, limit=limit, offset=offset)


@auth_bp.post("/encryption-key/rotate")
@require_auth()
def rotate_encryption_key():
    """Issues a new personal data key. New images and cards will be
    encrypted with it; existing ones keep decrypting fine under the key
    version they were written with (see app/crypto/userkeys.py)."""
    data = _json()
    if not verify_password(g.user["password_hash"], str(data.get("password", ""))):
        log_event("key_rotate_denied", g.user["username"])
        return jsonify(error="Current password is incorrect"), 401

    _, new_version = userkeys.issue_new_key(g.user["id"])
    log_event("key_rotated", g.user["username"])
    return jsonify(message="A new encryption key is now in use for new items.", key_version=new_version)


@auth_bp.post("/mfa/setup")
@require_auth()
def mfa_setup():
    # Once MFA is on, a stolen token must not be able to replace the secret.
    if g.user["mfa_enabled"]:
        return jsonify(error="MFA is already enabled"), 409

    secret = mfa.new_secret()
    db = get_db()
    db.execute(
        "UPDATE users SET mfa_secret = ?, mfa_enabled = 0 WHERE id = ?",
        (
            aes.encrypt_text(current_app.config["AES_KEY"], secret, _mfa_aad(g.user["id"])),
            g.user["id"],
        ),
    )
    db.commit()
    uri = mfa.provisioning_uri(secret, g.user["username"])
    return jsonify(otpauth_uri=uri, qr_svg=mfa.qr_svg(uri), secret=secret)


@auth_bp.post("/mfa/enable")
@require_auth()
def mfa_enable():
    if not g.user["mfa_secret"]:
        return jsonify(error="Call /api/mfa/setup first"), 400

    secret = aes.decrypt_text(
        current_app.config["AES_KEY"], g.user["mfa_secret"], _mfa_aad(g.user["id"])
    )
    if not mfa.verify_code(secret, str(_json().get("code", ""))):
        return jsonify(error="Invalid code"), 400

    db = get_db()
    db.execute("UPDATE users SET mfa_enabled = 1 WHERE id = ?", (g.user["id"],))
    db.commit()
    codes = _issue_recovery_codes(g.user["id"])
    log_event("mfa_enabled", g.user["username"])
    return jsonify(message="MFA enabled", recovery_codes=codes)


@auth_bp.get("/mfa/recovery-codes")
@require_auth()
def mfa_recovery_status():
    """How many unused recovery codes are left, so the UI can nudge a refill."""
    if not g.user["mfa_enabled"]:
        return jsonify(error="MFA is not enabled"), 400
    remaining = get_db().execute(
        "SELECT COUNT(*) FROM recovery_codes WHERE user_id = ? AND used = 0", (g.user["id"],)
    ).fetchone()[0]
    return jsonify(remaining=remaining)


@auth_bp.post("/mfa/recovery-codes/regenerate")
@require_auth()
def mfa_recovery_regenerate():
    """Invalidate all existing recovery codes and issue a fresh set. Needs the
    current password, since a stolen session token alone should not be enough
    to print a new get-in-anytime code."""
    if not g.user["mfa_enabled"]:
        return jsonify(error="MFA is not enabled"), 400
    if not verify_password(g.user["password_hash"], str(_json().get("password", ""))):
        log_event("mfa_recovery_regenerate_denied", g.user["username"])
        return jsonify(error="Current password is incorrect"), 401

    codes = _issue_recovery_codes(g.user["id"])
    log_event("mfa_recovery_regenerated", g.user["username"])
    return jsonify(recovery_codes=codes)
