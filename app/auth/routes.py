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
from app.db import get_db
from app.security import ratelimit
from app.security.audit import log_event

auth_bp = Blueprint("auth", __name__, url_prefix="/api")

USERNAME_RE = re.compile(r"[a-z0-9_]{3,32}")


def _json():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _mfa_aad(user_id):
    return f"mfa:{user_id}"


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
    cfg = current_app.config

    if not USERNAME_RE.fullmatch(username):
        return jsonify(error="Username must be 3-32 characters: a-z, 0-9, underscore"), 400
    if not (cfg["MIN_PASSWORD_LEN"] <= len(password) <= cfg["MAX_PASSWORD_LEN"]):
        return (
            jsonify(
                error=f"Password must be {cfg['MIN_PASSWORD_LEN']}-{cfg['MAX_PASSWORD_LEN']} characters"
            ),
            400,
        )

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

    log_event("register", username)
    return jsonify(message="Registered", role=role), 201


@auth_bp.post("/login")
def login():
    data = _json()
    username = str(data.get("username", "")).strip().lower()
    password = str(data.get("password", ""))
    totp_code = str(data.get("totp", "")).strip()

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

    if user["mfa_enabled"]:
        if not totp_code:
            return jsonify(mfa_required=True), 401
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
    log_event("mfa_enabled", g.user["username"])
    return jsonify(message="MFA enabled")
