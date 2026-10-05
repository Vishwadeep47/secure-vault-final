"""Route protection: valid JWT required, optional role check."""
from functools import wraps

import jwt
from flask import current_app, g, jsonify, request

from app.auth.tokens import decode_token
from app.db import get_db
from app.security.audit import log_event


def require_auth(role=None):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return jsonify(error="Missing token"), 401
            try:
                claims = decode_token(header[7:], current_app.config["JWT_SECRET"])
            except jwt.PyJWTError:
                return jsonify(error="Invalid or expired token"), 401

            user = get_db().execute(
                "SELECT * FROM users WHERE id = ?", (claims["sub"],)
            ).fetchone()
            if user is None:
                return jsonify(error="User not found"), 401

            # A password change/reset bumps token_version, which ends older sessions.
            if claims.get("ver", 0) != user["token_version"]:
                return jsonify(error="Session expired, please log in again"), 401

            # Role comes from the database, not from the token, so a role change
            # takes effect immediately.
            if role and user["role"] != role:
                log_event("forbidden_access", user["username"])
                return jsonify(error="Forbidden"), 403

            g.user = user
            return fn(*args, **kwargs)

        return wrapper

    return decorator
