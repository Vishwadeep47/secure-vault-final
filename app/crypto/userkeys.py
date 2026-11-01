"""Per-user data encryption keys.

Every user gets their own random 256-bit key for their images and cards,
instead of everyone sharing the single server master key. The user's
key is "wrapped" (encrypted) by the server master key and stored in the
`user_keys` table; the master key never touches vault data directly once a
user has their own key.

Versions, not replacement: rotating a key adds version N+1 instead of
overwriting version N. Each image/card row remembers which version
encrypted it (its `key_version` column), so old records stay readable under
their original key after a rotation - this project does not re-encrypt
existing data when a key is rotated; only new writes use the new version.

Version 0 is special and always means "encrypted directly with the server
master key". That is what every record created before this feature existed
already used, so it needs no migration: it keeps decrypting exactly as
before. A brand-new user is issued version 1 the first time they need a key.
"""
import base64
import secrets as pysecrets

from flask import current_app

from app.crypto import aes
from app.db import get_db

KEY_BYTES = 32  # AES-256


def _wrap_aad(user_id, version):
    return f"userkey:{user_id}:{version}"


def current_key(user_id):
    """The user's current (highest-version) key, for encrypting something new.
    Returns (key_bytes, version). A user who has never been issued a personal
    key (key_version still 0) gets the server master key, version 0 - exactly
    what every record used before this feature existed."""
    db = get_db()
    user = db.execute("SELECT key_version FROM users WHERE id = ?", (user_id,)).fetchone()
    version = user["key_version"] if user else 0
    return get_key_for_version(user_id, version), version


def get_key_for_version(user_id, version):
    """The key that was current at a given version. Version 0 is always the
    server master key (see module docstring); other versions are unwrapped
    from `user_keys`."""
    if version == 0:
        return current_app.config["AES_KEY"]

    row = get_db().execute(
        "SELECT wrapped_key FROM user_keys WHERE user_id = ? AND version = ?", (user_id, version)
    ).fetchone()
    if row is None:
        raise LookupError(f"No key version {version} for user {user_id}")

    blob = base64.b64decode(row["wrapped_key"])
    return aes.decrypt_bytes(current_app.config["AES_KEY"], blob, _wrap_aad(user_id, version))


def issue_new_key(user_id):
    """Create a brand-new key version for a user and make it current. Used
    both the first time a user needs a key, and on an explicit key rotation."""
    db = get_db()
    current = db.execute(
        "SELECT COALESCE(MAX(version), 0) FROM user_keys WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    new_version = current + 1

    raw_key = pysecrets.token_bytes(KEY_BYTES)
    wrapped = aes.encrypt_bytes(current_app.config["AES_KEY"], raw_key, _wrap_aad(user_id, new_version))

    db.execute(
        "INSERT INTO user_keys (user_id, version, wrapped_key, created_at) VALUES (?, ?, ?, ?)",
        (user_id, new_version, base64.b64encode(wrapped).decode(), _now_iso()),
    )
    db.execute("UPDATE users SET key_version = ? WHERE id = ?", (new_version, user_id))
    db.commit()
    return raw_key, new_version


def _now_iso():
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat(timespec="seconds")
