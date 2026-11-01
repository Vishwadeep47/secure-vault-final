"""Encrypted notes (internship Task 1 in action).

- Title is stored in plain text so notes can be listed.
- Content is encrypted with AES-256-GCM before it reaches the database.
- Each ciphertext is bound to BOTH its owner and its note id (AAD), so it cannot
  be moved to another user's note, or swapped with another note of the same user.
- Every query filters by the logged-in user's id: other people's notes look
  like they do not exist (404).
"""
import hashlib
import secrets
import time
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request

from app.auth.decorators import require_auth
from app.crypto import aes, userkeys
from app.db import get_db
from app.security import ratelimit
from app.security.audit import log_event

notes_bp = Blueprint("notes", __name__, url_prefix="/api/vault/notes")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _aad(user_id, note_id):
    return f"note:{user_id}:{note_id}"


def _json():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}


def _validate(data):
    """Return (title, content, error_message)."""
    cfg = current_app.config
    title = str(data.get("title", "")).strip()
    content = str(data.get("content", ""))
    if not title or not content.strip():
        return None, None, "title and content are required"
    if len(title) > cfg["NOTE_TITLE_MAX"]:
        return None, None, f"title must be at most {cfg['NOTE_TITLE_MAX']} characters"
    if len(content) > cfg["NOTE_CONTENT_MAX"]:
        return None, None, f"content must be at most {cfg['NOTE_CONTENT_MAX']} characters"
    return title, content, None


def _get_owned(note_id):
    return get_db().execute(
        "SELECT * FROM notes WHERE id = ? AND user_id = ?", (note_id, g.user["id"])
    ).fetchone()


@notes_bp.post("")
@require_auth()
def create_note():
    title, content, error = _validate(_json())
    if error:
        return jsonify(error=error), 400

    db = get_db()
    uid = g.user["id"]
    now = _now()
    # Insert first to get the id, then encrypt with the id in the AAD (one transaction).
    cur = db.execute(
        "INSERT INTO notes (user_id, title, content_enc, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (uid, title, "", now, now),
    )
    note_id = cur.lastrowid
    key, key_version = userkeys.current_key(uid)
    encrypted = aes.encrypt_text(key, content, _aad(uid, note_id))
    db.execute(
        "UPDATE notes SET content_enc = ?, key_version = ? WHERE id = ?", (encrypted, key_version, note_id)
    )
    db.commit()

    log_event("note_created", g.user["username"])
    return jsonify(id=note_id), 201


@notes_bp.get("")
@require_auth()
def list_notes():
    rows = get_db().execute(
        "SELECT id, title, created_at, updated_at FROM notes WHERE user_id = ? ORDER BY id DESC",
        (g.user["id"],),
    ).fetchall()
    return jsonify(notes=[dict(r) for r in rows])


@notes_bp.get("/<int:note_id>")
@require_auth()
def read_note(note_id):
    row = _get_owned(note_id)
    if row is None:
        return jsonify(error="Not found"), 404
    try:
        key = userkeys.get_key_for_version(g.user["id"], row["key_version"])
        content = aes.decrypt_text(key, row["content_enc"], _aad(g.user["id"], note_id))
    except (aes.InvalidTag, ValueError):
        # Wrong key, tampered data, or a ciphertext moved from another record.
        log_event("note_integrity_failure", g.user["username"])
        return jsonify(error="Data integrity check failed"), 500
    return jsonify(
        id=row["id"],
        title=row["title"],
        content=content,
        created_at=row["created_at"],
        updated_at=row["updated_at"],
    )


@notes_bp.put("/<int:note_id>")
@require_auth()
def update_note(note_id):
    if _get_owned(note_id) is None:
        return jsonify(error="Not found"), 404
    title, content, error = _validate(_json())
    if error:
        return jsonify(error=error), 400

    key, key_version = userkeys.current_key(g.user["id"])
    encrypted = aes.encrypt_text(key, content, _aad(g.user["id"], note_id))  # new random nonce on every update
    db = get_db()
    db.execute(
        "UPDATE notes SET title = ?, content_enc = ?, key_version = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (title, encrypted, key_version, _now(), note_id, g.user["id"]),
    )
    db.commit()
    log_event("note_updated", g.user["username"])
    return jsonify(message="Updated")


@notes_bp.delete("/<int:note_id>")
@require_auth()
def delete_note(note_id):
    db = get_db()
    cur = db.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?", (note_id, g.user["id"])
    )
    db.commit()
    if cur.rowcount == 0:
        return jsonify(error="Not found"), 404
    log_event("note_deleted", g.user["username"])
    return jsonify(message="Deleted")


# ------------------------------------------------------------- share links
# Lets someone without an account see one note, once, for a limited time -
# without logging in and without ever handing out the real credentials.
def _hash_share_token(token):
    return hashlib.sha256(token.encode()).hexdigest()


@notes_bp.get("/<int:note_id>/share")
@require_auth()
def share_link_status(note_id):
    """Whether an active (unused, unexpired) share link currently exists. The
    token itself is never shown again after creation - only its hash is kept."""
    if _get_owned(note_id) is None:
        return jsonify(error="Not found"), 404

    row = get_db().execute(
        "SELECT expires_at FROM share_links WHERE note_id = ? AND used = 0 AND expires_at > ?",
        (note_id, time.time()),
    ).fetchone()
    if row is None:
        return jsonify(active=False)
    return jsonify(active=True, expires_at=row["expires_at"])


@notes_bp.post("/<int:note_id>/share")
@require_auth()
def create_share_link(note_id):
    if _get_owned(note_id) is None:
        return jsonify(error="Not found"), 404

    token = secrets.token_urlsafe(32)
    minutes = current_app.config["SHARE_LINK_MINUTES"]
    expires_at = int(time.time()) + minutes * 60

    db = get_db()
    db.execute("DELETE FROM share_links WHERE note_id = ?", (note_id,))  # one active link per note
    db.execute(
        "INSERT INTO share_links (note_id, user_id, token_hash, expires_at, used, created_at) "
        "VALUES (?, ?, ?, ?, 0, ?)",
        (note_id, g.user["id"], _hash_share_token(token), expires_at, _now()),
    )
    db.commit()
    log_event("note_share_created", g.user["username"])
    return jsonify(token=token, expires_at=expires_at, minutes=minutes), 201


@notes_bp.delete("/<int:note_id>/share")
@require_auth()
def revoke_share_link(note_id):
    if _get_owned(note_id) is None:
        return jsonify(error="Not found"), 404

    cur = get_db().execute("DELETE FROM share_links WHERE note_id = ?", (note_id,))
    get_db().commit()
    if cur.rowcount:
        log_event("note_share_revoked", g.user["username"])
        return jsonify(message="Share link revoked")
    return jsonify(message="There was no active share link")


@notes_bp.get("/share/<token>")
def view_shared_note(token):
    """Public: no login needed. Works once, then the link is dead."""
    cfg = current_app.config
    if ratelimit.too_many_requests(
        f"share-view:{request.remote_addr}", cfg["SHARE_ATTEMPTS_PER_WINDOW"], cfg["SHARE_WINDOW_SECONDS"]
    ):
        return jsonify(error="Too many attempts. Try again later."), 429

    db = get_db()
    row = db.execute("SELECT * FROM share_links WHERE token_hash = ?", (_hash_share_token(token),)).fetchone()
    if row is None or row["used"] or row["expires_at"] < time.time():
        log_event("note_share_denied")
        return jsonify(error="This share link is invalid, used, or has expired"), 404

    note = db.execute("SELECT * FROM notes WHERE id = ?", (row["note_id"],)).fetchone()
    if note is None:
        return jsonify(error="This share link is invalid, used, or has expired"), 404

    # Used the moment it is looked up, even if decryption below somehow fails,
    # so a share link can never be retried past its one allowed view.
    db.execute("UPDATE share_links SET used = 1 WHERE id = ?", (row["id"],))
    db.commit()

    try:
        key = userkeys.get_key_for_version(row["user_id"], note["key_version"])
        content = aes.decrypt_text(key, note["content_enc"], _aad(row["user_id"], note["id"]))
    except (aes.InvalidTag, ValueError):
        log_event("note_integrity_failure")
        return jsonify(error="Data integrity check failed"), 500

    log_event("note_share_viewed")
    return jsonify(title=note["title"], content=content)
