"""Encrypted notes (internship Task 1 in action).

- Title is stored in plain text so notes can be listed.
- Content is encrypted with AES-256-GCM before it reaches the database.
- Each ciphertext is bound to BOTH its owner and its note id (AAD), so it cannot
  be moved to another user's note, or swapped with another note of the same user.
- Every query filters by the logged-in user's id: other people's notes look
  like they do not exist (404).
"""
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request

from app.auth.decorators import require_auth
from app.crypto import aes
from app.db import get_db
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
    encrypted = aes.encrypt_text(current_app.config["AES_KEY"], content, _aad(uid, note_id))
    db.execute("UPDATE notes SET content_enc = ? WHERE id = ?", (encrypted, note_id))
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
        content = aes.decrypt_text(
            current_app.config["AES_KEY"], row["content_enc"], _aad(g.user["id"], note_id)
        )
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

    encrypted = aes.encrypt_text(  # new random nonce on every update
        current_app.config["AES_KEY"], content, _aad(g.user["id"], note_id)
    )
    db = get_db()
    db.execute(
        "UPDATE notes SET title = ?, content_enc = ?, updated_at = ? WHERE id = ? AND user_id = ?",
        (title, encrypted, _now(), note_id, g.user["id"]),
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
