"""User-to-user messages.

- Every message body is encrypted with AES-256-GCM before it reaches the
  database, the same primitive used everywhere else in the vault.
- The associated data binds a ciphertext to BOTH the conversation pair (the
  two user ids, order-independent) and the message's own id, so a ciphertext
  copied into another message's row - or into a different conversation
  entirely - fails to decrypt instead of silently reading as something else.
- This is encryption at rest with the server's own master key, the same
  trust model the rest of the project documents: anyone who had the master
  key AND database access could read messages. It is deliberately not true
  end-to-end encryption (that would need each browser to hold a private key
  the server never sees, which this project's crypto design does not do
  anywhere else either). See docs/threat_model.md.
- A conversation is just "every message between me and one other user" -
  there is no separate conversation row to keep in sync.
"""
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request

from app.auth.decorators import require_auth
from app.crypto import aes
from app.db import get_db
from app.pagination import int_arg
from app.security import ratelimit
from app.security.audit import log_event

messages_bp = Blueprint("messages", __name__, url_prefix="/api/chat")


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _aad(user_a, user_b, message_id):
    lo, hi = sorted((user_a, user_b))
    return f"msg:{lo}:{hi}:{message_id}"


def _find_user(username):
    return get_db().execute(
        "SELECT * FROM users WHERE username = ?", (username.strip().lower(),)
    ).fetchone()


def _other_user_or_error(username):
    """Resolve the username in the URL to a row, or (None, response)."""
    if username.strip().lower() == g.user["username"]:
        return None, (jsonify(error="You cannot message yourself"), 400)
    other = _find_user(username)
    if other is None or other["disabled"]:
        return None, (jsonify(error="Not found"), 404)
    return other, None


@messages_bp.get("/users")
@require_auth()
def list_users():
    """Everyone you can start a conversation with: every other active account."""
    rows = get_db().execute(
        "SELECT username FROM users WHERE id != ? AND disabled = 0 ORDER BY username",
        (g.user["id"],),
    ).fetchall()
    return jsonify(users=[r["username"] for r in rows])


def _decrypt_row(row, me_id, other_id):
    key = current_app.config["AES_KEY"]
    body = aes.decrypt_text(key, row["body_enc"], _aad(me_id, other_id, row["id"]))
    return {
        "id": row["id"],
        "from_me": row["sender_id"] == me_id,
        "body": body,
        "created_at": row["created_at"],
    }


@messages_bp.get("/conversations")
@require_auth()
def list_conversations():
    """One row per person you have ever exchanged a message with, newest first,
    with a decrypted preview of the last message."""
    me = g.user["id"]
    db = get_db()
    pairs = db.execute(
        """
        SELECT other_id, MAX(id) AS last_id
        FROM (
            SELECT id, CASE WHEN sender_id = ? THEN recipient_id ELSE sender_id END AS other_id
            FROM messages WHERE sender_id = ? OR recipient_id = ?
        )
        GROUP BY other_id
        ORDER BY last_id DESC
        """,
        (me, me, me),
    ).fetchall()

    conversations = []
    for pair in pairs:
        other = db.execute("SELECT username FROM users WHERE id = ?", (pair["other_id"],)).fetchone()
        if other is None:
            continue
        last_row = db.execute("SELECT * FROM messages WHERE id = ?", (pair["last_id"],)).fetchone()
        try:
            decrypted = _decrypt_row(last_row, me, pair["other_id"])
            preview = decrypted["body"][:80]
        except (aes.InvalidTag, ValueError):
            log_event("message_integrity_failure", g.user["username"])
            preview = None
        conversations.append({
            "username": other["username"],
            "last_at": last_row["created_at"],
            "last_from_me": last_row["sender_id"] == me,
            "preview": preview,
        })
    return jsonify(conversations=conversations)


@messages_bp.get("/messages/<username>")
@require_auth()
def get_messages(username):
    other, error = _other_user_or_error(username)
    if error:
        return error
    after, err = int_arg("after", 0, 0)
    if err:
        return jsonify(error=err), 400

    me = g.user["id"]
    rows = get_db().execute(
        "SELECT * FROM messages WHERE "
        "((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)) "
        "AND id > ? ORDER BY id ASC",
        (me, other["id"], other["id"], me, after),
    ).fetchall()

    try:
        decrypted = [_decrypt_row(row, me, other["id"]) for row in rows]
    except (aes.InvalidTag, ValueError):
        log_event("message_integrity_failure", g.user["username"])
        return jsonify(error="Data integrity check failed"), 500

    return jsonify(messages=decrypted, with_user=other["username"])


@messages_bp.post("/messages/<username>")
@require_auth()
def send_message(username):
    other, error = _other_user_or_error(username)
    if error:
        return error

    cfg = current_app.config
    if ratelimit.too_many_requests(
        f"chat-send:{g.user['id']}", cfg["MESSAGE_SEND_LIMIT"], cfg["MESSAGE_SEND_WINDOW_SECONDS"]
    ):
        return jsonify(error="You're sending messages too fast. Try again in a bit."), 429

    data = request.get_json(silent=True)
    data = data if isinstance(data, dict) else {}
    body = str(data.get("body", "")).strip()
    if not body:
        return jsonify(error="Message cannot be empty"), 400
    if len(body) > cfg["MESSAGE_BODY_MAX"]:
        return jsonify(error=f"Message must be at most {cfg['MESSAGE_BODY_MAX']} characters"), 400

    me = g.user["id"]
    now = _now()
    db = get_db()
    # Insert first to get the id, then encrypt with the id bound into the AAD.
    cur = db.execute(
        "INSERT INTO messages (sender_id, recipient_id, body_enc, created_at) VALUES (?, ?, '', ?)",
        (me, other["id"], now),
    )
    message_id = cur.lastrowid
    encrypted = aes.encrypt_text(cfg["AES_KEY"], body, _aad(me, other["id"], message_id))
    db.execute("UPDATE messages SET body_enc = ? WHERE id = ?", (encrypted, message_id))
    db.commit()

    log_event("message_sent", g.user["username"])
    return jsonify(id=message_id, from_me=True, body=body, created_at=now), 201


@messages_bp.delete("/messages/<int:message_id>")
@require_auth()
def delete_message(message_id):
    db = get_db()
    cur = db.execute(
        "DELETE FROM messages WHERE id = ? AND sender_id = ?", (message_id, g.user["id"])
    )
    db.commit()
    if cur.rowcount == 0:
        return jsonify(error="Not found"), 404
    log_event("message_deleted", g.user["username"])
    return jsonify(message="Deleted")
