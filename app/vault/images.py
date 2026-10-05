"""Encrypted image vault (internship Task 3 in action).

Upload -> validate it really is an image -> encrypt the raw bytes with AES-256-GCM
(fresh random nonce) -> save the ciphertext to disk under a random name.
Only metadata (name, type, size) is kept in the database.

- File type is detected by Pillow from the actual bytes, never trusted from the
  filename or the client's Content-Type.
- Each file is bound to its owner and image id (AAD), so it cannot be moved to
  another user or swapped with another image.
- Decrypted images are sent with `Cache-Control: no-store` so they are not cached.
"""
import io
import os
import secrets
from datetime import datetime, timezone

from flask import Blueprint, current_app, g, jsonify, request, send_file
from PIL import Image, UnidentifiedImageError
from werkzeug.utils import secure_filename

from app.auth.decorators import require_auth
from app.crypto import aes
from app.db import get_db
from app.security.audit import log_event

images_bp = Blueprint("images", __name__, url_prefix="/api/vault/images")

ALLOWED_FORMATS = {
    "PNG": "image/png",
    "JPEG": "image/jpeg",
    "GIF": "image/gif",
    "WEBP": "image/webp",
}


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _aad(user_id, image_id):
    return f"image:{user_id}:{image_id}"


def _inspect_image(data):
    """Return (mime, error). Checks the bytes are a real, allowed, reasonably sized image."""
    try:
        with Image.open(io.BytesIO(data)) as img:
            fmt = img.format
            width, height = img.size
            if fmt not in ALLOWED_FORMATS:
                return None, "Only PNG, JPEG, GIF, or WEBP images are allowed"
            if width * height > current_app.config["IMAGE_MAX_PIXELS"]:
                return None, "Image dimensions are too large"
            img.verify()  # detects truncated or corrupt files
    except Image.DecompressionBombError:
        return None, "Image dimensions are too large"
    except (UnidentifiedImageError, OSError, SyntaxError, ValueError):
        return None, "File is not a valid image"
    return ALLOWED_FORMATS[fmt], None


def _file_path(stored_name):
    return os.path.join(current_app.config["UPLOAD_DIR"], stored_name)


def _get_owned(image_id):
    return get_db().execute(
        "SELECT * FROM images WHERE id = ? AND user_id = ?", (image_id, g.user["id"])
    ).fetchone()


@images_bp.post("")
@require_auth()
def upload_image():
    upload = request.files.get("file")
    if upload is None:
        return jsonify(error="Send the image in a form field named 'file'"), 400

    data = upload.read()
    if not data:
        return jsonify(error="File is empty"), 400

    mime, error = _inspect_image(data)
    if error:
        return jsonify(error=error), 400

    name = secure_filename(upload.filename or "")[:100] or "image"
    stored_name = secrets.token_hex(16) + ".bin"  # random, reveals nothing
    uid = g.user["id"]

    db = get_db()
    path = _file_path(stored_name)
    try:
        cur = db.execute(
            "INSERT INTO images (user_id, original_name, mime, size_bytes, stored_name, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (uid, name, mime, len(data), stored_name, _now()),
        )
        image_id = cur.lastrowid
        blob = aes.encrypt_bytes(current_app.config["AES_KEY"], data, _aad(uid, image_id))
        os.makedirs(current_app.config["UPLOAD_DIR"], exist_ok=True)
        with open(path, "wb") as f:
            f.write(blob)
        db.commit()
    except Exception:
        db.rollback()
        if os.path.exists(path):
            os.remove(path)
        current_app.logger.exception("Image upload failed")
        return jsonify(error="Could not store the image"), 500

    log_event("image_uploaded", g.user["username"])
    return jsonify(id=image_id, name=name, mime=mime, size_bytes=len(data)), 201


@images_bp.get("")
@require_auth()
def list_images():
    rows = get_db().execute(
        "SELECT id, original_name, mime, size_bytes, created_at FROM images "
        "WHERE user_id = ? ORDER BY id DESC",
        (g.user["id"],),
    ).fetchall()
    return jsonify(images=[dict(r) for r in rows])


@images_bp.get("/<int:image_id>")
@require_auth()
def download_image(image_id):
    row = _get_owned(image_id)
    if row is None:
        return jsonify(error="Not found"), 404

    try:
        with open(_file_path(row["stored_name"]), "rb") as f:
            blob = f.read()
    except FileNotFoundError:
        log_event("image_file_missing", g.user["username"])
        return jsonify(error="Stored file is missing"), 500

    try:
        data = aes.decrypt_bytes(
            current_app.config["AES_KEY"], blob, _aad(g.user["id"], image_id)
        )
    except (aes.InvalidTag, ValueError):
        log_event("image_integrity_failure", g.user["username"])
        return jsonify(error="Data integrity check failed"), 500

    response = send_file(
        io.BytesIO(data),
        mimetype=row["mime"],
        download_name=row["original_name"],
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response


@images_bp.delete("/<int:image_id>")
@require_auth()
def delete_image(image_id):
    row = _get_owned(image_id)
    if row is None:
        return jsonify(error="Not found"), 404

    db = get_db()
    db.execute("DELETE FROM images WHERE id = ? AND user_id = ?", (image_id, g.user["id"]))
    db.commit()
    try:
        os.remove(_file_path(row["stored_name"]))
    except FileNotFoundError:
        pass
    log_event("image_deleted", g.user["username"])
    return jsonify(message="Deleted")
