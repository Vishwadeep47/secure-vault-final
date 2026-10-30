"""Card vault (internship Task 5 in use). A learning project, not PCI DSS compliant,
so only use test numbers like 4242 4242 4242 4242, never real cards.

For each card we keep:
  token        a random "tok_..." id that stands in for the number
  last4, brand shown in the list
  fingerprint  keyed hash (HMAC), only used to spot duplicates
  payload_enc  the full number, holder name and expiry, encrypted with AES-256-GCM

The CVV is never stored. If the client sends one it is ignored.

Lists and details show a masked number. The full number only comes from /reveal,
which asks for the password again (and the MFA code if MFA is on), is rate limited
and is written to the audit log. Card data itself never goes in the log.
"""
import hashlib
import hmac
import json
import re
import secrets
import sqlite3
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from flask import Blueprint, current_app, g, jsonify

from app.auth import mfa
from app.auth.decorators import require_auth
from app.auth.passwords import verify_password
from app.crypto import aes
from app.db import get_db
from app.helpers import json_body, now_iso as _now
from app.security import ratelimit
from app.security.audit import log_event

cards_bp = Blueprint("cards", __name__, url_prefix="/api/vault/cards")

HOLDER_MAX = 60
LABEL_MAX = 50


@cards_bp.after_request
def _no_store(response):
    response.headers["Cache-Control"] = "no-store"
    return response


def _aad(user_id, card_id):
    return f"card:{user_id}:{card_id}"


def luhn_valid(number):
    """Luhn checksum. Card numbers are built to pass it, so it catches typing mistakes."""
    total = 0
    for i, ch in enumerate(reversed(number)):
        digit = int(ch)
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def detect_brand(number):
    if number.startswith("4"):
        return "visa"
    if number[:2] in ("51", "52", "53", "54", "55") or 2221 <= int(number[:4]) <= 2720:
        return "mastercard"
    if number[:2] in ("34", "37"):
        return "amex"
    return "other"


def mask(last4):
    return f"**** **** **** {last4}"


def _fingerprint(user_id, number):
    # Derive a separate key for the HMAC so the AES key is not used for two jobs.
    subkey = HKDF(
        algorithm=hashes.SHA256(), length=32, salt=None,
        info=b"securevault-card-fingerprint",
    ).derive(current_app.config["AES_KEY"])
    return hmac.new(subkey, f"{user_id}:{number}".encode(), hashlib.sha256).hexdigest()


def _parse_expiry(month, year):
    """Return (month, year, error)."""
    try:
        m = int(str(month).strip())
        y = int(str(year).strip())
    except ValueError:
        return None, None, "Expiry month and year must be numbers"
    if y < 100:
        y += 2000
    now = datetime.now(timezone.utc)
    if not 1 <= m <= 12:
        return None, None, "Expiry month must be 1-12"
    if y > now.year + 20:
        return None, None, "Expiry year is too far in the future"
    if (y, m) < (now.year, now.month):
        return None, None, "Card is expired"
    return m, y, None


def _get_owned(card_id):
    return get_db().execute(
        "SELECT * FROM cards WHERE id = ? AND user_id = ?", (card_id, g.user["id"])
    ).fetchone()


def _public(row):
    """Only fields that are safe to show. None of them reveals the card number."""
    return {
        "id": row["id"],
        "token": row["token"],
        "label": row["label"],
        "brand": row["brand"],
        "last4": row["last4"],
        "masked": mask(row["last4"]),
        "created_at": row["created_at"],
    }


def _decrypt_payload(row):
    raw = aes.decrypt_text(
        current_app.config["AES_KEY"], row["payload_enc"], _aad(row["user_id"], row["id"])
    )
    return json.loads(raw)


@cards_bp.post("")
@require_auth()
def add_card():
    data = json_body()
    # A "cvv" field, if sent, is ignored on purpose: never read, stored or logged.
    number = re.sub(r"[ -]", "", str(data.get("card_number", "")))
    holder = str(data.get("holder_name", "")).strip()
    label = str(data.get("label", "")).strip()

    if not re.fullmatch(r"\d{12,19}", number):
        return jsonify(error="Card number must be 12-19 digits"), 400
    if not luhn_valid(number):
        return jsonify(error="Card number failed the checksum (Luhn) check"), 400
    if not holder or len(holder) > HOLDER_MAX:
        return jsonify(error=f"Holder name is required (max {HOLDER_MAX} characters)"), 400
    if len(label) > LABEL_MAX:
        return jsonify(error=f"Label must be at most {LABEL_MAX} characters"), 400
    exp_month, exp_year, error = _parse_expiry(data.get("exp_month"), data.get("exp_year"))
    if error:
        return jsonify(error=error), 400

    uid = g.user["id"]
    brand = detect_brand(number)
    last4 = number[-4:]
    token = "tok_" + secrets.token_hex(12)
    label = label or f"{brand.capitalize()} ending {last4}"
    payload = json.dumps(
        {"number": number, "holder": holder, "exp_month": exp_month, "exp_year": exp_year}
    )

    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO cards (user_id, token, label, brand, last4, fingerprint, payload_enc, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (uid, token, label, brand, last4, _fingerprint(uid, number), "", _now()),
        )
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify(error="This card is already saved"), 409

    card_id = cur.lastrowid
    encrypted = aes.encrypt_text(current_app.config["AES_KEY"], payload, _aad(uid, card_id))
    db.execute("UPDATE cards SET payload_enc = ? WHERE id = ?", (encrypted, card_id))
    db.commit()

    log_event("card_added", g.user["username"])  # the event only, never card data
    return jsonify(
        id=card_id, token=token, label=label, brand=brand, last4=last4, masked=mask(last4)
    ), 201


@cards_bp.get("")
@require_auth()
def list_cards():
    rows = get_db().execute(
        "SELECT * FROM cards WHERE user_id = ? ORDER BY id DESC", (g.user["id"],)
    ).fetchall()
    return jsonify(cards=[_public(r) for r in rows])


@cards_bp.get("/<int:card_id>")
@require_auth()
def card_details(card_id):
    row = _get_owned(card_id)
    if row is None:
        return jsonify(error="Not found"), 404
    try:
        payload = _decrypt_payload(row)
    except (aes.InvalidTag, ValueError):
        log_event("card_integrity_failure", g.user["username"])
        return jsonify(error="Data integrity check failed"), 500
    details = _public(row)
    details.update(
        holder=payload["holder"], exp_month=payload["exp_month"], exp_year=payload["exp_year"]
    )
    return jsonify(details)  # the number stays masked here


@cards_bp.post("/<int:card_id>/reveal")
@require_auth()
def reveal_card(card_id):
    """Give back the full card number after re-checking the password (and MFA if it is on)."""
    user = g.user
    username = user["username"]
    row = _get_owned(card_id)
    if row is None:
        return jsonify(error="Not found"), 404

    if ratelimit.is_locked(username):
        log_event("card_reveal_locked", username)
        return jsonify(error="Too many failed attempts. Try again later."), 429

    data = json_body()
    if not verify_password(user["password_hash"], str(data.get("password", ""))):
        ratelimit.register_failure(username)
        log_event("card_reveal_denied", username)
        return jsonify(error="Re-enter your password to reveal the card number"), 401

    if user["mfa_enabled"]:
        code = str(data.get("totp", "")).strip()
        if not code:
            return jsonify(mfa_required=True), 401
        if not mfa.code_matches(user, code):
            ratelimit.register_failure(username)
            log_event("card_reveal_denied", username)
            return jsonify(error="Invalid MFA code"), 401

    try:
        payload = _decrypt_payload(row)
    except (aes.InvalidTag, ValueError):
        log_event("card_integrity_failure", username)
        return jsonify(error="Data integrity check failed"), 500

    log_event("card_revealed", username)
    return jsonify(
        card_number=payload["number"],
        holder=payload["holder"],
        exp_month=payload["exp_month"],
        exp_year=payload["exp_year"],
    )


@cards_bp.delete("/<int:card_id>")
@require_auth()
def delete_card(card_id):
    db = get_db()
    cur = db.execute("DELETE FROM cards WHERE id = ? AND user_id = ?", (card_id, g.user["id"]))
    db.commit()
    if cur.rowcount == 0:
        return jsonify(error="Not found"), 404
    log_event("card_deleted", g.user["username"])
    return jsonify(message="Deleted")
