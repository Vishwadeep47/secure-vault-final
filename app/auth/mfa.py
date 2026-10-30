"""TOTP helpers for the authenticator app."""
import io

import pyotp
import qrcode
import qrcode.image.svg
from flask import current_app

from app.crypto import aes


def new_secret():
    return pyotp.random_base32()


def secret_aad(user_id):
    """Binds the stored MFA secret to one user (used when encrypting and decrypting it)."""
    return f"mfa:{user_id}"


def provisioning_uri(secret, username, issuer="SecureVault"):
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_code(secret, code):
    code = (code or "").strip()
    if not (code.isdigit() and len(code) == 6):
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def code_matches(user, code):
    """Check a 6-digit code against the secret stored (encrypted) on the user row."""
    secret = aes.decrypt_text(current_app.config["AES_KEY"], user["mfa_secret"], secret_aad(user["id"]))
    return verify_code(secret, code)


def qr_svg(data):
    """QR code for `data` as an SVG string, shown on the MFA setup screen."""
    image = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode()
