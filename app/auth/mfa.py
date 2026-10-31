"""TOTP (authenticator app) helpers, plus MFA recovery codes.

A recovery code lets someone log in once without their authenticator app
(phone lost or broken). Each code is used at most once and is stored only as
a hash, the same way a password reset token is.
"""
import hashlib
import io
import secrets

import pyotp
import qrcode
import qrcode.image.svg


def new_secret():
    return pyotp.random_base32()


def provisioning_uri(secret, username, issuer="SecureVault"):
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_code(secret, code):
    code = (code or "").strip()
    if not (code.isdigit() and len(code) == 6):
        return False
    return pyotp.TOTP(secret).verify(code, valid_window=1)


def qr_svg(data):
    """Return a QR code for `data` as an SVG string (shown on the MFA setup screen)."""
    image = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buffer = io.BytesIO()
    image.save(buffer)
    return buffer.getvalue().decode()


def generate_recovery_codes(count):
    """Plaintext codes, shown to the user exactly once. Format: xxxxx-xxxxx."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o/1/i/l, so codes are easy to copy by hand
    codes = []
    for _ in range(count):
        half1 = "".join(secrets.choice(alphabet) for _ in range(5))
        half2 = "".join(secrets.choice(alphabet) for _ in range(5))
        codes.append(f"{half1}-{half2}")
    return codes


def hash_recovery_code(code):
    normalized = code.strip().lower()
    return hashlib.sha256(normalized.encode()).hexdigest()
