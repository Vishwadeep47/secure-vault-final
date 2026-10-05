"""TOTP (authenticator app) helpers."""
import io

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
