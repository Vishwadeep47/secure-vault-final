"""Small helpers shared by the security tests."""
import base64
import io
import random
import sqlite3

from PIL import Image

PASSWORD = "a-long-test-password"
NOTE_TEXT = "TOP-SECRET-NOTE-TEXT-12345"
PAN = "4242424242424242"  # well-known TEST card number
HOLDER = "Asha Verma"


def db(app):
    return sqlite3.connect(app.config["DB_PATH"])


def bearer(token):
    return {"Authorization": "Bearer " + token}


def png_bytes(seed=1, size=(24, 24)):
    rnd = random.Random(seed)
    img = Image.new("RGB", size)
    img.putdata([(rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)) for _ in range(size[0] * size[1])])
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()


def card_body(number="4242 4242 4242 4242", **overrides):
    from datetime import datetime, timezone

    body = {"card_number": number, "holder_name": HOLDER, "exp_month": 12,
            "exp_year": datetime.now(timezone.utc).year + 3}
    body.update(overrides)
    return body


def flip_last_byte(b64_text):
    raw = bytearray(base64.b64decode(b64_text))
    raw[-1] ^= 1
    return base64.b64encode(bytes(raw)).decode()


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
