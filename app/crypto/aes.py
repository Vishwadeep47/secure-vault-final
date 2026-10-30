"""AES-256-GCM helpers (the encryption from internship Task 1).

Every call uses a new random 12-byte nonce, so encrypting the same text twice gives
different output. GCM also detects changes: if the stored bytes are altered,
decryption fails instead of returning garbage.

`aad` is extra data that is checked but not encrypted. We pass things like
"note:5:12" (owner and record), so a ciphertext copied to another user's row,
or swapped with another record, no longer decrypts.
"""
import base64
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12
TAG_LEN = 16


def encrypt_bytes(key, data, aad):
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, data, aad.encode())


def decrypt_bytes(key, blob, aad):
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise InvalidTag()
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad.encode())


def encrypt_text(key, text, aad):
    return base64.b64encode(encrypt_bytes(key, text.encode(), aad)).decode()


def decrypt_text(key, token, aad):
    return decrypt_bytes(key, base64.b64decode(token), aad).decode()
