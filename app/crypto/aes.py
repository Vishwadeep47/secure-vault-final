"""AES-256-GCM helpers (internship Task 1 logic).

- A fresh random 12-byte nonce is used for EVERY encryption, so the same input
  never gives the same output.
- GCM authenticates the data: any change to the stored bytes makes decryption fail.
- `aad` (associated data) binds a record to its owner, e.g. "user:5". Ciphertext
  copied into another user's row fails to decrypt.
"""
import base64
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_LEN = 12

__all__ = [
    "InvalidTag",
    "encrypt_bytes",
    "decrypt_bytes",
    "encrypt_text",
    "decrypt_text",
]


def encrypt_bytes(key, data, aad):
    nonce = secrets.token_bytes(NONCE_LEN)
    return nonce + AESGCM(key).encrypt(nonce, data, aad.encode())


def decrypt_bytes(key, blob, aad):
    if len(blob) < NONCE_LEN + 16:
        raise InvalidTag()
    nonce, ciphertext = blob[:NONCE_LEN], blob[NONCE_LEN:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad.encode())


def encrypt_text(key, text, aad):
    return base64.b64encode(encrypt_bytes(key, text.encode(), aad)).decode()


def decrypt_text(key, token, aad):
    return decrypt_bytes(key, base64.b64decode(token), aad).decode()
