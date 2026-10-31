"""Argon2 password hashing."""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()

# Verified against when the username does not exist, so response time does not
# reveal which usernames are real.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")


def hash_password(password):
    return _hasher.hash(password)


def verify_password(stored_hash, password):
    """Return True only if stored_hash exists and matches. Always does real work."""
    try:
        _hasher.verify(stored_hash or _DUMMY_HASH, password)
        return stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False
