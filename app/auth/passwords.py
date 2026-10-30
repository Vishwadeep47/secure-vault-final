"""Argon2 password hashing."""
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError

_hasher = PasswordHasher()

# For an unknown username we still verify against this, so the response time
# does not show which usernames exist.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing")


def hash_password(password):
    return _hasher.hash(password)


def verify_password(stored_hash, password):
    """True only if stored_hash exists and matches. Does the same work either way."""
    try:
        _hasher.verify(stored_hash or _DUMMY_HASH, password)
        return stored_hash is not None
    except (VerificationError, InvalidHashError):
        return False
