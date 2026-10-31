"""JWT creation and verification."""
from datetime import datetime, timedelta, timezone

import jwt


def create_token(user_id, role, secret, minutes, version=0):
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "ver": version,  # bumped on password change, which ends all older sessions
        "iat": now,
        "exp": now + timedelta(minutes=minutes),
    }
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_token(token, secret):
    """Raises jwt.PyJWTError if the token is invalid, forged, or expired."""
    return jwt.decode(token, secret, algorithms=["HS256"])
