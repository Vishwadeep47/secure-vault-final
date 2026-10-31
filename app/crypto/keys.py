"""Key creation and loading. Keys live OUTSIDE the database."""
import base64
import os
import secrets


def load_or_create_secret(name, secrets_dir, nbytes=32):
    """Return `nbytes` of secret key material.

    Order: environment variable (base64) -> file in secrets_dir -> create new file.
    In a real deployment use a secrets manager instead of local files.
    """
    env_val = os.environ.get(name.upper())
    if env_val:
        key = base64.b64decode(env_val)
    else:
        os.makedirs(secrets_dir, exist_ok=True)
        path = os.path.join(secrets_dir, name)
        if os.path.exists(path):
            with open(path, "rb") as f:
                key = f.read()
        else:
            key = secrets.token_bytes(nbytes)
            with open(path, "wb") as f:
                f.write(key)
            try:
                os.chmod(path, 0o600)  # limited effect on Windows, still good practice
            except OSError:
                pass

    if len(key) != nbytes:
        raise ValueError(f"Secret '{name}' must be {nbytes} bytes, got {len(key)}")
    return key
