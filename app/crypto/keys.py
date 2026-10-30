"""Creates and loads the secret keys. They are kept outside the database."""
import base64
import os
import secrets


def load_or_create_secret(name, secrets_dir, nbytes=32):
    """Return `nbytes` of secret key material.

    It looks in an environment variable (base64) first, then in a file inside
    secrets_dir, and creates the file if neither exists. On a real server a
    secrets manager would be better than local files.
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
                os.chmod(path, 0o600)  # does little on Windows, but harmless
            except OSError:
                pass

    if len(key) != nbytes:
        raise ValueError(f"Secret '{name}' must be {nbytes} bytes, got {len(key)}")
    return key
