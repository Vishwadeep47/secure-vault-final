"""Reading page-size/offset query parameters safely. Shared by any route that
paginates a list (the admin audit log viewer, a user's own activity page)."""
from flask import request


def int_arg(name, default, minimum, maximum=None):
    """Read an integer query parameter. Returns (value, error_message)."""
    raw = request.args.get(name)
    if raw is None or raw == "":
        return default, None
    try:
        value = int(raw)
    except ValueError:
        return None, f"{name} must be a whole number"
    if value < minimum:
        return None, f"{name} must be at least {minimum}"
    if maximum is not None:
        value = min(value, maximum)  # quietly cap oversized requests
    return value, None
