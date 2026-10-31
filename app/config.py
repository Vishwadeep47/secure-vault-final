"""Central settings. Change limits here, not inside the code."""
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


class Config:
    # Storage
    DB_PATH = os.environ.get("VAULT_DB", os.path.join(BASE_DIR, "securevault.db"))
    SECRETS_DIR = os.environ.get("VAULT_SECRETS_DIR", os.path.join(BASE_DIR, ".secrets"))

    # Login protection
    MAX_FAILED_LOGINS = 5
    LOCKOUT_SECONDS = 300

    # Sessions
    TOKEN_MINUTES = 15

    # Password reset
    RESET_TOKEN_MINUTES = 15
    RESET_REQUESTS_PER_WINDOW = 3     # "forgot" requests per username per window
    RESET_ATTEMPTS_PER_WINDOW = 10    # reset attempts per IP per window
    RESET_WINDOW_SECONDS = 900

    # Abuse limits (per IP address)
    REGISTER_PER_WINDOW = 20          # sign-up requests
    REGISTER_WINDOW_SECONDS = 3600
    LOGIN_PER_IP = 120                # login requests, across ALL usernames
    LOGIN_IP_WINDOW_SECONDS = 300
    JSON_MAX_BYTES = 200 * 1024       # biggest JSON body accepted (images have their own 10 MB limit)

    # Account rules (NIST SP 800-63B: length matters more than character mix)
    MIN_PASSWORD_LEN = 12
    MAX_PASSWORD_LEN = 128

    # MFA recovery codes
    RECOVERY_CODE_COUNT = 8

    # Secure share links (one note, one view)
    SHARE_LINK_MINUTES = 60
    SHARE_ATTEMPTS_PER_WINDOW = 20    # guesses at a share token per IP per window
    SHARE_WINDOW_SECONDS = 900

    # Vault notes
    NOTE_TITLE_MAX = 200
    NOTE_CONTENT_MAX = 20000

    # Image vault
    UPLOAD_DIR = os.environ.get("VAULT_UPLOAD_DIR", os.path.join(BASE_DIR, "uploads"))
    MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10 MB per request
    IMAGE_MAX_PIXELS = 25_000_000  # rejects "decompression bomb" images
