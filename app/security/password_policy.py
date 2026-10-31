"""Password rules, following NIST SP 800-63B: check length and known-weak
passwords, and do not force periodic rotation or arbitrary character-mix rules.

One function, `password_error`, is the single place both sign-up and password
change/reset call, so the rule only has to be written once.
"""

# Passwords that show up at the top of every public "most common passwords"
# breach-analysis list. Being on this list is independent of length, so a
# long password can still fail here (e.g. "letmein1234567890").
COMMON_PASSWORDS = {
    "password", "password1", "password123", "passw0rd", "p@ssword", "p@ssw0rd",
    "123456", "123456789", "12345678", "1234567890", "1234567", "111111",
    "000000", "123123", "123321", "666666", "qwerty", "qwerty123", "qwertyuiop",
    "letmein", "letmein123", "welcome", "welcome1", "monkey", "dragon",
    "football", "baseball", "basketball", "soccer", "master", "superman",
    "iloveyou", "trustno1", "admin", "administrator", "root", "toor",
    "sunshine", "shadow", "ashley", "michael", "jennifer", "jordan23",
    "abc123", "abcd1234", "a1b2c3d4", "1q2w3e4r", "1q2w3e4r5t", "zxcvbnm",
    "asdfghjkl", "qazwsxedc", "changeme", "changeme123", "default",
    "guest", "guest123", "secret", "secret123", "whatever", "freedom",
    "ninja", "starwars", "princess", "login", "access", "flower",
    "hottie", "loveme", "biteme", "mustang", "harley", "cheese",
    "computer", "internet", "service", "google", "facebook", "instagram",
    "letmeinnow", "pass1234", "pass123456", "test1234", "demo1234",
}


def password_error(password, username=None):
    """Return an error message if the password breaks a rule, otherwise None."""
    from flask import current_app

    cfg = current_app.config
    if not (cfg["MIN_PASSWORD_LEN"] <= len(password) <= cfg["MAX_PASSWORD_LEN"]):
        return f"Password must be {cfg['MIN_PASSWORD_LEN']}-{cfg['MAX_PASSWORD_LEN']} characters"

    normalized = password.strip().lower()
    if normalized in COMMON_PASSWORDS:
        return "That password is too common. Choose one that is harder to guess."

    if username and normalized == username.strip().lower():
        return "Password cannot be the same as your username"

    return None
