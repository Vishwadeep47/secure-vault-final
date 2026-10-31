"""Quick check that Phase 1 works. Run from the repo root:

    python tests/smoke_phase1.py

Uses a temporary database and temporary keys, so it never touches your real data.
"""
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import pyotp  # noqa: E402

from app import create_app  # noqa: E402
from app.crypto import aes  # noqa: E402

tmp = tempfile.mkdtemp()
app = create_app({
    "DB_PATH": os.path.join(tmp, "test.db"),
    "SECRETS_DIR": os.path.join(tmp, "secrets"),
})
client = app.test_client()
passed = 0


def check(name, condition):
    global passed
    print(("PASS  " if condition else "FAIL  ") + name)
    if not condition:
        sys.exit(1)
    passed += 1


# --- crypto -----------------------------------------------------------------
key = app.config["AES_KEY"]
c1 = aes.encrypt_text(key, "hello", "user:1")
c2 = aes.encrypt_text(key, "hello", "user:1")
check("encrypt/decrypt round trip", aes.decrypt_text(key, c1, "user:1") == "hello")
check("same text gives different ciphertext (random nonce)", c1 != c2)
try:
    aes.decrypt_text(key, c1, "user:2")
    check("ciphertext bound to owner (wrong AAD fails)", False)
except aes.InvalidTag:
    check("ciphertext bound to owner (wrong AAD fails)", True)
tampered = bytearray(__import__("base64").b64decode(c1))
tampered[-1] ^= 1
try:
    aes.decrypt_text(key, __import__("base64").b64encode(bytes(tampered)).decode(), "user:1")
    check("tampered ciphertext is rejected", False)
except aes.InvalidTag:
    check("tampered ciphertext is rejected", True)

# --- auth -------------------------------------------------------------------
check("health endpoint", client.get("/api/health").json == {"status": "ok"})

r = client.post("/api/register", json={"username": "admin1", "password": "correct-horse-battery"})
check("first user registers as admin", r.status_code == 201 and r.json["role"] == "admin")
r = client.post("/api/register", json={"username": "bob", "password": "another-long-password"})
check("second user is a normal user", r.json["role"] == "user")
check("short password rejected",
      client.post("/api/register", json={"username": "eve", "password": "short"}).status_code == 400)
check("duplicate username rejected",
      client.post("/api/register", json={"username": "admin1", "password": "correct-horse-battery"}).status_code == 409)

stored = sqlite3.connect(app.config["DB_PATH"]).execute(
    "SELECT password_hash FROM users WHERE username='admin1'").fetchone()[0]
check("password stored as Argon2 hash, not plain text", stored.startswith("$argon2"))

check("wrong password rejected",
      client.post("/api/login", json={"username": "admin1", "password": "wrong-password-x"}).status_code == 401)
r = client.post("/api/login", json={"username": "admin1", "password": "correct-horse-battery"})
check("login returns token", r.status_code == 200 and "token" in r.json)
h = {"Authorization": "Bearer " + r.json["token"]}

check("/api/me with token", client.get("/api/me", headers=h).json["username"] == "admin1")
check("/api/me without token is 401", client.get("/api/me").status_code == 401)
check("forged token is 401",
      client.get("/api/me", headers={"Authorization": "Bearer abc.def.ghi"}).status_code == 401)

# --- MFA --------------------------------------------------------------------
secret = client.post("/api/mfa/setup", headers=h).json["secret"]
check("MFA secret stored encrypted",
      sqlite3.connect(app.config["DB_PATH"]).execute(
          "SELECT mfa_secret FROM users WHERE username='admin1'").fetchone()[0] != secret)
check("wrong MFA code rejected at enable",
      client.post("/api/mfa/enable", json={"code": "000000"}, headers=h).status_code == 400)
check("correct MFA code enables MFA",
      client.post("/api/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=h).status_code == 200)
check("MFA cannot be re-set up while enabled",
      client.post("/api/mfa/setup", headers=h).status_code == 409)

r = client.post("/api/login", json={"username": "admin1", "password": "correct-horse-battery"})
check("login now asks for MFA code", r.status_code == 401 and r.json.get("mfa_required") is True)
check("login with wrong MFA code rejected",
      client.post("/api/login", json={"username": "admin1", "password": "correct-horse-battery",
                                       "totp": "000000"}).status_code == 401)
check("login with correct MFA code works",
      client.post("/api/login", json={"username": "admin1", "password": "correct-horse-battery",
                                       "totp": pyotp.TOTP(secret).now()}).status_code == 200)

# --- lockout and audit ------------------------------------------------------
for _ in range(5):
    client.post("/api/login", json={"username": "ghost", "password": "whatever-password"})
check("locked after 5 failed attempts",
      client.post("/api/login", json={"username": "ghost", "password": "whatever-password"}).status_code == 429)

events = {row[0] for row in sqlite3.connect(app.config["DB_PATH"]).execute("SELECT event FROM audit_log")}
check("audit log records key events",
      {"register", "login_success", "login_failed", "login_locked", "mfa_enabled"} <= events)

print(f"\nAll {passed} checks passed. Phase 1 is working.")
