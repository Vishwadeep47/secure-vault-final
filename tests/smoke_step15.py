"""Checks for Step 15 (password reset and change). Run from the repo root:

    python tests/smoke_step15.py

Uses a temporary database and keys, so your real data is untouched.
"""
import hashlib
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

import pyotp  # noqa: E402

from app import create_app  # noqa: E402
from app.auth.passwords import hash_password  # noqa: E402
from app.security import mailer, ratelimit  # noqa: E402

tmp = tempfile.mkdtemp()
app = create_app({
    "DB_PATH": os.path.join(tmp, "test.db"),
    "SECRETS_DIR": os.path.join(tmp, "secrets"),
    "UPLOAD_DIR": os.path.join(tmp, "uploads"),
    "RESET_ATTEMPTS_PER_WINDOW": 1000,  # raised for the main run, lowered in the last test
})
client = app.test_client()
DB = app.config["DB_PATH"]
PW = "a-long-test-password"
NEW = "brand-new-long-password"
FORGOT, RESET, CHANGE = "/api/auth/password/forgot", "/api/auth/password/reset", "/api/auth/password/change"
passed = 0

# Capture tokens instead of printing them to the console.
issued = []
mailer.send_reset_token = lambda username, token: issued.append((username, token))


def check(name, condition):
    global passed
    print(("PASS  " if condition else "FAIL  ") + name)
    if not condition:
        sys.exit(1)
    passed += 1


def register(name):
    client.post("/api/register", json={"username": name, "password": PW})


def login(name, password=PW, **extra):
    return client.post("/api/login", json={"username": name, "password": password, **extra})


def auth(response):
    return {"Authorization": "Bearer " + response.json["token"]}


def last_token():
    return issued[-1][1]


def db_all(sql, *params):
    return sqlite3.connect(DB).execute(sql, params).fetchall()


for name in ("alice", "bob", "carol", "dave", "erin"):
    register(name)
alice_old_session = auth(login("alice"))

# --- forgot password ----------------------------------------------------------
r_real = client.post(FORGOT, json={"username": "alice"})
r_fake = client.post(FORGOT, json={"username": "ghost"})
check("forgot gives the same answer for real and unknown users",
      r_real.status_code == r_fake.status_code == 200 and r_real.json == r_fake.json)
check("a token was issued only for the real user", [u for u, _ in issued] == ["alice"])
token1 = last_token()
check("token is not in the server response", token1 not in r_real.get_data(as_text=True))

stored = db_all("SELECT token_hash FROM password_resets")[0][0]
dump = "\n".join(sqlite3.connect(DB).iterdump())
check("only a hash of the token is stored", stored != token1 and token1 not in dump)

# --- reset: failures first ----------------------------------------------------
check("wrong token rejected",
      client.post(RESET, json={"token": "not-a-real-token", "new_password": NEW}).status_code == 400)
check("too-short new password rejected",
      client.post(RESET, json={"token": token1, "new_password": "short"}).status_code == 400)
check("new password equal to the current one rejected",
      client.post(RESET, json={"token": token1, "new_password": PW}).status_code == 400)
check("token survives those mistakes (not used up)", db_all("SELECT used FROM password_resets")[0][0] == 0)

# --- reset: success -------------------------------------------------------------
r = client.post(RESET, json={"token": token1, "new_password": NEW})
check("reset with a good token works", r.status_code == 200)
check("old password no longer works", login("alice", PW).status_code == 401)
check("new password works", login("alice", NEW).status_code == 200)
check("old session token is rejected after reset",
      client.get("/api/me", headers=alice_old_session).status_code == 401)
check("new session works", client.get("/api/me", headers=auth(login("alice", NEW))).status_code == 200)
check("token cannot be used twice",
      client.post(RESET, json={"token": token1, "new_password": "another-long-password"}).status_code == 400)

# --- expiry ---------------------------------------------------------------------
client.post(FORGOT, json={"username": "alice"})
token2 = last_token()
con = sqlite3.connect(DB)
con.execute("UPDATE password_resets SET expires_at = 0 WHERE token_hash = ?",
            (hashlib.sha256(token2.encode()).hexdigest(),))
con.commit()
check("expired token rejected",
      client.post(RESET, json={"token": token2, "new_password": "another-long-password"}).status_code == 400)

# --- new request replaces the old token -------------------------------------------
client.post(FORGOT, json={"username": "bob"})
bob_first = last_token()
client.post(FORGOT, json={"username": "bob"})
bob_second = last_token()
check("an older token stops working when a new one is requested",
      client.post(RESET, json={"token": bob_first, "new_password": NEW}).status_code == 400)
check("the newest token works",
      client.post(RESET, json={"token": bob_second, "new_password": NEW}).status_code == 200)

# --- rate limits ------------------------------------------------------------------
client.post(FORGOT, json={"username": "alice"})  # alice's 3rd request in the window
check("4th reset request for a real user is limited",
      client.post(FORGOT, json={"username": "alice"}).status_code == 429)
client.post(FORGOT, json={"username": "ghost"})  # ghost's 2nd
client.post(FORGOT, json={"username": "ghost"})  # ghost's 3rd
check("unknown users are limited exactly the same way",
      client.post(FORGOT, json={"username": "ghost"}).status_code == 429)

# --- reset clears a lockout ---------------------------------------------------------
for _ in range(5):
    login("carol", "wrong-password-xx")
check("carol is locked out", login("carol", PW).status_code == 429)
client.post(FORGOT, json={"username": "carol"})
client.post(RESET, json={"token": last_token(), "new_password": NEW})
check("reset lets a locked-out user back in", login("carol", NEW).status_code == 200)

# --- reset does not bypass MFA ---------------------------------------------------------
dave_session = auth(login("dave"))
secret = client.post("/api/mfa/setup", headers=dave_session).json["secret"]
client.post("/api/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=dave_session)
client.post(FORGOT, json={"username": "dave"})
client.post(RESET, json={"token": last_token(), "new_password": NEW})
r = login("dave", NEW)
check("after reset, login still asks for the MFA code", r.status_code == 401 and r.json.get("mfa_required") is True)
check("after reset, login works with password + MFA code",
      login("dave", NEW, totp=pyotp.TOTP(secret).now()).status_code == 200)

# --- change password (logged in) ---------------------------------------------------------
erin = auth(login("erin"))
check("change needs login", client.post(CHANGE, json={}).status_code == 401)
check("change with wrong current password refused",
      client.post(CHANGE, json={"current_password": "wrong-password-xx", "new_password": NEW}, headers=erin).status_code == 401)
check("change to a too-short password refused",
      client.post(CHANGE, json={"current_password": PW, "new_password": "short"}, headers=erin).status_code == 400)
check("change to the same password refused",
      client.post(CHANGE, json={"current_password": PW, "new_password": PW}, headers=erin).status_code == 400)
r = client.post(CHANGE, json={"current_password": PW, "new_password": NEW}, headers=erin)
check("change with correct current password works", r.status_code == 200 and "token" in r.json)
check("the session used for the change is ended", client.get("/api/me", headers=erin).status_code == 401)
check("the fresh token from the change works",
      client.get("/api/me", headers={"Authorization": "Bearer " + r.json["token"]}).status_code == 200)
check("old password fails, new password works", login("erin", PW).status_code == 401 and login("erin", NEW).status_code == 200)

dave2 = auth(login("dave", NEW, totp=pyotp.TOTP(secret).now()))
r = client.post(CHANGE, json={"current_password": NEW, "new_password": "yet-another-long-pass"}, headers=dave2)
check("change asks for the MFA code when MFA is on", r.status_code == 401 and r.json.get("mfa_required") is True)
check("change works with password + MFA code",
      client.post(CHANGE, json={"current_password": NEW, "new_password": "yet-another-long-pass",
                                "totp": pyotp.TOTP(secret).now()}, headers=dave2).status_code == 200)

# --- audit log ---------------------------------------------------------------------------
events = {row[0] for row in db_all("SELECT event FROM audit_log")}
check("audit log records reset and change events",
      {"reset_requested", "reset_requested_unknown", "password_reset", "password_changed",
       "reset_rate_limited", "password_change_denied", "reset_failed"} <= events)
audit_text = " ".join(f"{e} {u}" for e, u in db_all("SELECT event, username FROM audit_log"))
check("audit log contains no tokens", all(t not in audit_text for _, t in issued))

# --- older databases are upgraded automatically -----------------------------------------------
legacy_db = os.path.join(tmp, "legacy.db")
con = sqlite3.connect(legacy_db)
con.execute("""CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user', mfa_secret TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)""")
con.execute("INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, 'admin', 'x')",
            ("legacy", hash_password(PW)))
con.commit()
con.close()
legacy_app = create_app({"DB_PATH": legacy_db, "SECRETS_DIR": os.path.join(tmp, "secrets2"),
                         "UPLOAD_DIR": os.path.join(tmp, "uploads2")})
lc = legacy_app.test_client()
r = lc.post("/api/login", json={"username": "legacy", "password": PW})
check("database from an earlier step is upgraded and still works",
      r.status_code == 200 and lc.get("/api/me", headers={"Authorization": "Bearer " + r.json["token"]}).status_code == 200)

# --- limit on guessing reset tokens (per IP) -----------------------------------------------------
ratelimit.clear_all()
app.config["RESET_ATTEMPTS_PER_WINDOW"] = 3
codes = [client.post(RESET, json={"token": f"guess-{i}", "new_password": NEW}).status_code for i in range(4)]
check("guessing reset tokens is limited per IP (3 tries, then 429)", codes == [400, 400, 400, 429])

print(f"\nAll {passed} checks passed. Step 15 is working.")
