"""Checks for Step 10 (card vault). Run from the repo root:

    python tests/smoke_step10.py

Uses a temporary database and keys, so your real data is untouched.
Only well-known TEST card numbers are used.
"""
import base64
import json
import os
import sqlite3
import sys
import tempfile
from datetime import datetime, timezone

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
DB = app.config["DB_PATH"]
URL = "/api/vault/cards"
PW = "a-long-test-password"
YEAR = datetime.now(timezone.utc).year + 3
passed = 0


def check(name, condition):
    global passed
    print(("PASS  " if condition else "FAIL  ") + name)
    if not condition:
        sys.exit(1)
    passed += 1


def make_user(name):
    client.post("/api/register", json={"username": name, "password": PW})
    token = client.post("/api/login", json={"username": name, "password": PW}).json["token"]
    return {"Authorization": "Bearer " + token}


def card(number="4242 4242 4242 4242", **overrides):
    body = {"card_number": number, "holder_name": "Asha Verma", "exp_month": 12, "exp_year": YEAR}
    body.update(overrides)
    return body


def dump_db():
    con = sqlite3.connect(DB)
    return "\n".join(con.iterdump())


alice = make_user("alice")
bob = make_user("bob")
VISA = "4242424242424242"

# --- add / validate ---------------------------------------------------------
check("cards require login", client.get(URL).status_code == 401)
r = client.post(URL, json=card(cvv="123"), headers=alice)
check("add Visa test card (spaces allowed)", r.status_code == 201)
cid = r.json["id"]
check("response is masked with brand, last4, token",
      r.json["masked"] == "**** **** **** 4242" and r.json["brand"] == "visa"
      and r.json["last4"] == "4242" and r.json["token"].startswith("tok_"))
check("full number is not in the create response", VISA not in r.get_data(as_text=True))
check("CVV is not echoed back", "123" not in r.get_data(as_text=True) and "cvv" not in r.json)

check("Mastercard accepted and detected",
      client.post(URL, json=card("5555555555554444"), headers=alice).json["brand"] == "mastercard")
check("Amex (15 digits) accepted and detected",
      client.post(URL, json=card("378282246310005"), headers=alice).json["brand"] == "amex")
check("bad checksum rejected (Luhn)",
      client.post(URL, json=card("4242424242424241"), headers=alice).status_code == 400)
check("non-digit card number rejected",
      client.post(URL, json=card("4242-4242-abcd-4242"), headers=alice).status_code == 400)
check("too-short number rejected",
      client.post(URL, json=card("4242"), headers=alice).status_code == 400)
check("expired card rejected",
      client.post(URL, json=card("6011111111111117", exp_year=2020), headers=alice).status_code == 400)
check("invalid month rejected",
      client.post(URL, json=card("6011111111111117", exp_month=13), headers=alice).status_code == 400)
check("missing holder name rejected",
      client.post(URL, json=card("6011111111111117", holder_name=" "), headers=alice).status_code == 400)
check("duplicate card rejected (same number, any spacing)",
      client.post(URL, json=card("4242-4242-4242-4242"), headers=alice).status_code == 409)
check("same number is allowed for a different user",
      client.post(URL, json=card(), headers=bob).status_code == 201)

# --- nothing sensitive stored in plain ---------------------------------------
dump = dump_db()
raw_file = open(DB, "rb").read()
check("full card number is not in the database", VISA not in dump and VISA.encode() not in raw_file)
check("holder name is not in the database in plain text", "Asha Verma" not in dump and b"Asha Verma" not in raw_file)
check("no CVV column exists",
      "cvv" not in [c[1].lower() for c in sqlite3.connect(DB).execute("PRAGMA table_info(cards)")])
enc = sqlite3.connect(DB).execute("SELECT payload_enc FROM cards WHERE id=?", (cid,)).fetchone()[0]
payload = json.loads(aes.decrypt_text(app.config["AES_KEY"], enc, f"card:1:{cid}"))
check("encrypted payload holds only number, holder, expiry (no CVV)",
      set(payload) == {"number", "holder", "exp_month", "exp_year"})

# --- listing and details stay masked ---------------------------------------
listing = client.get(URL, headers=alice)
check("list is masked and shows no secrets",
      all("masked" in c and "payload_enc" not in c and "card_number" not in c for c in listing.json["cards"])
      and VISA not in listing.get_data(as_text=True))
detail = client.get(f"{URL}/{cid}", headers=alice)
check("details show holder and expiry but a masked number",
      detail.json["holder"] == "Asha Verma" and detail.json["exp_year"] == YEAR
      and VISA not in detail.get_data(as_text=True))
check("responses are not cached", detail.headers.get("Cache-Control") == "no-store")

# --- ownership --------------------------------------------------------------
check("other user cannot see my card", client.get(f"{URL}/{cid}", headers=bob).status_code == 404)
check("other user cannot reveal my card",
      client.post(f"{URL}/{cid}/reveal", json={"password": PW}, headers=bob).status_code == 404)
check("other user cannot delete my card", client.delete(f"{URL}/{cid}", headers=bob).status_code == 404)

# --- reveal needs the password again ----------------------------------------
check("reveal without password is refused",
      client.post(f"{URL}/{cid}/reveal", json={}, headers=alice).status_code == 401)
check("reveal with wrong password is refused",
      client.post(f"{URL}/{cid}/reveal", json={"password": "wrong-password-xx"}, headers=alice).status_code == 401)
r = client.post(f"{URL}/{cid}/reveal", json={"password": PW}, headers=alice)
check("reveal with correct password returns the full number",
      r.status_code == 200 and r.json["card_number"] == VISA)

# --- reveal with MFA enabled --------------------------------------------------
dave = make_user("dave")
dave_card = client.post(URL, json=card("5555555555554444"), headers=dave).json["id"]
secret = client.post("/api/mfa/setup", headers=dave).json["secret"]
client.post("/api/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=dave)
r = client.post(f"{URL}/{dave_card}/reveal", json={"password": PW}, headers=dave)
check("reveal asks for the MFA code when MFA is on", r.status_code == 401 and r.json.get("mfa_required") is True)
check("reveal with wrong MFA code is refused",
      client.post(f"{URL}/{dave_card}/reveal", json={"password": PW, "totp": "000000"}, headers=dave).status_code == 401)
r = client.post(f"{URL}/{dave_card}/reveal", json={"password": PW, "totp": pyotp.TOTP(secret).now()}, headers=dave)
check("reveal with password + MFA works", r.status_code == 200 and r.json["card_number"] == "5555555555554444")

# --- reveal is rate limited ---------------------------------------------------
carol = make_user("carol")
carol_card = client.post(URL, json=card("378282246310005"), headers=carol).json["id"]
for _ in range(5):
    client.post(f"{URL}/{carol_card}/reveal", json={"password": "wrong-password-xx"}, headers=carol)
check("reveal locks after 5 wrong attempts",
      client.post(f"{URL}/{carol_card}/reveal", json={"password": PW}, headers=carol).status_code == 429)

# --- audit log has events, never card data ------------------------------------
audit_rows = sqlite3.connect(DB).execute("SELECT event, username FROM audit_log").fetchall()
events = {row[0] for row in audit_rows}
check("audit log records card events",
      {"card_added", "card_revealed", "card_reveal_denied", "card_reveal_locked"} <= events)
audit_text = " ".join(f"{e} {u}" for e, u in audit_rows)
check("audit log contains no card data", all(x not in audit_text for x in (VISA, "5555555555554444", "Asha")))

# --- tampering and swapping -------------------------------------------------
con = sqlite3.connect(DB)
raw = bytearray(base64.b64decode(con.execute("SELECT payload_enc FROM cards WHERE id=?", (cid,)).fetchone()[0]))
raw[-1] ^= 1
con.execute("UPDATE cards SET payload_enc=? WHERE id=?", (base64.b64encode(bytes(raw)).decode(), cid))
con.commit()
check("tampered card data fails integrity check", client.get(f"{URL}/{cid}", headers=alice).status_code == 500)

ids = [r[0] for r in sqlite3.connect(DB).execute("SELECT id FROM cards WHERE user_id=1 ORDER BY id")]
con = sqlite3.connect(DB)
other_enc = con.execute("SELECT payload_enc FROM cards WHERE id=?", (ids[1],)).fetchone()[0]
con.execute("UPDATE cards SET payload_enc=? WHERE id=?", (other_enc, ids[2]))
con.commit()
check("card data swapped between two cards is rejected",
      client.get(f"{URL}/{ids[2]}", headers=alice).status_code == 500)

# --- delete -----------------------------------------------------------------
check("delete works", client.delete(f"{URL}/{ids[1]}", headers=alice).status_code == 200)
check("deleted card is gone", client.get(f"{URL}/{ids[1]}", headers=alice).status_code == 404)

print(f"\nAll {passed} checks passed. Step 10 is working.")
