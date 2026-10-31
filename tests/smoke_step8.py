"""Checks for Step 8 (encrypted notes). Run from the repo root:

    python tests/smoke_step8.py

Uses a temporary database and keys, so your real data is untouched.
"""
import base64
import os
import sqlite3
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir)))

from app import create_app  # noqa: E402

tmp = tempfile.mkdtemp()
app = create_app({
    "DB_PATH": os.path.join(tmp, "test.db"),
    "SECRETS_DIR": os.path.join(tmp, "secrets"),
})
client = app.test_client()
DB = app.config["DB_PATH"]
passed = 0


def check(name, condition):
    global passed
    print(("PASS  " if condition else "FAIL  ") + name)
    if not condition:
        sys.exit(1)
    passed += 1


def make_user(name):
    client.post("/api/register", json={"username": name, "password": "a-long-test-password"})
    token = client.post("/api/login", json={"username": name, "password": "a-long-test-password"}).json["token"]
    return {"Authorization": "Bearer " + token}


alice = make_user("alice")
bob = make_user("bob")
SECRET = "my very secret note text"

# --- create / list / read ---------------------------------------------------
check("notes require login", client.get("/api/vault/notes").status_code == 401)
r = client.post("/api/vault/notes", json={"title": "First", "content": SECRET}, headers=alice)
check("create note", r.status_code == 201)
nid = r.json["id"]

listing = client.get("/api/vault/notes", headers=alice).json["notes"]
check("list shows title but not content", listing[0]["title"] == "First" and "content" not in listing[0])
check("read returns decrypted content", client.get(f"/api/vault/notes/{nid}", headers=alice).json["content"] == SECRET)

stored = sqlite3.connect(DB).execute("SELECT content_enc FROM notes WHERE id=?", (nid,)).fetchone()[0]
check("database holds ciphertext, not the text", SECRET not in stored and "secret" not in stored.lower())

# --- validation -------------------------------------------------------------
check("empty content rejected",
      client.post("/api/vault/notes", json={"title": "x", "content": "  "}, headers=alice).status_code == 400)
check("too-long title rejected",
      client.post("/api/vault/notes", json={"title": "t" * 201, "content": "x"}, headers=alice).status_code == 400)
check("too-long content rejected",
      client.post("/api/vault/notes", json={"title": "x", "content": "c" * 20001}, headers=alice).status_code == 400)

# --- ownership --------------------------------------------------------------
check("other user cannot read my note", client.get(f"/api/vault/notes/{nid}", headers=bob).status_code == 404)
check("other user cannot edit my note",
      client.put(f"/api/vault/notes/{nid}", json={"title": "h", "content": "hacked"}, headers=bob).status_code == 404)
check("other user cannot delete my note", client.delete(f"/api/vault/notes/{nid}", headers=bob).status_code == 404)
check("other user's list is empty", client.get("/api/vault/notes", headers=bob).json["notes"] == [])
check("my note survived those attempts", client.get(f"/api/vault/notes/{nid}", headers=alice).json["content"] == SECRET)

# --- update re-encrypts with a new nonce -----------------------------------
client.put(f"/api/vault/notes/{nid}", json={"title": "First", "content": SECRET}, headers=alice)
stored2 = sqlite3.connect(DB).execute("SELECT content_enc FROM notes WHERE id=?", (nid,)).fetchone()[0]
check("same content re-saved gives different ciphertext", stored != stored2)
client.put(f"/api/vault/notes/{nid}", json={"title": "Renamed", "content": "new text"}, headers=alice)
check("update works", client.get(f"/api/vault/notes/{nid}", headers=alice).json["content"] == "new text")

# --- tampering and swapping -------------------------------------------------
db = sqlite3.connect(DB)
raw = bytearray(base64.b64decode(db.execute("SELECT content_enc FROM notes WHERE id=?", (nid,)).fetchone()[0]))
raw[-1] ^= 1
db.execute("UPDATE notes SET content_enc=? WHERE id=?", (base64.b64encode(bytes(raw)).decode(), nid))
db.commit()
check("tampered ciphertext fails integrity check", client.get(f"/api/vault/notes/{nid}", headers=alice).status_code == 500)

a_id = client.post("/api/vault/notes", json={"title": "A", "content": "content A"}, headers=alice).json["id"]
b_id = client.post("/api/vault/notes", json={"title": "B", "content": "content B"}, headers=alice).json["id"]
db = sqlite3.connect(DB)
enc_a = db.execute("SELECT content_enc FROM notes WHERE id=?", (a_id,)).fetchone()[0]
db.execute("UPDATE notes SET content_enc=? WHERE id=?", (enc_a, b_id))
db.commit()
check("ciphertext swapped between two notes is rejected",
      client.get(f"/api/vault/notes/{b_id}", headers=alice).status_code == 500)

events = {row[0] for row in sqlite3.connect(DB).execute("SELECT event FROM audit_log")}
check("audit log records note events", {"note_created", "note_updated", "note_integrity_failure"} <= events)

# --- delete -----------------------------------------------------------------
check("delete works", client.delete(f"/api/vault/notes/{a_id}", headers=alice).status_code == 200)
check("deleted note is gone", client.get(f"/api/vault/notes/{a_id}", headers=alice).status_code == 404)

print(f"\nAll {passed} checks passed. Step 8 is working.")
