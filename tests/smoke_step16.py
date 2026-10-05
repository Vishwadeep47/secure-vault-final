"""Checks for Step 16 (admin routes). Run from the repo root:

    python tests/smoke_step16.py

Uses a temporary database and keys, so your real data is untouched.
"""
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
    "UPLOAD_DIR": os.path.join(tmp, "uploads"),
})
client = app.test_client()
DB = app.config["DB_PATH"]
PW = "a-long-test-password"
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


admin = make_user("alice")  # first account = admin
bob = make_user("bob")
carol = make_user("carol")
for title in ("one", "two"):
    client.post("/api/vault/notes", json={"title": title, "content": "text"}, headers=bob)

# --- access control -----------------------------------------------------------
for path in ("logs", "users", "stats"):
    check(f"/api/admin/{path}: no token is 401", client.get(f"/api/admin/{path}").status_code == 401)
    check(f"/api/admin/{path}: normal user is 403", client.get(f"/api/admin/{path}", headers=bob).status_code == 403)

# --- audit log ------------------------------------------------------------------
r = client.get("/api/admin/logs", headers=admin)
check("admin can read the audit log", r.status_code == 200 and len(r.json["logs"]) > 0)
ids = [row["id"] for row in r.json["logs"]]
check("newest entries come first", ids == sorted(ids, reverse=True))
check("blocked admin attempt was logged",
      any(row["event"] == "forbidden_access" and row["username"] == "bob" for row in r.json["logs"]))

check("limit works", len(client.get("/api/admin/logs?limit=2", headers=admin).json["logs"]) == 2)
big = client.get("/api/admin/logs?limit=100000", headers=admin).json
check("oversized limit is capped at 200", big["limit"] == 200)
check("limit=abc is rejected", client.get("/api/admin/logs?limit=abc", headers=admin).status_code == 400)
check("limit=0 is rejected", client.get("/api/admin/logs?limit=0", headers=admin).status_code == 400)
check("negative offset is rejected", client.get("/api/admin/logs?offset=-1", headers=admin).status_code == 400)

by_event = client.get("/api/admin/logs?event=forbidden_access", headers=admin).json
check("filter by event", by_event["total"] >= 1 and all(x["event"] == "forbidden_access" for x in by_event["logs"]))
by_user = client.get("/api/admin/logs?username=bob", headers=admin).json
check("filter by username", by_user["total"] >= 1 and all(x["username"] == "bob" for x in by_user["logs"]))

inject = client.get("/api/admin/logs?username=%27%20OR%201%3D1%20--", headers=admin)
check("SQL injection attempt in filter finds nothing and breaks nothing",
      inject.status_code == 200 and inject.json["total"] == 0)

page1 = client.get("/api/admin/logs?limit=3&offset=0", headers=admin).json
page2 = client.get("/api/admin/logs?limit=3&offset=3", headers=admin).json
check("pagination pages do not overlap",
      not ({x["id"] for x in page1["logs"]} & {x["id"] for x in page2["logs"]}) and page1["total"] == page2["total"])

# --- users ----------------------------------------------------------------------
r = client.get("/api/admin/users", headers=admin)
users = {u["username"]: u for u in r.json["users"]}
check("user list shows all three users", set(users) == {"alice", "bob", "carol"})
check("roles are correct", users["alice"]["role"] == "admin" and users["bob"]["role"] == "user")
check("item counts are shown", users["bob"]["notes_count"] == 2 and users["carol"]["notes_count"] == 0)
text = r.get_data(as_text=True)
check("no password hashes or MFA secrets in the user list",
      "$argon2" not in text and "password_hash" not in text and "mfa_secret" not in text)

# --- stats ----------------------------------------------------------------------
s = client.get("/api/admin/stats", headers=admin).json
check("stats counts are correct",
      s["users"] == 3 and s["admins"] == 1 and s["notes"] == 2 and s["images"] == 0 and s["cards"] == 0
      and s["mfa_enabled_users"] == 0)
check("stats include recent events", s["events_last_24h"].get("register") == 3)

# --- role comes from the database, not the token ----------------------------------
con = sqlite3.connect(DB)
con.execute("UPDATE users SET role='admin' WHERE username='bob'")
con.commit()
check("promoting a user takes effect immediately", client.get("/api/admin/users", headers=bob).status_code == 200)
con.execute("UPDATE users SET role='user' WHERE username='bob'")
con.commit()
check("demoting a user takes effect immediately", client.get("/api/admin/users", headers=bob).status_code == 403)

print(f"\nAll {passed} checks passed. Step 16 is working.")
