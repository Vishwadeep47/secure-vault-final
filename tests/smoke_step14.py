"""Checks for Step 14 (frontend files, security headers, logout, MFA QR code).
Run from the repo root:

    python tests/smoke_step14.py

Uses a temporary database and keys, so your real data is untouched.
"""
import os
import re
import sqlite3
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
sys.path.insert(0, ROOT)

from app import create_app  # noqa: E402

tmp = tempfile.mkdtemp()
app = create_app({
    "DB_PATH": os.path.join(tmp, "test.db"),
    "SECRETS_DIR": os.path.join(tmp, "secrets"),
    "UPLOAD_DIR": os.path.join(tmp, "uploads"),
})
client = app.test_client()
PW = "a-long-test-password"
passed = 0


def check(name, condition):
    global passed
    print(("PASS  " if condition else "FAIL  ") + name)
    if not condition:
        sys.exit(1)
    passed += 1


def read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as f:
        return f.read()


# --- the page and its files ---------------------------------------------------
page = client.get("/")
html = page.get_data(as_text=True)
check("home page is served", page.status_code == 200 and 'id="app"' in html and "SecureVault" in html)

scripts = re.findall(r'<script[^>]*src="([^"]+)"', html)
styles = re.findall(r'<link[^>]*href="([^"]+\.css)"', html)
check("page loads 7 scripts and a stylesheet", len(scripts) == 7 and len(styles) == 1)
for path in scripts + styles:
    r = client.get(path)
    check(f"{path} is served", r.status_code == 200 and len(r.data) > 100)
check("scripts are served as JavaScript", "javascript" in client.get(scripts[0]).content_type)

check("path traversal out of /static is blocked",
      all(client.get(p).status_code == 404 for p in ("/static/../app/config.py", "/static/%2e%2e/app/config.py")))

# --- security headers ---------------------------------------------------------
for path in ("/", "/api/health"):
    h = client.get(path).headers
    check(f"{path}: strict content security policy",
          "script-src 'self'" in h.get("Content-Security-Policy", "") and "frame-ancestors 'none'" in h["Content-Security-Policy"])
    check(f"{path}: nosniff, no framing, no referrer",
          h.get("X-Content-Type-Options") == "nosniff" and h.get("X-Frame-Options") == "DENY"
          and h.get("Referrer-Policy") == "no-referrer")
check("API responses are never cached", client.get("/api/health").headers.get("Cache-Control") == "no-store")

# --- the frontend code itself stays safe ----------------------------------------
js_dir = os.path.join(ROOT, "static", "js")
js_files = sorted(f for f in os.listdir(js_dir) if f.endswith(".js"))
sources = {f: read("static", "js", f) for f in js_files}
banned = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localStorage"]
found = [(f, b) for f, src in sources.items() for b in banned if b in src]
check("no innerHTML, eval, or localStorage anywhere in the scripts", not found)
check("scripts never set inline styles", not any('setAttribute("style"' in s or ".style." in s for s in sources.values()))
check("page has no inline scripts, styles, or event handlers",
      not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html)
      and "<style" not in html and not re.search(r'\s(style|on[a-z]+)=', html))
check("stylesheet uses no outside resources", "http" not in read("static", "css", "app.css"))

# --- logout really ends sessions ---------------------------------------------------
client.post("/api/register", json={"username": "alice", "password": PW})
token = client.post("/api/login", json={"username": "alice", "password": PW}).json["token"]
second = client.post("/api/login", json={"username": "alice", "password": PW}).json["token"]
headers = {"Authorization": "Bearer " + token}
check("session works before logout", client.get("/api/me", headers=headers).status_code == 200)
check("logout needs a session", client.post("/api/logout").status_code == 401)
check("logout succeeds", client.post("/api/logout", headers=headers).status_code == 200)
check("the logged-out token is rejected", client.get("/api/me", headers=headers).status_code == 401)
check("a second open session is ended too",
      client.get("/api/me", headers={"Authorization": "Bearer " + second}).status_code == 401)
check("logging in again works",
      client.get("/api/me", headers={"Authorization": "Bearer " + client.post(
          "/api/login", json={"username": "alice", "password": PW}).json["token"]}).status_code == 200)
events = {r[0] for r in sqlite3.connect(app.config["DB_PATH"]).execute("SELECT event FROM audit_log")}
check("logout is audit logged", "logout" in events)

# --- MFA setup returns a QR code ------------------------------------------------------
fresh = {"Authorization": "Bearer " + client.post(
    "/api/login", json={"username": "alice", "password": PW}).json["token"]}
setup = client.post("/api/mfa/setup", headers=fresh).json
check("MFA setup returns a QR code (SVG) next to the secret",
      "<svg" in setup["qr_svg"] and setup["secret"] and setup["otpauth_uri"].startswith("otpauth://totp/"))
check("QR code does not load anything from outside", "http://www.w3.org" in setup["qr_svg"] and "<image" not in setup["qr_svg"]
      and "<script" not in setup["qr_svg"])

print(f"\nAll {passed} checks passed. Step 14 backend is working.")
