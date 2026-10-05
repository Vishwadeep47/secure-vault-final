"""Tests for Step 18: abuse limits, safe errors, extra headers, production server, Git scans.

    python -m pytest tests/test_hardening.py -v
"""
import base64
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

from app.security import ratelimit
from tests.helpers import PASSWORD, db
from tests.test_threat_model import audit_events, login

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


# ------------------------------------------------------------ H1 sign-up flooding
def test_H1_signups_are_limited_per_address(app, client):
    app.config["REGISTER_PER_WINDOW"] = 3
    codes = [client.post("/api/register", json={"username": f"user{i}", "password": PASSWORD}).status_code for i in range(5)]
    assert codes == [201, 201, 201, 429, 429]
    assert "register_rate_limited" in audit_events(app)


def test_H1_invalid_signup_attempts_count_too(app, client):
    app.config["REGISTER_PER_WINDOW"] = 2
    client.post("/api/register", json={"username": "x", "password": "short"})
    client.post("/api/register", json={"username": "y", "password": "short"})
    assert client.post("/api/register", json={"username": "okname", "password": PASSWORD}).status_code == 429


# ----------------------------------------------- H2 one address trying many usernames
def test_H2_logins_are_limited_per_address_across_all_usernames(app, client, alice):
    app.config["LOGIN_PER_IP"] = 5
    ratelimit.clear_all()
    codes = [login(client, f"guess{i}", "wrong-password-xx").status_code for i in range(7)]
    assert codes == [401] * 5 + [429] * 2
    assert "login_ip_limited" in audit_events(app)


def test_H2_the_address_limit_also_blocks_the_right_password(app, client, alice):
    app.config["LOGIN_PER_IP"] = 3
    ratelimit.clear_all()
    for i in range(3):
        login(client, f"guess{i}", "wrong-password-xx")
    assert login(client, "alice", PASSWORD).status_code == 429


# --------------------------------------------------- H3 memory cannot be flooded
def test_H3_failed_login_tracking_stays_bounded(monkeypatch):
    monkeypatch.setattr(ratelimit, "MAX_TRACKED", 100)
    for i in range(1000):
        ratelimit.register_failure(f"random-name-{i}")
    assert len(ratelimit._failures) <= 100


def test_H3_request_counters_stay_bounded(monkeypatch):
    monkeypatch.setattr(ratelimit, "MAX_TRACKED", 100)
    for i in range(1000):
        ratelimit.too_many_requests(f"key-{i}", 5, 60)
    assert len(ratelimit._hits) <= 100


def test_H3_trimming_drops_the_oldest_entries_first(monkeypatch):
    monkeypatch.setattr(ratelimit, "MAX_TRACKED", 10)
    for i in range(30):
        ratelimit.register_failure(f"name-{i}")
        time.sleep(0.001)
    assert "name-29" in ratelimit._failures and "name-0" not in ratelimit._failures


# ----------------------------------------------------------- H4 body size limits
def test_H4_huge_json_bodies_are_refused_early(client, alice):
    huge = {"title": "t", "content": "a" * 300_000}
    r = client.post("/api/vault/notes", json=huge, headers=alice)
    assert r.status_code == 413 and r.json == {"error": "Request body too large"}


def test_H4_huge_json_is_refused_on_login_too(client):
    r = client.post("/api/login", json={"username": "a", "password": "b" * 500_000})
    assert r.status_code == 413


def test_H4_the_largest_allowed_note_still_works(client, alice):
    r = client.post("/api/vault/notes", json={"title": "big", "content": "é" * 20000}, headers=alice)
    assert r.status_code == 201


# ----------------------------------------------------------- H5 safe error pages
def test_H5_unknown_api_address_gives_plain_json(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and r.json == {"error": "Not Found"}


def test_H5_wrong_method_gives_plain_json(client):
    r = client.delete("/api/health")
    assert r.status_code == 405 and r.content_type.startswith("application/json")


def test_H5_unexpected_crash_leaks_no_details(app, client, alice, monkeypatch):
    from app.vault import notes

    def explode():
        raise RuntimeError("secret internal detail: /home/user/app.py line 42")

    monkeypatch.setattr(notes, "_now", explode)
    r = client.post("/api/vault/notes", json={"title": "t", "content": "c"}, headers=alice)
    text = r.get_data(as_text=True)
    assert r.status_code == 500 and r.json == {"error": "Internal server error"}
    assert "secret internal detail" not in text and "Traceback" not in text and "RuntimeError" not in text


def test_H5_malformed_json_is_a_clean_400(client, alice):
    r = client.post("/api/vault/notes", data="{not json", content_type="application/json", headers=alice)
    assert r.status_code == 400 and "Traceback" not in r.get_data(as_text=True)


# ------------------------------------------------------ H6 headers and cross-site use
def test_H6_extra_browser_protections_are_set(client):
    h = client.get("/").headers
    assert "camera=(self)" in h["Permissions-Policy"] and "microphone=()" in h["Permissions-Policy"]
    assert h["Cross-Origin-Opener-Policy"] == "same-origin"
    assert h["Cross-Origin-Resource-Policy"] == "same-origin"


def test_H6_strict_transport_security_only_over_https(client):
    assert "Strict-Transport-Security" not in client.get("/api/health").headers
    secure = client.get("/api/health", base_url="https://localhost")
    assert "max-age=31536000" in secure.headers["Strict-Transport-Security"]


def test_H6_other_websites_are_not_allowed_to_call_the_api(client, alice):
    evil = {"Origin": "https://evil.example"}
    assert "Access-Control-Allow-Origin" not in client.get("/api/health", headers=evil).headers
    preflight = client.options("/api/vault/notes", headers={**evil, "Access-Control-Request-Method": "POST"})
    assert "Access-Control-Allow-Origin" not in preflight.headers


# ------------------------------------------------------ H7 production server (Waitress)
def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture()
def live_server(tmp_path):
    pytest.importorskip("waitress")
    port = _free_port()
    env = dict(os.environ, VAULT_PORT=str(port), VAULT_DB=str(tmp_path / "live.db"),
               VAULT_SECRETS_DIR=str(tmp_path / "secrets"), VAULT_UPLOAD_DIR=str(tmp_path / "uploads"))
    proc = subprocess.Popen([sys.executable, os.path.join(ROOT, "serve.py")], cwd=ROOT, env=env,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"
    try:
        for _ in range(100):
            try:
                urllib.request.urlopen(base + "/api/health", timeout=1).read()
                break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("serve.py did not start")
        yield base
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def test_H7_waitress_serves_the_app_and_hides_its_version(live_server):
    response = urllib.request.urlopen(live_server + "/api/health")
    assert response.status == 200
    assert response.headers["Server"] == "SecureVault"  # no software name or version
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]


def test_H7_waitress_refuses_oversized_requests(live_server):
    request = urllib.request.Request(live_server + "/api/login", data=b"x" * (12 * 1024 * 1024),
                                     headers={"Content-Type": "application/octet-stream"}, method="POST")
    with pytest.raises((urllib.error.HTTPError, urllib.error.URLError, ConnectionError, OSError)):
        urllib.request.urlopen(request, timeout=20)


# ------------------------------------------------------ H8 Git history scanner
git_missing = shutil.which("git") is None


def _git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd=repo, check=True,
                   capture_output=True)


@pytest.fixture()
def repo(tmp_path):
    if git_missing:
        pytest.skip("git is not installed")
    _git(tmp_path, "init", "-q")
    return tmp_path


def _commit(repo, files, message="c"):
    for rel, text in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    _git(repo, "add", "-A", "-f")
    _git(repo, "commit", "-q", "-m", message)


def test_H8_scanner_passes_a_clean_repository(repo):
    from scripts import scan_git_history

    _commit(repo, {"app.py": "print('hello')\n", "README.md": "hi\n"})
    assert scan_git_history.scan(str(repo)) == []


def test_H8_scanner_finds_a_secret_file_even_after_it_was_deleted(repo):
    from scripts import scan_git_history

    _commit(repo, {".secrets/vault_key": "abc"})
    _git(repo, "rm", "-q", "-r", ".secrets")
    _git(repo, "commit", "-q", "-m", "removed it")
    findings = scan_git_history.scan(str(repo))
    assert any(".secrets/vault_key" in f for f in findings)


def test_H8_scanner_finds_database_files_and_uploads(repo):
    from scripts import scan_git_history

    _commit(repo, {"securevault.db": "x", "uploads/a.bin": "y"})
    text = " ".join(scan_git_history.scan(str(repo)))
    assert "securevault.db" in text and "uploads/a.bin" in text


def test_H8_scanner_finds_hard_coded_secrets_in_code(repo):
    from scripts import scan_git_history

    _commit(repo, {"app/config.py": 'JWT_SECRET = "hunter2hunter2hunter2"\n'})
    findings = scan_git_history.scan(str(repo))
    assert any("hard-coded secret" in f and "app/config.py" in f for f in findings)
    assert not any("hunter2" in f for f in findings)  # the report never prints the secret


def test_H8_scanner_ignores_sample_values_in_tests(repo):
    from scripts import scan_git_history

    _commit(repo, {"tests/test_x.py": 'JWT_SECRET = "sample-value-for-tests"\n'})
    assert scan_git_history.scan(str(repo)) == []


def test_H8_scanner_finds_your_real_key_value_in_history(repo):
    from scripts import scan_git_history

    key = os.urandom(32)
    secrets_dir = repo / ".secrets"
    secrets_dir.mkdir()
    (secrets_dir / "vault_key").write_bytes(key)
    _commit(repo, {"docs/notes.md": "oops " + base64.b64encode(key).decode()})
    findings = scan_git_history.scan(str(repo))
    assert any("real key 'vault_key'" in f for f in findings)


def test_H8_scanner_says_nothing_to_scan_outside_git(tmp_path):
    from scripts import scan_git_history

    assert scan_git_history.scan(str(tmp_path)) is None


# ------------------------------------------------------ H9 the whole checklist
def test_H9_hardening_checklist_has_no_failures(monkeypatch):
    from app.auth import passwords
    from scripts import hardening_check
    from tests.conftest import PRODUCTION_HASHER

    # The other tests use a cheap hasher for speed; the checklist must judge the real one.
    monkeypatch.setattr(passwords, "_hasher", PRODUCTION_HASHER)
    results = hardening_check.run_checks()
    failures = [r for r in results if r[0] == "FAIL"]
    assert not failures, failures


def test_H9_checklist_catches_debug_mode(tmp_path, monkeypatch):
    from scripts import hardening_check

    fake = tmp_path / "app"
    fake.mkdir()
    (fake / "x.py").write_text("app.run(debug=True)\n")
    monkeypatch.setattr(hardening_check, "ROOT", str(tmp_path))
    out = []
    hardening_check.check_debug_off(out)
    assert out[0][0] == "FAIL"
