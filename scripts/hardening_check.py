#!/usr/bin/env python
"""Step 18 hardening checklist: checks the project's security settings in one go.

    python scripts/hardening_check.py            # fast checks
    python scripts/hardening_check.py --audit    # also look for known-vulnerable libraries (needs internet)

PASS = fine, WARN = worth a look, FAIL = fix before the demo. Exit code 1 if anything fails.
Nothing here changes your files or your data.
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scripts import scan_git_history  # noqa: E402

PASS, WARN, FAIL = "PASS", "WARN", "FAIL"
REQUIRED_GITIGNORE = [".secrets/", "*.db", "uploads/", "venv/", ".env"]


def _py_files():
    for folder in ("app",):
        for current, dirs, files in os.walk(os.path.join(ROOT, folder)):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                if name.endswith(".py"):
                    yield os.path.join(current, name)
    for name in ("run.py", "serve.py"):
        path = os.path.join(ROOT, name)
        if os.path.exists(path):
            yield path


def check_debug_off(out):
    bad = []
    for path in _py_files():
        text = open(path, encoding="utf-8").read()
        if re.search(r"debug\s*=\s*True|\bDEBUG\s*=\s*True|FLASK_DEBUG\s*=\s*1", text):
            bad.append(os.path.relpath(path, ROOT))
    out.append((FAIL, "Debug mode is off", f"debug is switched on in: {bad}") if bad
               else (PASS, "Debug mode is off", "no debug=True anywhere"))


def check_gitignore(out):
    path = os.path.join(ROOT, ".gitignore")
    if not os.path.exists(path):
        out.append((FAIL, ".gitignore protects secrets and data", "there is no .gitignore"))
        return
    lines = {l.strip() for l in open(path, encoding="utf-8") if l.strip() and not l.startswith("#")}
    missing = [p for p in REQUIRED_GITIGNORE if p not in lines]
    out.append((FAIL, ".gitignore protects secrets and data", f"add these lines: {missing}") if missing
               else (PASS, ".gitignore protects secrets and data", ", ".join(REQUIRED_GITIGNORE)))


def check_keys(out):
    folder = os.path.join(ROOT, ".secrets")
    if not os.path.isdir(folder):
        out.append((WARN, "Encryption keys exist and are 256-bit", "no .secrets folder yet (start the server once)"))
        return
    names = ["jwt_secret", "vault_key"]
    problems = [n for n in names if not os.path.exists(os.path.join(folder, n))
                or os.path.getsize(os.path.join(folder, n)) != 32]
    if problems:
        out.append((FAIL, "Encryption keys exist and are 256-bit", f"missing or wrong size: {problems}"))
        return
    out.append((PASS, "Encryption keys exist and are 256-bit", "jwt_secret and vault_key are 32 bytes each"))
    if os.name != "nt":
        loose = [n for n in names if os.stat(os.path.join(folder, n)).st_mode & 0o077]
        out.append((WARN, "Key files readable only by you", f"other users can read: {loose}") if loose
                   else (PASS, "Key files readable only by you", "permissions are 600"))


def check_config(out):
    from app.config import Config as C

    rules = [
        ("MIN_PASSWORD_LEN", C.MIN_PASSWORD_LEN >= 10, ">= 10"),
        ("TOKEN_MINUTES", C.TOKEN_MINUTES <= 30, "<= 30"),
        ("MAX_FAILED_LOGINS", C.MAX_FAILED_LOGINS <= 10, "<= 10"),
        ("LOCKOUT_SECONDS", C.LOCKOUT_SECONDS >= 60, ">= 60"),
        ("RESET_TOKEN_MINUTES", C.RESET_TOKEN_MINUTES <= 30, "<= 30"),
        ("MAX_CONTENT_LENGTH", C.MAX_CONTENT_LENGTH <= 20 * 1024 * 1024, "<= 20 MB"),
        ("JSON_MAX_BYTES", C.JSON_MAX_BYTES <= 1024 * 1024, "<= 1 MB"),
        ("REGISTER_PER_WINDOW", C.REGISTER_PER_WINDOW <= 100, "<= 100 per hour"),
    ]
    bad = [f"{n} (want {w})" for n, ok, w in rules if not ok]
    out.append((FAIL, "Limits in config.py are sensible", "; ".join(bad)) if bad
               else (PASS, "Limits in config.py are sensible", f"{len(rules)} settings checked"))


def check_password_hashing(out):
    from app.auth import passwords

    hasher = passwords._hasher
    params = getattr(hasher, "_parameters", hasher)
    time_cost = getattr(params, "time_cost", None)
    memory_kib = getattr(params, "memory_cost", None)
    if time_cost is None or memory_kib is None:
        out.append((WARN, "Argon2 password hashing is strong", "could not read the settings"))
    elif memory_kib >= 19456 and time_cost >= 2:  # OWASP minimum for Argon2id
        out.append((PASS, "Argon2 password hashing is strong", f"{memory_kib // 1024} MiB memory, {time_cost} passes"))
    else:
        out.append((FAIL, "Argon2 password hashing is strong", f"{memory_kib} KiB / {time_cost} passes is below the OWASP minimum"))


def check_headers(out):
    from app import create_app

    tmp = tempfile.mkdtemp()
    try:
        app = create_app({"DB_PATH": os.path.join(tmp, "t.db"), "SECRETS_DIR": os.path.join(tmp, "s"),
                          "UPLOAD_DIR": os.path.join(tmp, "u")})
        client = app.test_client()
        page, api = client.get("/"), client.get("/api/health")
        wanted = {"Content-Security-Policy": "script-src 'self'", "X-Content-Type-Options": "nosniff",
                  "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
                  "Cross-Origin-Opener-Policy": "same-origin", "Permissions-Policy": "camera"}
        missing = [h for h, part in wanted.items() if part not in page.headers.get(h, "")]
        if api.headers.get("Cache-Control") != "no-store":
            missing.append("Cache-Control on /api")
        https = client.get("/api/health", base_url="https://localhost")
        if "Strict-Transport-Security" not in https.headers:
            missing.append("Strict-Transport-Security over HTTPS")
        out.append((FAIL, "Browser security headers are set", f"missing: {missing}") if missing
                   else (PASS, "Browser security headers are set", "CSP, nosniff, no framing, HSTS over HTTPS, no-store"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def check_server(out):
    try:
        import waitress  # noqa: F401
        out.append((PASS, "Production server available", "Waitress is installed: use python serve.py"))
    except ImportError:
        out.append((WARN, "Production server available", "Waitress missing: python -m pip install -r requirements.txt"))


def check_git(out):
    if not os.path.isdir(os.path.join(ROOT, ".git")):
        out.append((WARN, "Git checks", "this folder is not a Git repository"))
        return
    try:
        tracked = subprocess.run(["git", "ls-files"], cwd=ROOT, capture_output=True, text=True,
                                 encoding="utf-8", errors="replace").stdout.splitlines()
    except OSError:
        out.append((WARN, "Git checks", "Git is not installed"))
        return
    bad = [p for p in tracked if scan_git_history.FORBIDDEN_PATHS.search(p)]
    out.append((FAIL, "No secret or data files are tracked by Git", f"tracked now: {bad}") if bad
               else (PASS, "No secret or data files are tracked by Git", f"{len(tracked)} tracked files checked"))
    findings = scan_git_history.scan(ROOT)
    if findings is None:
        out.append((WARN, "Git history is clean", "could not scan the history"))
    elif findings:
        out.append((FAIL, "Git history is clean", f"{len(findings)} problem(s): run python scripts/scan_git_history.py"))
    else:
        out.append((PASS, "Git history is clean", "no secrets or forbidden files in any commit"))


def check_dependencies(out):
    if shutil.which("pip-audit") is None:
        out.append((WARN, "Libraries have no known vulnerabilities", "pip-audit not installed: python -m pip install pip-audit"))
        return
    try:
        result = subprocess.run(["pip-audit", "-r", os.path.join(ROOT, "requirements.txt")],
                                capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        out.append((WARN, "Libraries have no known vulnerabilities", "pip-audit timed out"))
        return
    text = (result.stdout + result.stderr).strip()
    if result.returncode == 0:
        out.append((PASS, "Libraries have no known vulnerabilities", "pip-audit found none"))
    elif "Found" in text and "vulnerab" in text:
        out.append((FAIL, "Libraries have no known vulnerabilities", "run: pip-audit -r requirements.txt  (then upgrade the listed libraries)"))
    else:
        out.append((WARN, "Libraries have no known vulnerabilities", "pip-audit could not finish (internet?): " + text[-120:].replace("\n", " ")))


def run_checks(audit=False):
    results = []
    for check in (check_debug_off, check_gitignore, check_keys, check_config, check_password_hashing,
                  check_headers, check_server, check_git):
        check(results)
    if audit:
        check_dependencies(results)
    return results


def main():
    parser = argparse.ArgumentParser(description="SecureVault hardening checklist")
    parser.add_argument("--audit", action="store_true", help="also check libraries for known vulnerabilities (internet needed)")
    args = parser.parse_args()
    results = run_checks(audit=args.audit)
    for status, name, detail in results:
        print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))
    counts = {s: sum(1 for r in results if r[0] == s) for s in (PASS, WARN, FAIL)}
    print(f"\n{counts[PASS]} passed, {counts[WARN]} warning(s), {counts[FAIL]} failed")
    if not args.audit:
        print("Tip: run with --audit to check your libraries for known vulnerabilities.")
    return 1 if counts[FAIL] else 0


if __name__ == "__main__":
    sys.exit(main())
