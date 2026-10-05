#!/usr/bin/env python
"""Look through the WHOLE Git history for things that must never be committed.

    python scripts/scan_git_history.py

Why history matters: deleting a file in a later commit does not remove it from Git.
Anyone who clones the repository can still read the old version.

It looks for:
  1. Files that should never be tracked (.secrets/, *.db, uploads/, .env, keys, models)
  2. Private keys and hard-coded secrets in code that was ever committed
  3. Your REAL key values (from .secrets/) appearing anywhere in the history

Exit code 0 = clean, 1 = something found. It prints names and commit ids, never the secrets.
"""
import base64
import os
import re
import subprocess
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))

FORBIDDEN_PATHS = re.compile(
    r"(^|/)(\.secrets/|uploads/|\.env$)|\.db$|\.pem$|\.key$|\.onnx$|(^|/)downloaded\.", re.IGNORECASE)

CONTENT_PATTERNS = {
    "a private key": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "an AWS access key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "a hard-coded secret": re.compile(
        r"(?i)(jwt_secret|secret_key|aes_key|api_key|private_key)\s*=\s*[\"'][^\"']{8,}[\"']"),
}
SKIP_CONTENT_IN = ("tests/", "docs/")  # sample values in tests and docs are fine


def _git(repo, *args):
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout


def scan(repo=ROOT):
    """Return a list of findings (empty = clean), or None if this is not a Git repository."""
    if not os.path.isdir(os.path.join(repo, ".git")):
        return None
    try:
        _git(repo, "--version")
    except (OSError, RuntimeError):
        return None

    findings = []

    # 1. forbidden files, ever committed on any branch
    try:
        names = _git(repo, "log", "--all", "--name-only", "--pretty=format:")
    except RuntimeError:  # a repository with no commits yet
        return findings
    for path in sorted({line.strip() for line in names.splitlines() if line.strip()}):
        if FORBIDDEN_PATHS.search(path):
            findings.append(f"File that should never be committed was in the history: {path}")

    # 2. secrets inside code that was committed (only lines that were ever added)
    patch = _git(repo, "log", "--all", "-p", "--no-color", "--no-ext-diff", "--pretty=format:commit %h")
    commit, current = "", ""
    seen = set()
    for line in patch.splitlines():
        if line.startswith("commit "):
            commit = line[7:]
        elif line.startswith("+++ b/"):
            current = line[6:]
        elif line.startswith("+") and not line.startswith("+++") and not current.startswith(SKIP_CONTENT_IN):
            for label, pattern in CONTENT_PATTERNS.items():
                if pattern.search(line) and (current, label) not in seen:
                    seen.add((current, label))
                    findings.append(f"Looks like {label} in {current} (commit {commit})")

    # 3. the real key values
    secrets_dir = os.path.join(repo, ".secrets")
    if os.path.isdir(secrets_dir):
        for name in sorted(os.listdir(secrets_dir)):
            with open(os.path.join(secrets_dir, name), "rb") as f:
                key = f.read()
            for needle in (base64.b64encode(key).decode(), key.hex()):
                hits = _git(repo, "log", "--all", f"-S{needle}", "--pretty=format:%h").split()
                if hits:
                    findings.append(f"Your real key '{name}' appears in commit(s): {', '.join(hits)}")
                    break
    return findings


def main():
    findings = scan()
    if findings is None:
        print("Not a Git repository (or Git is not installed): nothing to scan.")
        return 0
    if not findings:
        print("Clean: no secrets or forbidden files found in the Git history.")
        return 0
    print(f"FOUND {len(findings)} problem(s) in the Git history:")
    for finding in findings:
        print("  - " + finding)
    print("\nWhat to do:")
    print("  1. Treat any exposed key or password as stolen. Create new ones (delete .secrets/ files")
    print("     to generate fresh keys; existing encrypted data then becomes unreadable, which is")
    print("     acceptable for a demo database but not for real data).")
    print("  2. Remove the file from history (git filter-repo) or, for a student project, create a")
    print("     fresh repository from the current files.")
    print("  3. Force-pushing alone does not erase copies others already cloned.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
