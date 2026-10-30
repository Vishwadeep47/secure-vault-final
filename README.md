# SecureVault

A small web app for keeping private notes, images and test payment cards in one encrypted place. Logging in takes a password and a code from an authenticator app, and everything stored is encrypted before it reaches the database.

We built it for our cybersecurity minor project, using the tasks from the Slash Mark internship (text encryption, image encryption, card encryption and user authentication) as the starting point.

## What it does

- Sign up and log in with an Argon2-hashed password plus a TOTP code (Google Authenticator and similar apps)
- Sessions last 15 minutes, and logging out or changing the password ends all older sessions straight away
- Encrypted notes, images and test cards (AES-256-GCM), with the key kept outside the database and outside Git
- Revealing a full card number asks for the password and a fresh code again; the CVV is never stored
- Password reset (the token is printed in the server console, there is no email yet)
- Admin page with the audit log, user list and some counts. The first account to sign up becomes the admin

## Run it

You need Python 3.13. On Windows with PowerShell:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python serve.py
```

Then open http://127.0.0.1:5000. The first run creates a `.secrets` folder with the keys, so don't commit it (it is already in `.gitignore`).

Use only test card numbers such as 4242 4242 4242 4242.

## Tests

```powershell
python -m pytest -q                  # 119 passed, 1 skipped
python scripts/hardening_check.py    # settings checklist
python scripts/scan_git_history.py   # looks for keys or .db files in Git history
```

The one skipped test is for face login, which is not built (see below).

## What is not finished

- **Face authentication.** We designed it with OpenCV (YuNet and SFace) and wrote a setup check script, but the laptop camera we tested with returned a black image, so we never built enrollment and login. The login code has a marked hook where it would go.
- Rate limits and lockouts are kept in memory, so they reset when the server restarts.
- Password reset has no email.
- SQLite and a local key folder are fine for a demo, not for a real deployment.

## Folders

| Folder | What is in it |
|---|---|
| `app/` | the Flask app: `auth/`, `vault/`, `admin/`, `crypto/`, `security/` |
| `static/`, `templates/` | the front end (plain HTML, CSS and JavaScript) |
| `tests/` | threat-model tests, hardening tests and smoke scripts |
| `scripts/` | hardening check, Git history scanner, face setup check |
| `docs/` | report, threat model, architecture, hardening notes, demo script |

## Team

| Name | Roll no. | Role |
|---|---|---|
| Vishwadeep Choudhary | 107 | Leader |
| Aman Kumar Mishra | 141 | Member |
| Raja Babu | 151 | Member |
| Rajesh Kumar Mahato | 152 | Member |
