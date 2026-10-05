# SecureVault: Demo Script (about 8 minutes)

## Before you start (do this 10 minutes early)

```powershell
cd C:\dev\secure-vault-final
.\venv\Scripts\Activate.ps1
python -m pytest -q
Remove-Item -Force *.db -ErrorAction SilentlyContinue   # fresh demo database
python serve.py
```
Open `http://127.0.0.1:5000`. Keep a second terminal open in the same folder. Have an authenticator app ready on your phone. Use only test card numbers (4242 4242 4242 4242).

## Script

| Time | Do | Say |
|---|---|---|
| 0:00 | Show the title and the one-line goal | "SecureVault is an encrypted vault with layered login. It combines our internship security tasks into one product." |
| 0:45 | Register the first user | "The first account becomes admin automatically." |
| 1:15 | Try a weak password | "Weak passwords are rejected. Stored passwords are Argon2 hashes." |
| 1:45 | Log in, open Account, set up MFA, scan the QR code, confirm with a code | "Second factor is a time-based code." |
| 2:30 | Log out and log in again with a code | "Login now needs password and code." |
| 3:00 | Add a note, then an image | "Both are encrypted before they touch the disk." |
| 4:00 | Add the test card, then press reveal and enter password and code | "The CVV is never stored. Revealing the number asks for proof again." |
| 5:00 | In the second terminal run the database peek below | "This is what a thief with the database file would see." |
| 6:00 | Open Admin: logs and stats | "Every sensitive event is logged for the admin." |
| 6:45 | Run `python -m pytest -q` | "119 tests check the threats in our threat model." |
| 7:30 | Say the limitation | "Face login was designed but not built because our laptop camera returned a black image. We left a hook for it." |

## Database peek (shows encrypted data)

```powershell
python -c "import sqlite3,glob; f=glob.glob('*.db')[0]; c=sqlite3.connect(f); print([t[0] for t in c.execute(\"select name from sqlite_master where type='table'\")])"
```
Pick a table name from that list and show a few rows of the notes table: the content column is unreadable bytes, not text. If the column names differ, open `app/db.py` to check them before the demo.

## Attack demos (optional, pick one or two)

1. **Lockout:** enter a wrong password 5 times; the account locks and the admin log shows it.
2. **Another user's data:** register a second user, then ask for the first user's note id; the server answers "not found".
3. **Old token:** log out, then reuse the old token in the API; it is rejected.

## If something goes wrong

- Page will not load: stop the server with Ctrl+C and run `python serve.py` again.
- MFA code rejected: check the phone clock is automatic; wait for a new code.
- Locked out of your demo account: delete the `*.db` file and register again.
- Show `docs/test_results.txt` as proof if the live tests are slow.

## Likely questions

- **Why AES-GCM?** It encrypts and detects tampering in one step.
- **Where are the keys?** In `.secrets/`, outside the database and Git.
- **Why no keylogger?** It attacks users; our product defends them.
- **What is missing?** Face login, email for reset, HTTPS and key rotation.
