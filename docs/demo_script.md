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
| 1:15 | Try a weak password ("administrator"), then a long normal one | "Weak and common passwords are rejected even if they're long enough. Stored passwords are Argon2 hashes." |
| 1:45 | Log in, open Account, set up MFA, scan the QR code, confirm with a code | "Second factor is a time-based code. The 8 recovery codes shown right after are a backup if I lose this phone." |
| 2:30 | Log out and log in again with a code, then once more with a recovery code | "Login now needs password and code - or, just this once, a backup code instead." |
| 3:00 | Add a note, then an image | "Both are encrypted before they touch the disk, with a key that belongs to this account alone." |
| 3:40 | Open the note, press Share, copy the link, open it in a private window | "That link works once with no login, then it's dead." |
| 4:00 | Add the test card, then press reveal and enter password and code | "The CVV is never stored. Revealing the number asks for proof again, and the number clears itself (and the clipboard) after 15 seconds." |
| 4:45 | In the second terminal run the database peek below | "This is what a thief with the database file would see." |
| 5:30 | Open Admin: logs, stats, and press "Verify audit log integrity" | "Every sensitive event is logged, and this hash chain proves nobody quietly edited it." |
| 6:00 | In Admin, disable the second account, then try logging in as it | "An admin can shut an account down immediately, no password change needed." |
| 6:30 | Run `python -m pytest -q` | "The full suite - including the new password, recovery-code, admin, audit-chain and per-user-key tests - passes." |
| 7:15 | Say the limitation | "Face login was designed but not built because our laptop camera returned a black image. We left a hook for it." |

## Database peek (shows encrypted data)

```powershell
python -c "import sqlite3,glob; f=glob.glob('*.db')[0]; c=sqlite3.connect(f); print([t[0] for t in c.execute(\"select name from sqlite_master where type='table'\")])"
```
Pick a table name from that list and show a few rows of the notes table: the content column is unreadable bytes, not text. If the column names differ, open `app/db.py` to check them before the demo.

## Attack demos (optional, pick one or two)

1. **Lockout:** enter a wrong password 5 times; the account locks and the admin log shows it. Then show the admin "Unlock" button clearing it without touching the password.
2. **Another user's data:** register a second user, then ask for the first user's note id; the server answers "not found".
3. **Old token:** log out, then reuse the old token in the API; it is rejected.
4. **Tamper with the audit log:** open the `.db` file directly and edit one `audit_log` row's `event` column, then press "Verify audit log integrity" in Admin - it names the exact row.
5. **Share link reuse:** open a note's share link twice; the second open is refused even though nothing changed server-side except that one view.

## If something goes wrong

- Page will not load: stop the server with Ctrl+C and run `python serve.py` again.
- MFA code rejected: check the phone clock is automatic; wait for a new code.
- Locked out of your demo account: delete the `*.db` file and register again.
- Show `docs/test_results.txt` as proof if the live tests are slow.

## Likely questions

- **Why AES-GCM?** It encrypts and detects tampering in one step.
- **Where are the keys?** In `.secrets/`, outside the database and Git. Each account also has its own data key, wrapped by the master key.
- **Why no keylogger?** It attacks users; our product defends them.
- **How does the audit log prove it wasn't edited?** Each row's hash includes the row before it, like a mini blockchain. Change any field in any row and every hash after it stops matching.
- **What happens to old notes when I rotate my key?** They keep working - they're tagged with the key version that encrypted them, so decryption always uses the right one.
- **What is missing?** Face login, email for reset, and HTTPS (the app sends the right header for it, but needs a reverse proxy in front to actually terminate TLS).
