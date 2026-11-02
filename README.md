## Project status (replace the old status table in README.md with this)

| Area | Status |
|---|---|
| Password hashing (Argon2), lockout | Done |
| TOTP multi-factor authentication | Done |
| JWT sessions with revocation | Done |
| Encrypted image vault | Done |
| Encrypted card vault (test cards only) | Done |
| Offline encryption FAQ chat | Done |
| User-to-user encrypted messaging (AES-256-GCM) | Done |
| Admin logs, users, statistics | Done |
| Password reset and change | Done (token printed to console, no email) |
| Frontend | Done |
| Security tests | 187 passed, 2 skipped |
| Hardening | Done, see `docs/hardening.md` |
| Face authentication | **Not built**: design and setup script only |

Running on : vault.vishwadeep.in

## Run it

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install -r requirements-dev.txt
python serve.py          # then open http://127.0.0.1:5000
python -m pytest -q      # run all tests
python scripts/hardening_check.py
```

## Documents

- `docs/report.md` project report
- `docs/threat_model.md` threats, defences and tests
- `docs/architecture.md` diagrams
- `docs/demo_script.md` demo steps
- `docs/hardening.md` hardening table
- `docs/test_results.txt` full test output

## Team

| Name | Roll no. | Members |
|---|---|---|
| Vishwadeep Choudhary | 107 | Leader |
| Aman Kumar Mishra | 141 | Member |
| Raja Babu | 151 | Member |
| Rajesh Kumar Mahato | 152 | Member |
