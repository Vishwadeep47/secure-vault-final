# SecureVault

> **Protecting data end to end, from who you are to how it's stored.**

SecureVault is a web application where a user proves their identity through **layered authentication** (password, one-time code, and face check) and then stores sensitive data (**text notes, images, and payment card details**) in a vault where everything is **encrypted before it touches the database**. If the database is stolen, the attacker gets unreadable ciphertext, not your data.

This is our **minor project** (final-year, cybersecurity track). It combines and extends six security tasks built during a summer internship into one structured, tested, documented product.

---

## Table of Contents

1. [Project Status](#1-project-status)
2. [The Problem We Are Solving](#2-the-problem-we-are-solving)
3. [Goals and Non-Goals](#3-goals-and-non-goals)
4. [Features](#4-features)
5. [How the Six Internship Tasks Map to This Project](#5-how-the-six-internship-tasks-map-to-this-project)
6. [System Architecture](#6-system-architecture)
7. [Security Design (How Each Protection Works)](#7-security-design-how-each-protection-works)
8. [Tech Stack](#8-tech-stack)
9. [Database Design](#9-database-design)
10. [API Reference](#10-api-reference)
11. [Project Folder Structure](#11-project-folder-structure)
12. [Setup and Installation (Windows)](#12-setup-and-installation-windows)
13. [Quick Test of the Running Backend](#13-quick-test-of-the-running-backend)
14. [Threat Model](#14-threat-model)
15. [Testing Plan](#15-testing-plan)
16. [Development Roadmap](#16-development-roadmap)
17. [Team Roles](#17-team-roles)
18. [Demo Script (For Evaluation Day)](#18-demo-script-for-evaluation-day)
19. [Related Work](#19-related-work)
20. [Limitations (Be Honest in the Viva)](#20-limitations-be-honest-in-the-viva)
21. [Ethics, Legal, and Academic Integrity](#21-ethics-legal-and-academic-integrity)
22. [Future Scope](#22-future-scope)
23. [Glossary](#23-glossary)
24. [References](#24-references)

---

## 1. Project Status

| Area | Status |
|---|---|
| Backend skeleton (Flask + SQLite) | Done (single `app.py`, tested) |
| Registration, login, Argon2 password hashing | Done |
| JWT sessions (15 min expiry) | Done |
| TOTP multi-factor authentication | Done |
| Role-based access (user / admin) | Done |
| Brute-force lockout (5 failed attempts, 5 min) | Done |
| Audit log + admin log viewer | Done |
| Encrypted notes (AES-256-GCM) | Done |
| Encrypted image vault | Planned |
| Credit card tokenization and encryption | Planned |
| Face authentication with liveness hint | Planned |
| Password reset flow | Planned |
| Frontend (web UI, mobile-friendly) | Planned |
| Code restructure into modules | Planned |
| Automated security tests | Planned |
| Threat model and architecture documents | Planned |

> Update this table as work progresses so everyone sees the real state of the project.

---

## 2. The Problem We Are Solving

Most small applications fail at security in the same few ways:

- Passwords stored in plain text or with weak hashing, so one database leak exposes every account.
- Login protected by a password alone, so a stolen or guessed password means a full takeover.
- Sensitive data (documents, images, card numbers) stored as-is, so anyone with database access can read it.
- No limit on login attempts, which allows automated guessing.
- No record of who did what, so attacks go unnoticed.

**SecureVault demonstrates the correct way to handle all of these in one cohesive application**, and shows (with tests) that each defense actually works.

---

## 3. Goals and Non-Goals

### Goals
- Build a working vault with **layered authentication**: something you know (password), something you have (authenticator app), something you are (face).
- Ensure **no sensitive data is stored in plain form**: passwords are hashed; notes, images, and card numbers are encrypted.
- Detect tampering: modified ciphertext must fail to decrypt.
- Limit and log attacks: lockouts and an admin-visible audit trail.
- Produce **evidence** of security: a threat model, automated tests, and a live demo.
- Keep the code **modular and documented**, so it can later grow from a test app into a full-scale website.

### Non-Goals (to keep scope realistic)
- This is **not** a production password manager and makes no claim of replacing tools like Bitwarden.
- We do **not** claim PCI DSS compliance. Card handling is an educational demonstration of encryption, masking, and tokenization.
- We do **not** build or ship a keylogger as part of the product (see [Section 21](#21-ethics-legal-and-academic-integrity)).
- No native mobile app in this phase. The web UI is mobile-friendly.

---

## 4. Features

### 4.1 Authentication and Access Control
- **Registration** with username rules and a minimum password length (10 characters).
- **Argon2** password hashing (a memory-hard, modern algorithm designed to resist GPU cracking).
- **JWT access tokens** that expire after 15 minutes.
- **Optional TOTP MFA** compatible with Google Authenticator, Microsoft Authenticator, Authy, etc.
- **Face authentication** (planned) as an additional factor after the password step, with liveness hints (blink / mouth open) and rate limiting to reduce spoof attempts.
- **Role-based access control**: the first registered account becomes `admin`; all others are `user`. Admin-only routes return `403 Forbidden` for normal users.
- **Brute-force protection**: after 5 failed attempts, the account is locked for 5 minutes. Locked attempts are logged.
- **Timing-attack mitigation**: a hash verification is always performed, even for unknown usernames, so response time does not reveal which usernames exist.
- **Password reset** (planned) using single-use, short-lived reset tokens.

### 4.2 Vault (Encrypted Storage)
- **Notes**: title stored as plain text for listing, content encrypted with AES-256-GCM.
- **Images** (planned): files encrypted as binary data with a random nonce per file.
- **Payment cards** (planned): card number encrypted, only a random token plus the last 4 digits kept for display, Luhn validation on input, **CVV never stored**.
- **Ownership checks**: a user can only read their own records. Requests for another user's data return `404`.

### 4.3 Security Operations
- **Audit log** of registrations, logins (success, failure, locked), MFA events, note creation, forbidden access, and decryption failures.
- **Admin dashboard/API** to view recent events.
- **Integrity checks**: a failed decryption (tampered data) is detected and logged.

### 4.4 User Interface (planned)
- Register, login (with MFA and face steps), and vault pages.
- Mobile-first, simple, large tap targets.
- Clear error messages that do not leak sensitive information.

---

## 5. How the Six Internship Tasks Map to This Project

| # | Internship Task | Difficulty | Role in SecureVault | Status |
|---|---|---|---|---|
| 1 | Text Encryption Using Cryptographic Algorithms | Beginner | Core of the **encrypted notes** feature: random nonce per encryption, so identical text gives different ciphertext | Integrated |
| 2 | Keylogger Software | Beginner | **Excluded from the product.** Optional defensive reuse only (see below) | Excluded |
| 3 | Image Encryption | Beginner | The **encrypted image vault** | To integrate |
| 4 | Web-Based Facial Authentication System | Intermediate | The **face check** step after password/MFA | To build and integrate |
| 5 | Credit Card Encryption and Decryption | Intermediate | The **card vault** with masking and tokenization | To build and integrate |
| 6 | User Authentication System | Advanced | The whole **auth layer**: hashing, sessions/JWT, MFA, reset, roles | Mostly integrated |

**About Task 2 (keylogger):** it stays out of the main project because a keylogger invites misuse concerns even when built for education. If the team wants to reuse the learning, convert it to a **defensive feature**, for example an on-screen virtual keyboard for entering the master password, or a basic keylogger-detection demo, and document it as defense, not attack.

---

## 6. System Architecture

```
┌────────────────────────────────────────────────────────┐
│                  Browser (Web UI)                      │
│        Register · Login · MFA · Face · Vault           │
└───────────────────────────┬────────────────────────────┘
                            │ HTTPS (in deployment)
┌───────────────────────────▼────────────────────────────┐
│                     Flask Application                  │
│                                                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │ AUTH LAYER                                       │  │
│  │ password (Argon2) → TOTP code → face check       │  │
│  │ → JWT issued                                     │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │ VAULT API (requires valid JWT)                   │  │
│  │ notes | images | cards                           │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │ CRYPTO SERVICE                                   │  │
│  │ AES-256-GCM · random nonce · key separate        │  │
│  └──────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────┐  │
│  │ SECURITY SERVICES                                │  │
│  │ audit log · rate limiting/lockout · RBAC         │  │
│  └──────────────────────────────────────────────────┘  │
└───────────────────────────┬────────────────────────────┘
                            │
┌───────────────────────────▼────────────────────────────┐
│  SQLite database: hashes + ciphertext only             │
│  Keys live OUTSIDE the database (.secrets/ or env vars)│
└────────────────────────────────────────────────────────┘
```

**Request flow for reading a note:**
1. Browser sends `GET /api/vault/notes/1` with `Authorization: Bearer <token>`.
2. Server verifies the JWT signature and expiry, then loads the user.
3. Server fetches the note **only if it belongs to that user**.
4. Server decrypts using AES-GCM (the authentication tag is verified automatically).
5. If decryption fails, an integrity failure is logged and an error is returned.
6. Otherwise the plain text is returned to the user.

---

## 7. Security Design (How Each Protection Works)

### 7.1 Password hashing (Argon2)
Passwords are never stored. We store an Argon2 hash that includes a random salt and cost parameters. Verification re-hashes the attempt and compares. Even we (the developers) cannot recover a user's password.

### 7.2 Sessions with JWT
After a successful login, the server issues a signed token containing the user id, role, issue time, and a 15-minute expiry. The token is verified on every protected request. Short expiry limits damage if a token is stolen.

### 7.3 TOTP multi-factor authentication
1. `POST /api/mfa/setup` generates a random secret and returns an `otpauth://` URI (shown as a QR code in the UI).
2. The user scans it with an authenticator app.
3. `POST /api/mfa/enable` confirms the user can produce a valid code.
4. After that, login requires password **and** a current 6-digit code.

The MFA secret is itself **encrypted at rest** in the database.

### 7.4 Encryption of vault data (AES-256-GCM)
- **AES-256**: a strong symmetric cipher.
- **GCM mode**: encrypts **and** authenticates, so modified data is detected.
- **Random 12-byte nonce per encryption**: the same input never produces the same output.
- **Associated data (AAD)**: each record is bound to its owner (for example `user:5`), so ciphertext copied to another user's row fails to decrypt.
- Stored format: `base64(nonce + ciphertext + tag)`.

### 7.5 Key management
Keys are generated automatically and stored **outside the database**, in a local `.secrets/` folder (or in environment variables). The folder is excluded from Git. In a real deployment keys belong in a secrets manager or hardware security module.

### 7.6 Brute-force protection
Failed logins are counted per username. After 5 failures the account is locked for 5 minutes, and locked attempts return `429 Too Many Requests`. Failures are written to the audit log.

### 7.7 Face authentication (planned design)
- Capture from the webcam in the browser, send frames over HTTPS.
- Extract a **face embedding** (a numeric vector). Store the **embedding encrypted**, not the photo.
- Compare with a distance threshold at login.
- **Liveness hints** (blink / mouth open) and **rate limiting** reduce the success of photo or screen spoofing.
- Face check is a **second factor, not a replacement** for the password. A failed face check never reveals whether the password was right.
- Known caveat: webcam liveness is basic and not equal to certified anti-spoofing. We document this honestly.

### 7.8 Card handling (planned design)
- Validate the number with the **Luhn algorithm**.
- Encrypt the full number with AES-GCM; keep a **random token** and **last 4 digits** for display.
- **Never store the CVV.**
- Always **mask** numbers in API responses (for example `**** **** **** 4242`).
- Do not log card data.

### 7.9 Audit logging
Every security-relevant event is recorded with timestamp, event name, username, and IP address. Admins can review the latest events.

---

## 8. Tech Stack

| Layer | Technology | Why |
|---|---|---|
| Language | Python 3.10+ | Team familiarity, strong security libraries |
| Web framework | Flask | Lightweight, easy to structure |
| Database | SQLite (later PostgreSQL) | Zero setup now, upgradeable later |
| Password hashing | `argon2-cffi` | Modern memory-hard hashing |
| Tokens | `PyJWT` | Standard signed sessions |
| MFA | `pyotp` | TOTP (RFC 6238) |
| Encryption | `cryptography` (AES-GCM) | Well-reviewed library, authenticated encryption |
| Face auth (planned) | OpenCV + `face_recognition`/dlib or TensorFlow Lite | Face detection and embeddings |
| Images (planned) | Pillow | Image handling before encryption |
| Frontend (planned) | HTML, CSS, JavaScript (mobile-first) | Simple and demo-friendly |
| Testing | `pytest` (planned) | Automated security tests |

> **Windows note:** `dlib`/`face_recognition` can be difficult to install on Windows. One teammate should test this early, and we keep a fallback (OpenCV-based approach) ready.

---

## 9. Database Design

**users**

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| username | TEXT UNIQUE | lowercase, 3 to 32 chars |
| password_hash | TEXT | Argon2 hash |
| role | TEXT | `user` or `admin` |
| mfa_secret | TEXT | encrypted |
| mfa_enabled | INTEGER | 0 or 1 |
| created_at | TEXT | UTC timestamp |

**notes**

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| user_id | INTEGER FK | owner |
| title | TEXT | plain, for listing |
| content_enc | TEXT | AES-GCM ciphertext |
| created_at | TEXT | |

**audit_log**

| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| ts | TEXT | UTC timestamp |
| event | TEXT | e.g. `login_failed` |
| username | TEXT | may be null |
| ip | TEXT | |

**Planned tables:** `images` (owner, filename, encrypted blob or file path, created_at), `cards` (owner, token, last4, encrypted number, expiry, created_at), `face_templates` (owner, encrypted embedding, created_at), `password_resets` (user, token hash, expires_at, used).

---

## 10. API Reference

All request and response bodies are JSON. Protected routes need the header `Authorization: Bearer <token>`.

### Implemented

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | No | Health check |
| POST | `/api/register` | No | Create an account |
| POST | `/api/login` | No | Log in; returns JWT |
| POST | `/api/mfa/setup` | Yes | Generate MFA secret and `otpauth` URI |
| POST | `/api/mfa/enable` | Yes | Confirm code and enable MFA |
| POST | `/api/vault/notes` | Yes | Create an encrypted note |
| GET | `/api/vault/notes` | Yes | List your notes (titles only) |
| GET | `/api/vault/notes/<id>` | Yes | Read and decrypt one note |
| GET | `/api/admin/logs` | Admin | Latest 200 audit events |

### Examples

**Register**
```
POST /api/register
{ "username": "admin1", "password": "correct-horse-battery" }

201 → { "message": "Registered", "role": "admin" }
```

**Login (no MFA)**
```
POST /api/login
{ "username": "admin1", "password": "correct-horse-battery" }

200 → { "token": "<jwt>", "role": "admin" }
```

**Login (MFA enabled, code missing)**
```
401 → { "mfa_required": true }
```
Send the same request again with `"totp": "123456"`.

**Create note**
```
POST /api/vault/notes
Authorization: Bearer <token>
{ "title": "First note", "content": "my secret text" }

201 → { "id": 1 }
```

### Error codes used
`400` bad input · `401` not authenticated or bad credentials · `403` forbidden (role) · `404` not found · `409` username taken · `429` locked out · `500` integrity failure

### Planned
- `POST /api/auth/face/enroll`, `POST /api/auth/face/verify`
- `POST /api/auth/password/forgot`, `POST /api/auth/password/reset`
- `POST /api/vault/images`, `GET /api/vault/images`, `GET /api/vault/images/<id>`
- `POST /api/vault/cards`, `GET /api/vault/cards` (masked), `GET /api/vault/cards/<id>`
- `GET /api/admin/users`

---

## 11. Project Folder Structure

**Current (starter):**
```
securevault/
├── app.py
├── requirements.txt
└── README.md
```

**Target structure after restructuring:**
```
securevault/
├── app/
│   ├── __init__.py          # create_app()
│   ├── config.py            # settings (lockout limits, token lifetime)
│   ├── db.py                # database connection and schema
│   ├── auth/
│   │   ├── routes.py
│   │   ├── passwords.py     # Argon2
│   │   ├── tokens.py        # JWT
│   │   ├── mfa.py           # TOTP
│   │   └── face.py          # face enrollment and verification
│   ├── vault/
│   │   ├── notes.py
│   │   ├── images.py
│   │   └── cards.py
│   ├── crypto/
│   │   ├── aes.py           # encrypt/decrypt helpers
│   │   └── keys.py          # key loading and creation
│   ├── admin/
│   │   └── routes.py
│   └── security/
│       ├── audit.py
│       └── ratelimit.py
├── templates/               # HTML pages
├── static/                  # CSS, JS
├── tests/                   # pytest security tests
├── docs/
│   ├── threat_model.md
│   ├── architecture.md
│   └── screenshots/
├── run.py
├── requirements.txt
├── .gitignore
└── README.md
```

**`.gitignore` must include:**
```
.secrets/
*.db
venv/
__pycache__/
.env
```
Never commit keys or the database.

---

## 12. Setup and Installation (Windows)

**Requirements:** Python 3.10 or newer, Git, VS Code (recommended).

1. **Clone or open the project folder**
   ```powershell
   cd "C:\Users\<you>\Desktop\Minor Project"
   ```

2. **Create and activate a virtual environment** (recommended)
   ```powershell
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   ```
   If PowerShell blocks the script, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

3. **Install dependencies**
   ```powershell
   python -m pip install -r requirements.txt
   ```
   Using `python -m pip` ensures packages go into the same Python that runs the app.

4. **Run the server**
   ```powershell
   python app.py
   ```
   Open `http://127.0.0.1:5000/api/health`. You should see `{"status":"ok"}`.

> Opening `http://127.0.0.1:5000/` shows **404 Not Found**. That is expected: there are only `/api/...` routes until the frontend is added.

**First run:** the app creates `securevault.db` and a `.secrets/` folder with the encryption and JWT keys. Do **not** delete `.secrets/` while you have data, or existing encrypted data becomes unreadable. Each teammate has their own local keys and database.

**Optional environment variables:** `VAULT_DB` (database path), `JWT_SECRET` and `VAULT_KEY` (base64 values that override the key files).

---

## 13. Quick Test of the Running Backend

Open a **second terminal** (leave the server running) and run:

```powershell
$base = "http://127.0.0.1:5000/api"
Invoke-RestMethod "$base/health"

$creds = @{ username = "admin1"; password = "correct-horse-battery" } | ConvertTo-Json
Invoke-RestMethod -Method Post "$base/register" -ContentType "application/json" -Body $creds

$login = Invoke-RestMethod -Method Post "$base/login" -ContentType "application/json" -Body $creds
$h = @{ Authorization = "Bearer $($login.token)" }

$note = @{ title = "First note"; content = "my secret text" } | ConvertTo-Json
Invoke-RestMethod -Method Post "$base/vault/notes" -Headers $h -ContentType "application/json" -Body $note
Invoke-RestMethod "$base/vault/notes" -Headers $h
Invoke-RestMethod "$base/vault/notes/1" -Headers $h
Invoke-RestMethod "$base/admin/logs" -Headers $h
```

**Expected results**
- Registration returns `role: admin` (you are the first user).
- Listing shows the title; reading note 1 returns the decrypted text.
- Admin logs show register, login, and note events.
- Running the block twice gives `409` on registration (username exists). Change the username to retry.

**See the encryption proof:** open `securevault.db` with DB Browser for SQLite and look at the `notes` table. `content_enc` should be unreadable base64, not your text.

---

## 14. Threat Model

Each row is an attack we defend against, the defense, and the test that proves it. **Every row must have a passing test before the final demo.**

| # | Attack | Defense | Proof (test) |
|---|---|---|---|
| T1 | Database stolen | Passwords Argon2-hashed; vault data AES-256-GCM encrypted; keys stored outside DB | Inspect DB: no plain passwords or note text |
| T2 | Password brute force | Lockout after 5 failures for 5 min; strong minimum length | Script 6 wrong logins, expect `429` |
| T3 | Stolen or guessed password | TOTP MFA (and face check) required | Login with correct password but no code is rejected |
| T4 | Username enumeration | Same error message for unknown user and wrong password; hash always verified | Compare responses and timing |
| T5 | Stolen session token | Short 15-min expiry; signature verified every request | Expired and forged tokens return `401` |
| T6 | Tampered stored data | AES-GCM authentication tag | Edit one byte of ciphertext, expect integrity failure |
| T7 | Ciphertext copied to another user | AAD binds data to owner | Move a record between users, decryption fails |
| T8 | User reads another user's data | Ownership check on every query | User B requests user A's note id, expect `404` |
| T9 | Normal user accesses admin features | Role check | Non-admin calls `/api/admin/logs`, expect `403` |
| T10 | Identical plaintexts reveal patterns | Random nonce per encryption | Encrypt same text twice, ciphertexts differ |
| T11 | Photo or screen spoof of face (planned) | Liveness hints, rate limiting, face is only one factor | Present a printed photo, expect rejection |
| T12 | Card data leakage (planned) | Encryption, masking, token and last 4 only, no CVV storage | Check API output and DB contain no raw number or CVV |
| T13 | Secrets committed to Git | `.gitignore`, keys in `.secrets/` or env vars | Repository scan shows no keys |
| T14 | Injection (SQL) | Parameterized queries everywhere | Test with `' OR 1=1 --` as username |

**Out of scope threats (documented honestly):** malware on the user's device, compromised server host, advanced deepfake attacks, denial of service at scale.

---

## 15. Testing Plan

- **Unit tests** (`pytest`): encryption round trip, nonce uniqueness, tamper detection, password hashing, Luhn validation, TOTP verification.
- **API tests**: register, login, MFA flow, vault CRUD, role checks, ownership checks, lockout.
- **Security tests**: one test per threat-model row above.
- **Manual tests**: face enrollment and verification under different lighting, mobile browser layout, token expiry behavior.
- **Evidence for the report**: save test output and screenshots in `docs/`.

Target: run all tests with a single command (`pytest`) live during the demo.

---

## 16. Development Roadmap

| Phase | Work | Output |
|---|---|---|
| 1. Foundation | Venv, Git repo, `.gitignore`, README, agree on structure | Shared repo |
| 2. Restructure | Split `app.py` into modules, add config | Clean codebase |
| 3. Auth complete | Password reset, CORS/CSRF settings, token refresh/logout | Full auth layer |
| 4. Vault | Port image encryption, build card vault (Luhn, masking, tokens) | Images and cards working |
| 5. Face auth | Port face login, add liveness hint, rate limit, encrypted embeddings | Third authentication factor |
| 6. Frontend | Register, login (MFA and face steps), vault pages, mobile-friendly | Usable UI |
| 7. Testing | Security and API tests mapped to the threat model | Passing test suite |
| 8. Documentation | Threat model, architecture diagram, screenshots, report | `docs/` complete |
| 9. Demo prep | Rehearse the demo script, prepare backup screenshots/video | Ready for evaluation |

Work in short cycles and keep `main` always runnable. Use feature branches and pull requests so teammates review each other's code.

---

## 17. Team Roles

> Fill in names. Suggested split so everyone has a defensible part to explain in the viva.

| Member | Responsibility |
|---|---|
| _Name 1_ | Authentication layer (passwords, JWT, MFA, reset, lockout) |
| _Name 2_ | Vault and crypto (notes, images, cards, key management) |
| _Name 3_ | Face authentication and liveness |
| _Name 4_ | Frontend, testing, documentation |

Everyone should understand the **whole** architecture and be able to explain concepts from the [Glossary](#23-glossary), not just their own module.

---

## 18. Demo Script (For Evaluation Day)

1. **Problem (1 min):** how weak authentication and plain storage cause breaches.
2. **Architecture (1 min):** show the diagram in Section 6.
3. **Register and log in:** show Argon2 hash in the database, not the password.
4. **Enable MFA:** scan the QR code, log in with a code.
5. **Face check:** enroll, then log in; show a printed photo being rejected.
6. **Vault:** add a note, an image, and a card; show masked card display.
7. **Show the database:** open it and show only ciphertext and hashes.
8. **Attack demos:** wrong password lockout, tampered ciphertext failing, normal user blocked from admin.
9. **Audit log:** show the admin view recording those attacks.
10. **Run tests:** `pytest` passing live.
11. **Related work and limits (1 min):** compare with existing tools and state limitations honestly.

Prepare a backup screen recording in case the webcam or network fails during the demo.

---

## 19. Related Work

| Existing tool | What it does | How SecureVault differs |
|---|---|---|
| Bitwarden, 1Password, KeePass | Production password managers | Ours is an educational demonstration of the full stack of defenses with documented threat model and tests; not a replacement |
| Google/Microsoft Authenticator | TOTP codes | We integrate TOTP into our own login and combine it with a face factor |
| Typical tutorial login apps | Password only | We layer password, one-time code, and face, with lockouts and auditing |

Our contribution is the **integration, evidence (threat model and tests), and clarity**, not a claim of beating commercial products.

---

## 20. Limitations (Be Honest in the Viva)

- The current build uses **one server-side master key** for vault encryption. A stronger design is **per-user keys derived from the user's password** (so even the server operator cannot read data). This is documented as future work.
- Face liveness using a webcam is basic and not equal to certified anti-spoofing.
- The lockout counter is held **in memory** and resets if the server restarts; a database or Redis would persist it.
- SQLite and the Flask development server are for development, not production load.
- No HTTPS in local testing; production requires TLS.
- Card handling demonstrates concepts only and is not PCI DSS certified.
- No account recovery for encrypted data if keys are lost.

Listing limitations clearly shows maturity and usually earns credit.

---

## 21. Ethics, Legal, and Academic Integrity

- **Keylogger:** the internship included a keylogger task. It is **not** part of this product. Any related work must be defensive and documented as such. Never run or distribute monitoring software on anyone's device without explicit consent.
- **Face data and personal data:** use only test accounts and consenting teammates. Store embeddings, not photos, and encrypted.
- **Test card numbers:** use only well-known test numbers (for example, `4242 4242 4242 4242`). Never enter real card details.
- **Internship work:** Tasks 1 to 3 (and the others) originated as internship training tasks. **Check your college's policy on reusing internship work, and cite the internship in the project report.** Make clear what was extended or newly built for this minor project.
- **Open-source libraries:** all dependencies keep their own licenses; credit them in the report.
- **Responsible use:** the attack demos run only against our own application.

---

## 22. Future Scope

- Per-user encryption keys derived from passwords (zero-knowledge style design).
- Hardware-backed key storage or a cloud KMS.
- WebAuthn / passkeys as a modern replacement for passwords.
- Stronger liveness detection and anti-spoofing models.
- Persistent rate limiting (Redis), IP-based throttling, and CAPTCHA.
- Encrypted file sharing between users.
- Mobile app (Flutter or React Native) and browser extension.
- Migration to PostgreSQL and deployment behind HTTPS with a production WSGI server.
- Security headers, CSP, dependency scanning, and automated CI tests.

---

## 23. Glossary

| Term | Meaning |
|---|---|
| **Hashing** | One-way transformation; cannot be reversed. Used for passwords. |
| **Encryption** | Two-way transformation with a key. Used for vault data. |
| **Argon2** | Modern, memory-hard password hashing algorithm. |
| **Salt** | Random value added before hashing so identical passwords hash differently. |
| **AES-256-GCM** | Strong symmetric encryption that also detects tampering. |
| **Nonce / IV** | Unique random value per encryption so repeated plaintext looks different. |
| **AAD** | Associated data bound to ciphertext (here: the owner), checked during decryption. |
| **JWT** | Signed token proving a successful login, with an expiry. |
| **TOTP / MFA** | Time-based one-time code from an authenticator app; a second factor. |
| **RBAC** | Role-based access control (user vs admin). |
| **Tokenization** | Replacing sensitive data (like a card number) with a random token. |
| **Luhn algorithm** | Checksum used to validate card numbers. |
| **Face embedding** | Numeric vector describing a face, used for comparison instead of storing photos. |
| **Liveness detection** | Checks that a real person (not a photo) is present, e.g. blink detection. |
| **Audit log** | Record of security-relevant events. |
| **Brute force** | Trying many passwords until one works. |
| **Threat model** | Structured list of attacks, defenses, and proofs. |

---

## 24. References

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- OWASP Authentication Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- RFC 6238 (TOTP): https://datatracker.ietf.org/doc/html/rfc6238
- RFC 7519 (JWT): https://datatracker.ietf.org/doc/html/rfc7519
- NIST SP 800-38D (AES-GCM): https://csrc.nist.gov/publications/detail/sp800-38d/final
- Python `cryptography` documentation: https://cryptography.io
- Flask documentation: https://flask.palletsprojects.com
- Argon2 (`argon2-cffi`) documentation: https://argon2-cffi.readthedocs.io

---

_Last updated: October 2026. Keep the Project Status table current as the team progresses._