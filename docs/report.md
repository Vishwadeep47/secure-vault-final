# SecureVault: Project Report

**Course project:** Cybersecurity minor project
**Repository:** https://github.com/Vishwadeep47/secure-vault-final


## 1. Abstract

SecureVault is a web application that stores sensitive personal data (notes, images and payment card details) in an encrypted vault. Access is protected by layered authentication: a password hashed with Argon2, time-based one-time password (TOTP) multi-factor authentication, and short-lived signed session tokens. The project combines several cybersecurity internship tasks into one structured product and is tested against a written threat model.

## 2. Objectives

1. Build a working application that protects data at rest and in transit between layers.
2. Apply layered authentication rather than a single password.
3. Show each security claim with an automated test.
4. Document the design, the threats, the limitations and the hardening done.

## 3. Mapping to internship tasks

| Internship task | Where it appears in SecureVault |
|---|---|
| Password security | Argon2 hashing, a length-first policy with a common-password blocklist (NIST SP 800-63B), lockout after 5 failures, password reset and change |
| Multi-factor authentication | TOTP setup with QR code, required at login and for card reveal, with 8 single-use recovery codes as a backup |
| Data encryption | AES-256-GCM for notes, images and cards, with a separate per-account key (versioned, rotatable) wrapped by a master key kept outside the database |
| Secure file handling | Image vault: type detected from bytes, random file names, encrypted at rest |
| Logging and monitoring | Hash-chained (tamper-evident) audit log, an admin log/user/stats view, and a per-user "my activity" view |
| Face authentication | Designed, not completed (see Limitations) |
| Keylogger task | Excluded from the product on purpose: it is an attack tool, not a defence |

## 4. Architecture (summary)

Plain HTML, CSS and JavaScript in the browser talk to a Flask JSON API. The API is split into authentication, vault, admin and security modules. Data lives in SQLite. Keys live in a separate `.secrets/` folder, never in the database or Git. A diagram is in `docs/architecture.md`.

## 5. Security design

- **Passwords:** Argon2, never stored or logged in plain text. A length-first rule (minimum 12 characters) plus a common-password blocklist and a check against the username, enforced on sign-up, change, and reset.
- **Sessions:** JWT valid for 15 minutes. A `token_version` stored in the database is bumped on logout, password change, password reset, and when an admin disables an account, so old tokens stop working at once. The browser also logs itself out after 5 minutes of inactivity.
- **MFA:** TOTP; card reveal asks again for password and MFA. 8 single-use recovery codes are issued when MFA is turned on, for logging in if the authenticator app is unavailable; they can be regenerated (with the current password) which invalidates the old set.
- **Encryption:** AES-256-GCM with a random nonce per item. Associated data binds each ciphertext to its owner and record, so swapped or tampered ciphertext fails to decrypt. Each account's notes, images, and cards are encrypted under that account's own data key (not one key shared by everyone); the key is wrapped by a server master key and versioned, so rotating it never breaks data written under an earlier version.
- **Cards:** Luhn check, number encrypted, only a token and last four digits are stored, CVV is never stored or returned, an HMAC fingerprint detects duplicates. Revealed numbers hide themselves (and clear the clipboard) after 15 seconds. Only test card numbers are used.
- **Images:** accepted types are PNG, JPEG, GIF and WEBP, detected by Pillow from the bytes. Decompression bombs are rejected. Responses use `Cache-Control: no-store`.
- **Rate limiting:** login lockout after 5 failures, 20 sign-ups per address per hour, 120 logins per address per 5 minutes; counters live in the database so a restart cannot reset an attack in progress, and an admin can clear a lockout directly without touching the password.
- **Password reset:** same response for real and unknown users, token stored hashed, single use, 15-minute expiry, MFA is not bypassed.
- **Sharing:** a note can be shared through a link that works once, carries a random 256-bit token (stored only as a hash), expires, and needs no account to open.
- **Audit log:** hash-chained - each row's hash covers its own fields plus the row before it, so an admin can recompute the chain and get back the exact row where something was edited, deleted, or inserted out of order.
- **Admin:** role checked from the database on every request; filters are parameterised; an admin can disable or re-enable an account or clear its lockout, and verify the audit log's integrity.
- **Frontend:** no `innerHTML` anywhere (checked by a test), strict Content Security Policy, session kept in `sessionStorage`, idle auto-logout after 5 minutes.
- **Server:** JSON body cap of 200 KB, no stack traces in errors, extra headers (Permissions-Policy, COOP, CORP, HSTS over HTTPS), Waitress production server.

## 6. Testing

| Suite | Result |
|---|---|
| Threat-model tests (`tests/test_threat_model.py`) | 90 passed |
| Hardening tests (`tests/test_hardening.py`) | 28 passed |
| New-feature tests (password policy, recovery codes, admin controls, audit chain, per-user keys, share links, activity) | 67 passed |
| Smoke scripts (7 scripts) | 205 checks passed |
| Face test | 1 skipped (feature deferred) |
| 2nd skip | 1 skipped (needs `.secrets/`, created on first server run) |
| `pip-audit` | no known vulnerabilities at time of testing |

Full suite: 185 passed, 2 skipped.

Full output: `docs/test_results.txt`. Tests were also checked to fail when a flaw is deliberately injected, so they are not passing by accident.

## 7. Limitations (honest list)

- **Face authentication is not implemented.** The design (OpenCV YuNet detector with SFace recognition) and a setup check script exist, but the test laptop camera returned a black image, so enrollment and login were not built. The login code has a marked hook where it would plug in.
- Password reset prints the token to the console instead of sending email.
- Rotating a per-account encryption key only applies to new data; existing notes, images, and cards keep decrypting under the key version that wrote them rather than being re-encrypted.
- Per-account keys are wrapped by a single server master key, not derived from each user's own password, so a leaked master key still exposes every account (it would just no longer mean "every account under one shared encryption key").
- The audit log's hash chain proves a row was not quietly edited, but cannot stop someone with direct database access from deleting the whole table and starting a new chain.
- SQLite and a local key folder suit a demo, not production. A real deployment needs HTTPS, a managed key store and a proper database.
- No independent penetration test was done.

## 8. Future work

Face authentication with liveness checks, email delivery for reset, deployment behind HTTPS, full re-encryption on key rotation, and per-account keys derived from each user's own password instead of a shared master key.

## 9. Conclusion

SecureVault delivers a working encrypted vault with layered authentication (including MFA recovery codes and a hardened password policy), per-account encryption keys, a tamper-evident audit log, admin account controls, one-time note sharing, and a self-service activity view - backed by a written threat model and automated tests for each major threat. The one planned feature left out, face authentication, is documented openly along with the reason.

## 10. Team contributions

| Name | Enrollment Number | Section | Roll No | 
|---|---|---|---|
| Vishwadeep Choudhary | AJU/221210 | D | 107 | 
| Aman Kumar Mishra | AJU/232166 | D | 141 | 
| Raja Babu | AJU/232212 | D | 151 | 
| Rajesh Kumar Mahato | AJU/232213 | D | 152 | 
