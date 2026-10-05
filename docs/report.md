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
| Password security | Argon2 hashing, lockout after 5 failures, password reset and change |
| Multi-factor authentication | TOTP setup with QR code, required at login and for card reveal |
| Data encryption | AES-256-GCM for notes, images and cards, keys stored outside the database |
| Secure file handling | Image vault: type detected from bytes, random file names, encrypted at rest |
| Logging and monitoring | Audit log plus admin log, user and statistics views |
| Face authentication | Designed, not completed (see Limitations) |
| Keylogger task | Excluded from the product on purpose: it is an attack tool, not a defence |

## 4. Architecture (summary)

Plain HTML, CSS and JavaScript in the browser talk to a Flask JSON API. The API is split into authentication, vault, admin and security modules. Data lives in SQLite. Keys live in a separate `.secrets/` folder, never in the database or Git. A diagram is in `docs/architecture.md`.

## 5. Security design

- **Passwords:** Argon2, never stored or logged in plain text.
- **Sessions:** JWT valid for 15 minutes. A `token_version` stored in the database is bumped on logout, password change and password reset, so old tokens stop working at once.
- **MFA:** TOTP; card reveal asks again for password and MFA.
- **Encryption:** AES-256-GCM with a random nonce per item. Associated data binds each ciphertext to its owner and record, so swapped or tampered ciphertext fails to decrypt.
- **Cards:** Luhn check, number encrypted, only a token and last four digits are stored, CVV is never stored or returned, an HMAC fingerprint detects duplicates. Only test card numbers are used.
- **Images:** accepted types are PNG, JPEG, GIF and WEBP, detected by Pillow from the bytes. Decompression bombs are rejected. Responses use `Cache-Control: no-store`.
- **Rate limiting:** login lockout after 5 failures, 20 sign-ups per address per hour, 120 logins per address per 5 minutes, bounded memory (10,000 tracked entries).
- **Password reset:** same response for real and unknown users, token stored hashed, single use, 15-minute expiry, MFA is not bypassed.
- **Admin:** role checked from the database on every request; filters are parameterised.
- **Frontend:** no `innerHTML` anywhere (checked by a test), strict Content Security Policy, session kept in `sessionStorage`.
- **Server:** JSON body cap of 200 KB, no stack traces in errors, extra headers (Permissions-Policy, COOP, CORP, HSTS over HTTPS), Waitress production server.

## 6. Testing

| Suite | Result |
|---|---|
| Threat-model tests (`tests/test_threat_model.py`) | 91 passed |
| Hardening tests (`tests/test_hardening.py`) | 28 passed |
| Smoke scripts (7 scripts) | 205 checks passed |
| Face test | 1 skipped (feature deferred) |
| `pip-audit` | no known vulnerabilities at time of testing |

Full output: `docs/test_results.txt`. Tests were also checked to fail when a flaw is deliberately injected, so they are not passing by accident.

## 7. Limitations (honest list)

- **Face authentication is not implemented.** The design (OpenCV YuNet detector with SFace recognition) and a setup check script exist, but the test laptop camera returned a black image, so enrollment and login were not built. The login code has a marked hook where it would plug in.
- Rate-limit counters are in memory and reset when the server restarts.
- Password reset prints the token to the console instead of sending email.
- SQLite and a local key folder suit a demo, not production. A real deployment needs HTTPS, a managed key store and a proper database.
- No independent penetration test was done.

## 8. Future work

Face authentication with liveness checks, email delivery for reset, key rotation, persistent rate limiting, and deployment behind HTTPS.

## 9. Conclusion

SecureVault delivers a working encrypted vault with layered authentication, an admin audit view, a written threat model and automated tests for each major threat. The one planned feature left out, face authentication, is documented openly along with the reason.

## 10. Team contributions

| Name | Enrollment Number | Section | Roll No | 
|---|---|---|---|
| Vishwadeep Choudhary | AJU/221210 | D | 107 | 
| Aman Kumar Mishra | AJU/232166 | D | 141 | 
| Raja Babu | AJU/232212 | D | 151 | 
| Rajesh Kumar Mahato | AJU/232213 | D | 152 | 
