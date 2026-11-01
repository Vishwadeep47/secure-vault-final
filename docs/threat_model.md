# SecureVault: Threat Model

Method: STRIDE-style review. Each threat lists the attack, the defence built, and the test that proves it. Test IDs refer to `tests/test_threat_model.py` (T01-T17) and `tests/test_hardening.py` (H1-H9).

**Assets:** images, card data, passwords, MFA secrets, session tokens, encryption keys, audit log.
**Attackers considered:** anonymous internet user, a registered user attacking another user, someone who steals the database file, someone who steals a session token.

| ID | Threat | Attack example | Defence | Test |
|---|---|---|---|---|
| T01 | Password guessing | Try thousands of passwords on one account | Lockout after 5 failures, Argon2 slows each guess | T01 |
| T02 | Password database theft | Attacker copies the `.db` file | Only Argon2 hashes stored; vault data encrypted with AES-256-GCM; keys kept outside DB | T02 |
| T03 | Ciphertext tampering | Edit encrypted bytes in the DB | GCM authentication fails, request returns an error | T03 |
| T04 | Swapping ciphertext between records | Copy user A's blob into user B's row | Associated data binds ciphertext to owner and record id | T04 |
| T05 | Accessing another user's data | Change the id in the URL | Ownership check on every read, update, delete; returns 404 | T05 |
| T06 | Stolen or reused token | Use a token after logout or password change | `token_version` bumped, old tokens rejected; 15-minute expiry | T06 |
| T07 | Forged token | Edit JWT claims or sign with a guessed key | Signature check with a 32-byte random secret; role read from DB, not token | T07 |
| T08 | MFA bypass | Skip the second step, replay a code | Login needs valid TOTP when enabled; reset does not bypass MFA | T08 |
| T09 | Password reset abuse | Learn which users exist, reuse a token | Same response for known and unknown users; hashed, single-use, 15-minute token; rate limited | T09 |
| T10 | SQL injection | Quote characters in login or admin filters | Parameterised queries everywhere | T10 |
| T11 | Face spoofing | Photo of the victim | **Not applicable: face login not built** (test skipped) | T11 (skip) |
| T12 | Malicious upload | Script renamed to `.png`, huge image | Type detected from bytes, allow-list, random file name, size and pixel limits | T12 |
| T13 | Card data exposure | Read full number or CVV from API or DB | Number encrypted, CVV never stored, reveal needs password and MFA again | T13 |
| T14 | Cross-site scripting | A card holder name containing `<script>` | No `innerHTML` in the frontend, strict CSP | T14 |
| T15 | Privilege escalation | Normal user calls admin routes | Role checked from DB on each admin request | T15 |
| T16 | Information leakage | Stack traces, server banner, cached images | Generic errors, server name hidden, `no-store` on images | T16 |
| T17 | Secrets in Git | Keys or data committed by mistake | `.gitignore`, history scanner, checklist script | T17, H9 |
| H1-H8 | Abuse and resource exhaustion | Mass sign-ups, huge JSON, memory growth | Sign-up and login limits, 200 KB body cap, bounded trackers, security headers | H1-H8 |
| T18 | Weak or reused password | "password123" at the length minimum | Common-password blocklist on top of the length rule, checked on sign-up, change, and reset | test_password_policy.py |
| T19 | Lost authenticator device locks the account out | Phone lost, no way to produce a TOTP code | Single-use recovery codes, issued once, replaceable (invalidating the old set) with the current password | test_recovery_codes.py |
| T20 | Disabled or locked account still usable | A banned user keeps using an open session | `disabled` ends login AND bumps `token_version` (kills open sessions immediately); checked again in `require_auth` as defense in depth | test_admin_user_management.py |
| T21 | Silent tampering with the audit trail | Edit or delete a row to hide an attack | Each row's hash covers its own fields plus the row before it; one admin call recomputes the whole chain and names the first broken row | test_audit_chain.py |
| T22 | One compromised key exposes every account's data | Master key leaks | Each account's vault data is under its own key (wrapped by the master key); a rotation is per-account, not all-or-nothing | test_user_keys.py |
| T24 | Session left open on a shared machine | Forgetting to log out on a public computer | Idle auto-logout after 5 minutes of no activity, on top of the 15-minute token lifetime | frontend, static/js/main.js |

## Out of scope / accepted risks

- Malware on the user's own computer (this is where a keylogger would matter, and it is why that task was not added to the product).
- Physical access to the server and its `.secrets/` folder.
- Denial of service at network level.
- Traffic is plain HTTP on localhost for the demo; real use needs HTTPS (HSTS is already sent when HTTPS is used).
- Rotating a per-user data key does not re-encrypt existing images/cards; only new writes use the new key version. Old data keeps decrypting fine under the version it was written with, but a full re-encryption pass is not built.
- The audit hash chain detects tampering; it does not stop an attacker with direct database write access from truncating the table entirely and starting a new chain from scratch (there is nothing outside the database itself to compare against).
- Face login is not built (see T11).
