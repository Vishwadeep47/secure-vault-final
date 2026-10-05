# SecureVault hardening checklist

Run `python scripts/hardening_check.py` (add `--audit` to check libraries for known
vulnerabilities). Run `python scripts/scan_git_history.py` before every push to GitHub.
Run `python -m pytest -v tests/test_hardening.py` for the automated proof.

| # | Risk | Protection | Where | Proof |
|---|------|-----------|-------|-------|
| H1 | Bots creating thousands of accounts | 20 sign-up requests per address per hour | `auth/routes.py`, `config.py` | `test_H1_*` |
| H2 | One address trying many usernames (credential stuffing) | 120 logins per address per 5 minutes, on top of the per-account lockout | `auth/routes.py` | `test_H2_*` |
| H3 | Flooding memory with random names | Lockout and counter tables are capped at 10,000 entries, oldest dropped first | `security/ratelimit.py` | `test_H3_*` |
| H4 | Huge request bodies | JSON limited to 200 KB, images to 10 MB, Waitress to 11 MB | `__init__.py`, `serve.py` | `test_H4_*`, `test_H7_*` |
| H5 | Error pages leaking internals | Plain JSON errors on `/api`; crashes return a generic message, details stay in the server log | `__init__.py` | `test_H5_*` |
| H6 | Browser-side attacks | CSP, no framing, no sniffing, no referrer, camera only for this site, same-origin policies, HSTS over HTTPS, no CORS | `__init__.py` | `test_H6_*`, `test_T17_*` |
| H7 | Development server in production | Waitress via `python serve.py`; hides server name and version | `serve.py` | `test_H7_*` |
| H8 | Secrets already in Git history | History scanner for forbidden files, hard-coded secrets, and your real keys | `scripts/scan_git_history.py` | `test_H8_*` |
| H9 | Settings drifting over time | One-command checklist: debug off, `.gitignore`, key sizes, sensible limits, Argon2 strength, headers, tracked files, history, optional library audit | `scripts/hardening_check.py` | `test_H9_*` |

## HTTPS (needed for any real deployment)

Passwords and tokens cross the network in clear text on plain `http://`. For anything beyond
`localhost`, put a reverse proxy in front that handles HTTPS and certificates, and keep
SecureVault listening only on `127.0.0.1`.

Simplest option, Caddy (gets a free certificate automatically for a real domain name):

    caddy reverse-proxy --from yourdomain.example --to 127.0.0.1:5000

Run `python serve.py` as usual. Do not set `VAULT_HOST=0.0.0.0` unless a firewall or proxy
protects the port. When requests arrive over HTTPS through a proxy, the app sends the
`Strict-Transport-Security` header. (If your proxy terminates HTTPS, configure Waitress to
trust its forwarded headers first; see the Waitress documentation for `trusted_proxy`.)

## Known limitations (say these in the viva)

- Lockouts and rate limits are kept in memory and reset when the server restarts.
- Per-account lockout lets someone deliberately lock another person's account for 5 minutes
  (a trade-off against brute-forcing). The per-address limit slows that down.
- The login token is kept in `sessionStorage`, so a cross-site-scripting bug would expose it.
  The strict CSP and the "no HTML from text" rule exist to prevent that.
- Reset tokens are printed to the server console because accounts have no email address.
- A single server-side key encrypts all vault data. Per-user keys derived from passwords
  would stop even the server operator from reading data (future work).
- No certificate pinning, web application firewall, or intrusion detection.
