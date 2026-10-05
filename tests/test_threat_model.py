"""Security tests, one group per row of the threat model (T01 to T17).

Run everything:         python -m pytest -v
Run one threat:         python -m pytest -v -k T05
Short summary only:     python -m pytest -q

Each test name starts with the threat id so the output reads as evidence:
    attack -> defense -> test that proves it.
Every test gets a brand-new temporary database and keys, so your real data is untouched.
"""
import base64
import io
import json
import os
import re
import time

import jwt
import pyotp
import pytest

from app.auth import passwords
from app.auth.tokens import create_token
from app.crypto import aes
from app.security import mailer
from tests.helpers import (HOLDER, NOTE_TEXT, PAN, PASSWORD, b64url, b64url_decode, bearer,
                           card_body, db, flip_last_byte, png_bytes)

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))


# ============================================================ small shortcuts
def login(client, name, password=PASSWORD, **extra):
    return client.post("/api/login", json={"username": name, "password": password, **extra})


def add_note(client, headers, title="t", content=NOTE_TEXT):
    return client.post("/api/vault/notes", json={"title": title, "content": content}, headers=headers).json["id"]


def add_card(client, headers, number="4242 4242 4242 4242"):
    return client.post("/api/vault/cards", json=card_body(number), headers=headers).json["id"]


def add_image(client, headers, seed=1):
    r = client.post("/api/vault/images", data={"file": (io.BytesIO(png_bytes(seed)), "p.png")},
                    headers=headers, content_type="multipart/form-data")
    assert r.status_code == 201
    return r.json["id"]


def enable_mfa(client, headers):
    secret = client.post("/api/mfa/setup", headers=headers).json["secret"]
    assert client.post("/api/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=headers).status_code == 200
    return secret


def user_id(app, name):
    return db(app).execute("SELECT id FROM users WHERE username=?", (name,)).fetchone()[0]


def audit_events(app):
    return {row[0] for row in db(app).execute("SELECT event FROM audit_log")}


def image_file(app, image_id):
    stored = db(app).execute("SELECT stored_name FROM images WHERE id=?", (image_id,)).fetchone()[0]
    return os.path.join(app.config["UPLOAD_DIR"], stored)


# ======================================================= T01 database stolen
def test_T01_stolen_database_and_files_reveal_nothing(app, client, alice):
    add_note(client, alice)
    add_card(client, alice)
    add_image(client, alice)
    mfa_secret = client.post("/api/mfa/setup", headers=alice).json["secret"]

    raw = open(app.config["DB_PATH"], "rb").read()
    for needle in (PASSWORD, NOTE_TEXT, PAN, HOLDER, mfa_secret):
        assert needle.encode() not in raw, f"{needle!r} found in the database file"


def test_T01_keys_are_not_stored_in_the_database(app):
    raw = open(app.config["DB_PATH"], "rb").read()
    for key in (app.config["AES_KEY"], app.config["JWT_SECRET"]):
        assert key not in raw
        assert base64.b64encode(key) not in raw and key.hex().encode() not in raw


def test_T01_passwords_are_stored_as_argon2_hashes(app, client, alice):
    stored = db(app).execute("SELECT password_hash FROM users WHERE username='alice'").fetchone()[0]
    assert stored.startswith("$argon2id$") and PASSWORD not in stored


def test_T01_uploaded_images_are_encrypted_on_disk(app, client, alice):
    image_id = add_image(client, alice)
    on_disk = open(image_file(app, image_id), "rb").read()
    assert b"\x89PNG" not in on_disk and on_disk != png_bytes(1)


# ====================================================== T02 password brute force
def test_T02_account_locks_after_five_wrong_passwords(client, alice):
    for _ in range(5):
        assert login(client, "alice", "wrong-password-xx").status_code == 401
    assert login(client, "alice", "wrong-password-xx").status_code == 429


def test_T02_correct_password_is_refused_while_locked(client, alice):
    for _ in range(5):
        login(client, "alice", "wrong-password-xx")
    assert login(client, "alice", PASSWORD).status_code == 429


def test_T02_changing_the_username_case_does_not_reset_the_counter(client, alice):
    for name in ("alice", "ALICE", " alice ", "Alice", "aLiCe"):
        assert login(client, name, "wrong-password-xx").status_code == 401
    assert login(client, "ALICE", "wrong-password-xx").status_code == 429


def test_T02_lockout_ends_after_the_waiting_time(app, client, alice):
    app.config["LOCKOUT_SECONDS"] = 1
    for _ in range(5):
        login(client, "alice", "wrong-password-xx")
    assert login(client, "alice", PASSWORD).status_code == 429
    time.sleep(1.2)
    assert login(client, "alice", PASSWORD).status_code == 200


def test_T02_weak_passwords_are_refused_at_registration(client):
    for weak in ("short", "123456789", ""):
        assert client.post("/api/register", json={"username": "weak1", "password": weak}).status_code == 400


# ============================================================ T03 stolen password
def test_T03_password_alone_does_not_log_in_when_mfa_is_on(client, alice):
    secret = enable_mfa(client, alice)
    r = login(client, "alice")
    assert r.status_code == 401 and r.json.get("mfa_required") is True and "token" not in r.json
    r = login(client, "alice", totp="000000")
    assert r.status_code == 401 and "token" not in r.json
    assert login(client, "alice", totp=pyotp.TOTP(secret).now()).status_code == 200


def test_T03_guessing_mfa_codes_gets_locked_out(client, alice):
    secret = enable_mfa(client, alice)
    for _ in range(5):
        assert login(client, "alice", totp="000000").status_code == 401
    assert login(client, "alice", totp=pyotp.TOTP(secret).now()).status_code == 429


def test_T03_mfa_secret_cannot_be_replaced_with_a_stolen_token(client, alice):
    enable_mfa(client, alice)
    assert client.post("/api/mfa/setup", headers=alice).status_code == 409


def test_T03_revealing_a_card_needs_the_password_again(client, alice):
    card = add_card(client, alice)
    assert client.post(f"/api/vault/cards/{card}/reveal", json={}, headers=alice).status_code == 401
    assert client.post(f"/api/vault/cards/{card}/reveal", json={"password": "wrong-password-xx"}, headers=alice).status_code == 401
    assert client.post(f"/api/vault/cards/{card}/reveal", json={"password": PASSWORD}, headers=alice).json["card_number"] == PAN


# ======================================================== T04 username enumeration
def test_T04_login_error_is_identical_for_unknown_user_and_wrong_password(client, alice):
    unknown = client.post("/api/login", json={"username": "nobody", "password": "whatever-long-password"})
    wrong = client.post("/api/login", json={"username": "alice", "password": "wrong-long-password-1"})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json == wrong.json


def test_T04_unknown_user_still_costs_a_password_hash_check(client, monkeypatch):
    calls = []
    real = passwords._hasher

    class Counting:
        def verify(self, stored_hash, password):
            calls.append(1)
            return real.verify(stored_hash, password)

        def __getattr__(self, name):
            return getattr(real, name)

    monkeypatch.setattr(passwords, "_hasher", Counting())
    client.post("/api/login", json={"username": "nobody-here", "password": "whatever-long-password"})
    assert len(calls) == 1  # same work as for a real account, so timing does not give it away


# ============================================================ T05 token attacks
def _claims(app, name, **overrides):
    claims = {"sub": str(user_id(app, name)), "role": "user", "ver": 0, "iat": int(time.time()), "exp": int(time.time()) + 900}
    claims.update(overrides)
    return claims


def test_T05_token_signed_with_another_key_is_rejected(app, client, alice):
    forged = jwt.encode(_claims(app, "alice"), "x" * 32, algorithm="HS256")
    assert client.get("/api/me", headers=bearer(forged)).status_code == 401


def test_T05_editing_the_token_contents_breaks_the_signature(app, client, alice):
    header, payload, signature = alice["Authorization"][7:].split(".")
    data = json.loads(b64url_decode(payload))
    data["role"] = "admin"
    edited = ".".join([header, b64url(json.dumps(data).encode()), signature])
    assert client.get("/api/me", headers=bearer(edited)).status_code == 401


def test_T05_token_with_algorithm_none_is_rejected(app, client, alice):
    unsigned = b64url(b'{"alg":"none","typ":"JWT"}') + "." + b64url(json.dumps(_claims(app, "alice", role="admin")).encode()) + "."
    assert client.get("/api/me", headers=bearer(unsigned)).status_code == 401


def test_T05_expired_token_is_rejected(app, client, alice):
    expired = create_token(user_id(app, "alice"), "user", app.config["JWT_SECRET"], minutes=-1)
    assert client.get("/api/me", headers=bearer(expired)).status_code == 401


def test_T05_valid_signature_for_a_user_that_does_not_exist_is_rejected(app, client, alice):
    ghost = jwt.encode(_claims(app, "alice", sub="9999"), app.config["JWT_SECRET"], algorithm="HS256")
    assert client.get("/api/me", headers=bearer(ghost)).status_code == 401


@pytest.mark.parametrize("header", ["", "Bearer", "Bearer ", "Basic abc123", "bearer lowercase.token.value", "Token abc.def.ghi"])
def test_T05_missing_or_malformed_authorization_header_is_rejected(client, alice, header):
    assert client.get("/api/me", headers={"Authorization": header}).status_code == 401


# ==================================================== T06 tampered stored data
def test_T06_edited_note_fails_the_integrity_check(app, client, alice):
    note = add_note(client, alice)
    con = db(app)
    enc = con.execute("SELECT content_enc FROM notes WHERE id=?", (note,)).fetchone()[0]
    con.execute("UPDATE notes SET content_enc=? WHERE id=?", (flip_last_byte(enc), note))
    con.commit()
    assert client.get(f"/api/vault/notes/{note}", headers=alice).status_code == 500
    assert "note_integrity_failure" in audit_events(app)


def test_T06_edited_image_file_fails_the_integrity_check(app, client, alice):
    image = add_image(client, alice)
    path = image_file(app, image)
    data = bytearray(open(path, "rb").read())
    data[20] ^= 1
    open(path, "wb").write(bytes(data))
    assert client.get(f"/api/vault/images/{image}", headers=alice).status_code == 500
    assert "image_integrity_failure" in audit_events(app)


def test_T06_edited_card_data_fails_the_integrity_check(app, client, alice):
    card = add_card(client, alice)
    con = db(app)
    enc = con.execute("SELECT payload_enc FROM cards WHERE id=?", (card,)).fetchone()[0]
    con.execute("UPDATE cards SET payload_enc=? WHERE id=?", (flip_last_byte(enc), card))
    con.commit()
    assert client.get(f"/api/vault/cards/{card}", headers=alice).status_code == 500
    assert client.post(f"/api/vault/cards/{card}/reveal", json={"password": PASSWORD}, headers=alice).status_code == 500
    assert "card_integrity_failure" in audit_events(app)


# ============================================ T07 ciphertext moved to another record
def test_T07_note_copied_to_another_users_row_cannot_be_read(app, client, alice, bob):
    a, b = add_note(client, alice), add_note(client, bob, content="bob's own text")
    con = db(app)
    enc = con.execute("SELECT content_enc FROM notes WHERE id=?", (a,)).fetchone()[0]
    con.execute("UPDATE notes SET content_enc=? WHERE id=?", (enc, b))
    con.commit()
    assert client.get(f"/api/vault/notes/{b}", headers=bob).status_code == 500


def test_T07_two_notes_of_the_same_user_cannot_be_swapped(app, client, alice):
    a, b = add_note(client, alice, "A", "content A"), add_note(client, alice, "B", "content B")
    con = db(app)
    enc = con.execute("SELECT content_enc FROM notes WHERE id=?", (a,)).fetchone()[0]
    con.execute("UPDATE notes SET content_enc=? WHERE id=?", (enc, b))
    con.commit()
    assert client.get(f"/api/vault/notes/{b}", headers=alice).status_code == 500


def test_T07_card_copied_to_another_users_row_cannot_be_read(app, client, alice, bob):
    a, b = add_card(client, alice), add_card(client, bob, "5555555555554444")
    con = db(app)
    enc = con.execute("SELECT payload_enc FROM cards WHERE id=?", (a,)).fetchone()[0]
    con.execute("UPDATE cards SET payload_enc=? WHERE id=?", (enc, b))
    con.commit()
    assert client.get(f"/api/vault/cards/{b}", headers=bob).status_code == 500


def test_T07_image_file_copied_to_another_users_record_cannot_be_read(app, client, alice, bob):
    a, b = add_image(client, alice, seed=1), add_image(client, bob, seed=2)
    open(image_file(app, b), "wb").write(open(image_file(app, a), "rb").read())
    assert client.get(f"/api/vault/images/{b}", headers=bob).status_code == 500


# ======================================================= T08 reading other users' data
def test_T08_another_user_gets_404_for_every_route_and_every_id(client, alice, bob):
    note, image, card = add_note(client, alice), add_image(client, alice), add_card(client, alice)
    for i in range(1, 6):  # includes the real ids and guesses around them
        assert client.get(f"/api/vault/notes/{i}", headers=bob).status_code == 404
        assert client.put(f"/api/vault/notes/{i}", json={"title": "x", "content": "hacked"}, headers=bob).status_code == 404
        assert client.delete(f"/api/vault/notes/{i}", headers=bob).status_code == 404
        assert client.get(f"/api/vault/images/{i}", headers=bob).status_code == 404
        assert client.delete(f"/api/vault/images/{i}", headers=bob).status_code == 404
        assert client.get(f"/api/vault/cards/{i}", headers=bob).status_code == 404
        assert client.delete(f"/api/vault/cards/{i}", headers=bob).status_code == 404
        assert client.post(f"/api/vault/cards/{i}/reveal", json={"password": PASSWORD}, headers=bob).status_code == 404
    for path in ("notes", "images", "cards"):
        assert list(client.get(f"/api/vault/{path}", headers=bob).json.values())[0] == []
    # alice's data survived all of that
    assert client.get(f"/api/vault/notes/{note}", headers=alice).json["content"] == NOTE_TEXT
    assert client.get(f"/api/vault/images/{image}", headers=alice).status_code == 200
    assert client.get(f"/api/vault/cards/{card}", headers=alice).status_code == 200


# =========================================================== T09 admin access
@pytest.mark.parametrize("path", ["/api/admin/logs", "/api/admin/users", "/api/admin/stats"])
def test_T09_normal_user_cannot_use_admin_routes(client, admin, alice, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers=alice).status_code == 403
    assert client.get(path, headers=admin).status_code == 200


def test_T09_claiming_the_admin_role_inside_a_real_token_does_not_work(app, client, alice):
    # Even a token signed with the REAL key and saying role=admin is not enough:
    # the role is always read from the database.
    claimed = create_token(user_id(app, "alice"), "admin", app.config["JWT_SECRET"], minutes=15)
    assert client.get("/api/admin/users", headers=bearer(claimed)).status_code == 403


def test_T09_blocked_admin_attempts_are_logged(app, client, alice):
    client.get("/api/admin/logs", headers=alice)
    assert "forbidden_access" in audit_events(app)


def test_T09_admin_screens_never_expose_secrets(client, admin, alice):
    enable_mfa(client, alice)
    text = client.get("/api/admin/users", headers=admin).get_data(as_text=True)
    assert "$argon2" not in text and "password_hash" not in text and "mfa_secret" not in text


# =========================================================== T10 repeated encryption
def test_T10_same_text_never_encrypts_to_the_same_output():
    key = os.urandom(32)
    outputs = {aes.encrypt_text(key, "identical text", "user:1") for _ in range(500)}
    assert len(outputs) == 500


def test_T10_every_encryption_uses_a_new_nonce():
    key = os.urandom(32)
    nonces = {base64.b64decode(aes.encrypt_text(key, "x", "a"))[:12] for _ in range(500)}
    assert len(nonces) == 500


def test_T10_the_encryption_key_is_256_bits(app):
    assert len(app.config["AES_KEY"]) == 32


# ======================================================== T11 face spoofing (deferred)
@pytest.mark.skip(reason="Face authentication is deferred; add liveness and spoof tests when Steps 12-13 are built")
def test_T11_printed_photo_is_rejected():
    raise AssertionError("not built yet")


# ======================================================== T12 card data leakage
def test_T12_cvv_is_never_stored(app, client, alice):
    r = client.post("/api/vault/cards", json=card_body(cvv="737"), headers=alice)
    assert r.status_code == 201 and "737" not in r.get_data(as_text=True) and "cvv" not in r.json
    columns = [c[1].lower() for c in db(app).execute("PRAGMA table_info(cards)")]
    assert not any("cvv" in c or "cvc" in c for c in columns)
    enc = db(app).execute("SELECT payload_enc FROM cards WHERE id=?", (r.json["id"],)).fetchone()[0]
    payload = json.loads(aes.decrypt_text(app.config["AES_KEY"], enc, f"card:{user_id(app, 'alice')}:{r.json['id']}"))
    assert set(payload) == {"number", "holder", "exp_month", "exp_year"}


def test_T12_card_numbers_are_masked_in_every_response(client, alice):
    created = client.post("/api/vault/cards", json=card_body(), headers=alice)
    card = created.json["id"]
    for response in (created, client.get("/api/vault/cards", headers=alice), client.get(f"/api/vault/cards/{card}", headers=alice)):
        assert PAN not in response.get_data(as_text=True)
    assert created.json["masked"] == "**** **** **** 4242"


def test_T12_card_data_never_reaches_the_audit_log(app, client, alice):
    card = add_card(client, alice)
    client.post(f"/api/vault/cards/{card}/reveal", json={"password": PASSWORD}, headers=alice)
    text = " ".join(f"{e} {u}" for e, u in db(app).execute("SELECT event, username FROM audit_log"))
    assert PAN not in text and HOLDER not in text and "4242" not in text


def test_T12_error_messages_do_not_echo_the_card_number(client, alice):
    r = client.post("/api/vault/cards", json=card_body("4242424242424241"), headers=alice)  # fails the checksum
    assert r.status_code == 400 and "4242424242424241" not in r.get_data(as_text=True)


def test_T12_invalid_and_expired_cards_are_refused(client, alice):
    assert client.post("/api/vault/cards", json=card_body("4242424242424241"), headers=alice).status_code == 400
    assert client.post("/api/vault/cards", json=card_body("abcd"), headers=alice).status_code == 400
    assert client.post("/api/vault/cards", json=card_body(exp_year=2020), headers=alice).status_code == 400
    assert client.post("/api/vault/cards", json=card_body(exp_month=13), headers=alice).status_code == 400


def test_T12_the_same_card_cannot_be_saved_twice(client, alice):
    assert client.post("/api/vault/cards", json=card_body("4242-4242-4242-4242"), headers=alice).status_code == 201
    assert client.post("/api/vault/cards", json=card_body("4242 4242 4242 4242"), headers=alice).status_code == 409


# ==================================================== T13 secrets committed to Git
SKIP_DIRS = {".git", ".secrets", "venv", ".venv", "__pycache__", "models", "uploads", "node_modules", ".pytest_cache"}
SKIP_SUFFIXES = (".db", ".pyc", ".zip", ".onnx", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".bin")


def repo_text_files(folders):
    for folder in folders:
        for current, dirs, files in os.walk(os.path.join(ROOT, folder)):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for name in files:
                if not name.endswith(SKIP_SUFFIXES):
                    path = os.path.join(current, name)
                    try:
                        yield path, open(path, encoding="utf-8").read()
                    except (UnicodeDecodeError, OSError):
                        continue


def test_T13_gitignore_keeps_secrets_and_data_out_of_git():
    path = os.path.join(ROOT, ".gitignore")
    assert os.path.exists(path), "There is no .gitignore in the project root"
    lines = {line.strip() for line in open(path, encoding="utf-8") if line.strip() and not line.startswith("#")}
    missing = [p for p in (".secrets/", "*.db", "uploads/", "venv/", ".env") if p not in lines]
    assert not missing, f"Add these lines to .gitignore: {missing}"


def test_T13_no_keys_or_passwords_are_written_in_the_source_code():
    patterns = [r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"AKIA[0-9A-Z]{16}",
                r"(?i)(jwt_secret|secret_key|aes_key|api_key)\s*=\s*[\"'][^\"']{6,}[\"']"]
    hits = [(os.path.relpath(p, ROOT), pat) for p, text in repo_text_files(["app", "scripts", "static", "templates"])
            for pat in patterns if re.search(pat, text)]
    assert not hits, f"Possible hard-coded secrets: {hits}"


def test_T13_your_real_keys_do_not_appear_in_any_project_file():
    secrets_dir = os.path.join(ROOT, ".secrets")
    if not os.path.isdir(secrets_dir):
        pytest.skip("No .secrets folder here yet (run the server once to create it)")
    needles = []
    for name in os.listdir(secrets_dir):
        key = open(os.path.join(secrets_dir, name), "rb").read()
        needles += [base64.b64encode(key).decode(), key.hex()]
    leaks = [os.path.relpath(p, ROOT) for p, text in repo_text_files(["app", "scripts", "static", "templates", "tests", "docs"])
             if any(n in text for n in needles)]
    assert not leaks, f"Your real key appears in: {leaks}"


def test_T13_key_folder_is_not_reachable_from_the_web(client):
    for path in ("/.secrets/jwt_secret", "/static/../.secrets/jwt_secret", "/securevault.db", "/static/%2e%2e/.secrets/vault_key"):
        r = client.get(path)
        assert r.status_code == 404


# ================================================================== T14 SQL injection
INJECTIONS = ["' OR '1'='1", "admin' --", "x'; DROP TABLE users; --", "\" OR \"\"=\"", "1; DELETE FROM notes"]


@pytest.mark.parametrize("payload", INJECTIONS)
def test_T14_login_cannot_be_bypassed_with_injection(client, alice, payload):
    assert login(client, payload, payload).status_code == 401
    assert login(client, "alice", payload).status_code == 401


@pytest.mark.parametrize("payload", INJECTIONS)
def test_T14_registration_refuses_injection_in_the_username(client, admin, payload):
    assert client.post("/api/register", json={"username": payload, "password": PASSWORD}).status_code == 400


@pytest.mark.parametrize("payload", INJECTIONS)
def test_T14_injection_text_in_notes_is_stored_and_returned_as_plain_text(app, client, alice, payload):
    note = add_note(client, alice, title=payload, content=payload)
    assert client.get(f"/api/vault/notes/{note}", headers=alice).json["title"] == payload
    tables = {r[0] for r in db(app).execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"users", "notes", "images", "cards", "audit_log"} <= tables


@pytest.mark.parametrize("payload", INJECTIONS)
def test_T14_admin_log_filters_are_safe(client, admin, payload):
    r = client.get("/api/admin/logs", query_string={"username": payload, "event": payload}, headers=admin)
    assert r.status_code == 200 and r.json["total"] == 0
    assert client.get("/api/admin/users", headers=admin).status_code == 200  # tables still exist


def test_T14_odd_ids_in_the_address_are_rejected(client, alice):
    for bad in ("1%20OR%201=1", "1;DROP%20TABLE%20notes", "-1", "abc"):
        assert client.get(f"/api/vault/notes/{bad}", headers=alice).status_code == 404


# ======================================================= T15 password reset abuse
@pytest.fixture()
def inbox(monkeypatch):
    issued = []
    monkeypatch.setattr(mailer, "send_reset_token", lambda username, token: issued.append((username, token)))
    return issued


def test_T15_forgot_password_does_not_reveal_which_accounts_exist(client, alice, inbox):
    real = client.post("/api/auth/password/forgot", json={"username": "alice"})
    fake = client.post("/api/auth/password/forgot", json={"username": "nobody"})
    assert real.status_code == fake.status_code == 200 and real.json == fake.json
    assert [u for u, _ in inbox] == ["alice"]


def test_T15_reset_token_is_stored_hashed_only(app, client, alice, inbox):
    client.post("/api/auth/password/forgot", json={"username": "alice"})
    token = inbox[-1][1]
    assert token not in "\n".join(db(app).iterdump())


def test_T15_reset_token_works_only_once(client, alice, inbox):
    client.post("/api/auth/password/forgot", json={"username": "alice"})
    token = inbox[-1][1]
    assert client.post("/api/auth/password/reset", json={"token": token, "new_password": "brand-new-long-password"}).status_code == 200
    assert client.post("/api/auth/password/reset", json={"token": token, "new_password": "yet-another-long-password"}).status_code == 400


def test_T15_expired_reset_token_is_refused(app, client, alice, inbox):
    client.post("/api/auth/password/forgot", json={"username": "alice"})
    con = db(app)
    con.execute("UPDATE password_resets SET expires_at = 0")
    con.commit()
    assert client.post("/api/auth/password/reset", json={"token": inbox[-1][1], "new_password": "brand-new-long-password"}).status_code == 400


def test_T15_guessed_reset_tokens_are_refused_and_limited(app, client, alice, inbox):
    app.config["RESET_ATTEMPTS_PER_WINDOW"] = 5
    codes = [client.post("/api/auth/password/reset", json={"token": f"guess-{i}", "new_password": "brand-new-long-password"}).status_code
             for i in range(7)]
    assert codes[:5] == [400] * 5 and codes[5:] == [429, 429]


def test_T15_reset_requests_are_rate_limited_the_same_for_every_username(client, alice):
    real = [client.post("/api/auth/password/forgot", json={"username": "alice"}).status_code for _ in range(5)]
    fake = [client.post("/api/auth/password/forgot", json={"username": "nobody"}).status_code for _ in range(5)]
    assert real == fake == [200, 200, 200, 429, 429]


def test_T15_resetting_the_password_does_not_switch_off_mfa(client, alice, inbox):
    secret = enable_mfa(client, alice)
    client.post("/api/auth/password/forgot", json={"username": "alice"})
    client.post("/api/auth/password/reset", json={"token": inbox[-1][1], "new_password": "brand-new-long-password"})
    r = login(client, "alice", "brand-new-long-password")
    assert r.status_code == 401 and r.json.get("mfa_required") is True
    assert login(client, "alice", "brand-new-long-password", totp=pyotp.TOTP(secret).now()).status_code == 200


# ================================================== T16 sessions that should be over
def test_T16_logout_ends_every_open_session(client, alice):
    other = bearer(login(client, "alice").json["token"])
    assert client.post("/api/logout", headers=alice).status_code == 200
    assert client.get("/api/me", headers=alice).status_code == 401
    assert client.get("/api/me", headers=other).status_code == 401


def test_T16_changing_the_password_ends_older_sessions(client, alice):
    other = bearer(login(client, "alice").json["token"])
    r = client.post("/api/auth/password/change", json={"current_password": PASSWORD, "new_password": "brand-new-long-password"}, headers=alice)
    assert r.status_code == 200
    assert client.get("/api/me", headers=alice).status_code == 401
    assert client.get("/api/me", headers=other).status_code == 401
    assert client.get("/api/me", headers=bearer(r.json["token"])).status_code == 200


def test_T16_resetting_the_password_ends_older_sessions(client, alice, inbox):
    client.post("/api/auth/password/forgot", json={"username": "alice"})
    client.post("/api/auth/password/reset", json={"token": inbox[-1][1], "new_password": "brand-new-long-password"})
    assert client.get("/api/me", headers=alice).status_code == 401


def test_T16_changing_a_password_needs_the_current_one(client, alice):
    r = client.post("/api/auth/password/change", json={"current_password": "wrong-password-xx", "new_password": "brand-new-long-password"}, headers=alice)
    assert r.status_code == 401
    assert client.get("/api/me", headers=alice).status_code == 200


# =============================================== T17 attacks through the browser
def test_T17_pages_carry_strict_browser_security_headers(client):
    for path in ("/", "/api/health", "/static/js/main.js"):
        h = client.get(path).headers
        csp = h.get("Content-Security-Policy", "")
        assert "script-src 'self'" in csp and "object-src 'none'" in csp and "frame-ancestors 'none'" in csp
        assert h.get("X-Content-Type-Options") == "nosniff" and h.get("X-Frame-Options") == "DENY"
        assert h.get("Referrer-Policy") == "no-referrer"


def test_T17_api_answers_are_never_cached(client, alice):
    for path in ("/api/me", "/api/vault/notes", "/api/vault/cards", "/api/vault/images"):
        assert client.get(path, headers=alice).headers.get("Cache-Control") == "no-store"


def test_T17_script_in_a_note_is_returned_as_data_not_as_a_page(client, alice):
    payload = "<script>alert(document.cookie)</script>"
    note = add_note(client, alice, title=payload, content=payload)
    r = client.get(f"/api/vault/notes/{note}", headers=alice)
    assert r.content_type.startswith("application/json") and r.json["content"] == payload


def test_T17_frontend_code_never_builds_html_from_text():
    banned = ["innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function", "localStorage"]
    found = [(os.path.basename(p), b) for p, text in repo_text_files(["static/js"]) for b in banned if b in text]
    assert not found, f"Unsafe patterns in the frontend: {found}"


def test_T17_html_page_has_no_inline_scripts_styles_or_handlers():
    html = open(os.path.join(ROOT, "templates", "index.html"), encoding="utf-8").read()
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>\s*\S", html)
    assert "<style" not in html and not re.search(r"\s(style|on[a-z]+)=", html)


def test_T17_uploads_must_be_real_images(client, alice):
    for name, data in (("evil.png", b"<html><script>alert(1)</script></html>"), ("x.jpg", b"just text"), ("e.png", b"")):
        r = client.post("/api/vault/images", data={"file": (io.BytesIO(data), name)}, headers=alice, content_type="multipart/form-data")
        assert r.status_code == 400
