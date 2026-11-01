"""Per-user data-encryption keys: every account gets its own key for images
and cards instead of sharing the server's master key. See
app/crypto/userkeys.py and POST /api/encryption-key/rotate."""
from app.crypto import userkeys
from tests.helpers import PASSWORD, card_body, db


def test_a_new_account_is_issued_its_own_key(app, client, alice):
    row = db(app).execute("SELECT key_version FROM users WHERE username='alice'").fetchone()
    assert row[0] == 1  # version 1: a personal key, not the server master key (version 0)


def test_the_personal_key_is_not_the_server_master_key(app, client, alice):
    uid = db(app).execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
    with app.app_context():
        key, version = userkeys.current_key(uid)
    assert version == 1
    assert key != app.config["AES_KEY"]


def test_a_card_is_tagged_with_the_key_version_used(app, client, alice):
    client.post("/api/vault/cards", json=card_body(), headers=alice)
    row = db(app).execute("SELECT key_version FROM cards").fetchone()
    assert row[0] == 1


def test_an_image_is_tagged_with_the_key_version_used(app, client, alice):
    import io

    from tests.helpers import png_bytes

    client.post(
        "/api/vault/images", data={"file": (io.BytesIO(png_bytes(1)), "p.png")},
        headers=alice, content_type="multipart/form-data",
    )
    row = db(app).execute("SELECT key_version FROM images").fetchone()
    assert row[0] == 1


def test_data_round_trips_through_the_api_normally(client, alice):
    """The point of the feature should be invisible day to day: create, then read back."""
    card_id = client.post("/api/vault/cards", json=card_body(), headers=alice).json["id"]
    resp = client.get(f"/api/vault/cards/{card_id}", headers=alice)
    assert resp.json["holder"] == card_body()["holder_name"]


def test_rotating_the_key_needs_the_current_password(client, alice):
    resp = client.post("/api/encryption-key/rotate", json={"password": "wrong"}, headers=alice)
    assert resp.status_code == 401


def test_rotating_the_key_issues_a_new_version(app, client, alice):
    resp = client.post("/api/encryption-key/rotate", json={"password": PASSWORD}, headers=alice)
    assert resp.status_code == 200
    assert resp.json["key_version"] == 2
    row = db(app).execute("SELECT key_version FROM users WHERE username='alice'").fetchone()
    assert row[0] == 2


def test_items_written_before_a_rotation_still_decrypt_afterwards(client, alice):
    card_id = client.post(
        "/api/vault/cards", json=card_body(number="4242424242424242"), headers=alice
    ).json["id"]
    client.post("/api/encryption-key/rotate", json={"password": PASSWORD}, headers=alice)

    resp = client.get(f"/api/vault/cards/{card_id}", headers=alice)
    assert resp.status_code == 200
    assert resp.json["holder"] == card_body()["holder_name"]


def test_items_written_after_a_rotation_use_the_new_version(app, client, alice):
    client.post("/api/encryption-key/rotate", json={"password": PASSWORD}, headers=alice)
    client.post("/api/vault/cards", json=card_body(number="5555555555554444", label="after-rotation"), headers=alice)
    row = db(app).execute(
        "SELECT key_version FROM cards WHERE label = 'after-rotation'"
    ).fetchone()
    assert row[0] == 2


def test_old_data_that_predates_this_feature_still_decrypts(app, client, alice):
    """A record inserted directly with key_version 0 (what every record used
    to be, before per-user keys existed) must still decrypt with the server
    master key, with no migration needed."""
    import json
    from datetime import datetime, timezone

    from app.crypto import aes

    uid = db(app).execute("SELECT id FROM users WHERE username='alice'").fetchone()[0]
    payload = json.dumps({"number": "4000000000000002", "holder": "Legacy Holder", "exp_month": 12, "exp_year": 2030})
    with app.app_context():
        encrypted = aes.encrypt_text(app.config["AES_KEY"], payload, f"card:{uid}:999999")
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    conn = db(app)
    conn.execute(
        "INSERT INTO cards (id, user_id, token, label, brand, last4, fingerprint, payload_enc, key_version, created_at) "
        "VALUES (999999, ?, 'tok_legacy', 'Legacy card', 'visa', '0002', 'legacy-fp', ?, 0, ?)",
        (uid, encrypted, now),
    )
    conn.commit()
    conn.close()

    resp = client.get("/api/vault/cards/999999", headers=alice)
    assert resp.status_code == 200
    assert resp.json["holder"] == "Legacy Holder"
