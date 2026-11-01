"""User-to-user messages: app/chat/messages.py.
Messages are AES-256-GCM encrypted at rest, bound (via associated data) to
the conversation pair and the message's own id - the same pattern used for
every other encrypted record in this project (see docs/threat_model.md)."""
from tests.helpers import PASSWORD, db


def send(client, headers, to, body="hello there"):
    return client.post(f"/api/chat/messages/{to}", json={"body": body}, headers=headers)


# --------------------------------------------------------------- basic flow
def test_sending_and_reading_a_message_round_trips(client, alice, bob):
    assert send(client, alice, "bob", "hi bob").status_code == 201
    resp = client.get("/api/chat/messages/bob", headers=alice)
    assert resp.status_code == 200
    bodies = [m["body"] for m in resp.json["messages"]]
    assert "hi bob" in bodies


def test_the_recipient_sees_the_same_message(client, alice, bob):
    send(client, alice, "bob", "hi bob")
    resp = client.get("/api/chat/messages/alice", headers=bob)
    msgs = resp.json["messages"]
    assert len(msgs) == 1 and msgs[0]["body"] == "hi bob" and msgs[0]["from_me"] is False


def test_sending_requires_login(client):
    assert client.post("/api/chat/messages/bob", json={"body": "hi"}).status_code == 401


def test_reading_requires_login(client):
    assert client.get("/api/chat/messages/bob").status_code == 401


def test_cannot_message_yourself(client, alice):
    assert send(client, alice, "alice").status_code == 400


def test_messaging_a_nonexistent_user_is_404(client, alice):
    assert send(client, alice, "nobody").status_code == 404


def test_empty_message_is_rejected(client, alice, bob):
    assert send(client, alice, "bob", "   ").status_code == 400


def test_oversized_message_is_rejected(client, alice, bob):
    assert send(client, alice, "bob", "x" * 2001).status_code == 400


def test_the_largest_allowed_message_still_works(client, alice, bob):
    assert send(client, alice, "bob", "x" * 2000).status_code == 201


# ------------------------------------------------------------ data at rest
def test_message_body_is_encrypted_in_the_database(app, client, alice, bob):
    send(client, alice, "bob", "a very secret message")
    row = db(app).execute("SELECT body_enc FROM messages").fetchone()[0]
    assert b"a very secret message" not in row.encode()


def test_tampered_message_fails_the_integrity_check(app, client, alice, bob):
    from tests.helpers import flip_last_byte

    send(client, alice, "bob")
    con = db(app)
    enc = con.execute("SELECT body_enc FROM messages").fetchone()[0]
    con.execute("UPDATE messages SET body_enc = ?", (flip_last_byte(enc),))
    con.commit()
    assert client.get("/api/chat/messages/bob", headers=alice).status_code == 500


# -------------------------------------------------------- isolation between pairs
def test_a_third_user_cannot_see_someone_elses_conversation(client, admin, alice, bob, make_user):
    carol = make_user("carol")
    send(client, alice, "bob", "a secret between alice and bob")
    resp = client.get("/api/chat/messages/bob", headers=carol)
    assert resp.status_code == 200 and resp.json["messages"] == []


# --------------------------------------------------------------- polling
def test_after_only_returns_newer_messages(client, alice, bob):
    first = send(client, alice, "bob", "one").json["id"]
    send(client, alice, "bob", "two")
    resp = client.get(f"/api/chat/messages/bob?after={first}", headers=alice)
    bodies = [m["body"] for m in resp.json["messages"]]
    assert bodies == ["two"]


# --------------------------------------------------------- rate limiting
def test_sending_too_fast_is_rate_limited(app, client, alice, bob):
    limit = app.config["MESSAGE_SEND_LIMIT"]
    for _ in range(limit):
        assert send(client, alice, "bob").status_code == 201
    assert send(client, alice, "bob").status_code == 429


# --------------------------------------------------------------- deleting
def test_sender_can_delete_their_own_message(client, alice, bob):
    message_id = send(client, alice, "bob").json["id"]
    assert client.delete(f"/api/chat/messages/{message_id}", headers=alice).status_code == 200
    assert client.get("/api/chat/messages/bob", headers=alice).json["messages"] == []


def test_recipient_cannot_delete_a_message_they_did_not_send(client, alice, bob):
    message_id = send(client, alice, "bob").json["id"]
    assert client.delete(f"/api/chat/messages/{message_id}", headers=bob).status_code == 404


# --------------------------------------------------------- users / conversations
def test_user_directory_excludes_me_and_disabled_accounts(client, admin, alice, bob):
    resp = client.get("/api/chat/users", headers=alice)
    names = resp.json["users"]
    assert "alice" not in names and "bob" in names

    client.post("/api/admin/users/2/disable", headers=admin)  # alice is id 2 (admin is id 1)
    resp = client.get("/api/chat/users", headers=bob)
    assert "alice" not in resp.json["users"]


def test_conversations_list_shows_the_latest_preview(client, alice, bob):
    send(client, alice, "bob", "first")
    send(client, bob, "alice", "second")
    conv = client.get("/api/chat/conversations", headers=alice).json["conversations"]
    assert len(conv) == 1
    assert conv[0]["username"] == "bob"
    assert conv[0]["preview"] == "second"
    assert conv[0]["last_from_me"] is False


# --------------------------------------------------------------- audit log
def test_sending_a_message_is_audit_logged_without_the_content(app, client, alice, bob):
    send(client, alice, "bob", "the secret payload")
    rows = db(app).execute("SELECT event FROM audit_log").fetchall()
    events = {r[0] for r in rows}
    assert "message_sent" in events

    text = client.get("/api/me/activity", headers=alice).get_data(as_text=True)
    assert "the secret payload" not in text and PASSWORD not in text
