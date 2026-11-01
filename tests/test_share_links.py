"""One-time, expiring links to view a single note without logging in.
See the /share routes in app/vault/notes.py."""
import time

from tests.helpers import db


def _add_note(client, headers, content="shared secret"):
    return client.post("/api/vault/notes", json={"title": "t", "content": content}, headers=headers).json["id"]


def test_creating_a_share_link_returns_a_token(client, alice):
    note_id = _add_note(client, alice)
    resp = client.post(f"/api/vault/notes/{note_id}/share", headers=alice)
    assert resp.status_code == 201
    assert len(resp.json["token"]) > 20
    assert resp.json["minutes"] == 60


def test_only_the_owner_can_create_a_share_link(client, alice, bob):
    note_id = _add_note(client, alice)
    resp = client.post(f"/api/vault/notes/{note_id}/share", headers=bob)
    assert resp.status_code == 404


def test_the_raw_token_is_never_stored(app, client, alice):
    note_id = _add_note(client, alice)
    token = client.post(f"/api/vault/notes/{note_id}/share", headers=alice).json["token"]
    (stored,) = db(app).execute("SELECT token_hash FROM share_links WHERE note_id = ?", (note_id,)).fetchone()
    assert token not in stored
    assert len(stored) == 64  # a sha256 hex digest


def test_a_valid_token_shows_the_note_content_without_login(client, alice):
    note_id = _add_note(client, alice, content="viewable once")
    token = client.post(f"/api/vault/notes/{note_id}/share", headers=alice).json["token"]
    resp = client.get(f"/api/vault/notes/share/{token}")
    assert resp.status_code == 200
    assert resp.json["content"] == "viewable once"


def test_a_token_can_only_be_used_once(client, alice):
    note_id = _add_note(client, alice)
    token = client.post(f"/api/vault/notes/{note_id}/share", headers=alice).json["token"]
    assert client.get(f"/api/vault/notes/share/{token}").status_code == 200
    second = client.get(f"/api/vault/notes/share/{token}")
    assert second.status_code == 404


def test_an_unknown_token_is_rejected(client):
    resp = client.get("/api/vault/notes/share/not-a-real-token")
    assert resp.status_code == 404


def test_an_expired_token_is_rejected(app, client, alice):
    note_id = _add_note(client, alice)
    token = client.post(f"/api/vault/notes/{note_id}/share", headers=alice).json["token"]
    conn = db(app)
    conn.execute("UPDATE share_links SET expires_at = ? WHERE note_id = ?", (time.time() - 10, note_id))
    conn.commit()
    conn.close()
    resp = client.get(f"/api/vault/notes/share/{token}")
    assert resp.status_code == 404


def test_creating_a_new_share_link_replaces_the_old_one(client, alice):
    note_id = _add_note(client, alice)
    old_token = client.post(f"/api/vault/notes/{note_id}/share", headers=alice).json["token"]
    client.post(f"/api/vault/notes/{note_id}/share", headers=alice)
    assert client.get(f"/api/vault/notes/share/{old_token}").status_code == 404


def test_owner_can_revoke_a_share_link_before_it_is_used(client, alice):
    note_id = _add_note(client, alice)
    token = client.post(f"/api/vault/notes/{note_id}/share", headers=alice).json["token"]
    assert client.delete(f"/api/vault/notes/{note_id}/share", headers=alice).status_code == 200
    assert client.get(f"/api/vault/notes/share/{token}").status_code == 404


def test_share_status_reports_whether_a_link_is_active(client, alice):
    note_id = _add_note(client, alice)
    assert client.get(f"/api/vault/notes/{note_id}/share", headers=alice).json["active"] is False
    client.post(f"/api/vault/notes/{note_id}/share", headers=alice)
    assert client.get(f"/api/vault/notes/{note_id}/share", headers=alice).json["active"] is True


def test_share_status_is_inactive_after_the_link_is_used(client, alice):
    note_id = _add_note(client, alice)
    token = client.post(f"/api/vault/notes/{note_id}/share", headers=alice).json["token"]
    client.get(f"/api/vault/notes/share/{token}")
    assert client.get(f"/api/vault/notes/{note_id}/share", headers=alice).json["active"] is False


def test_the_shared_view_never_includes_the_owners_username(client, alice):
    note_id = _add_note(client, alice)
    token = client.post(f"/api/vault/notes/{note_id}/share", headers=alice).json["token"]
    resp = client.get(f"/api/vault/notes/share/{token}")
    assert "alice" not in resp.get_data(as_text=True)
