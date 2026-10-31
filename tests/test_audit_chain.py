"""Tamper-evident audit log: each row is hash-chained to the one before it.
See app/security/audit.py and GET /api/admin/logs/verify."""
from tests.helpers import db


def test_chain_starts_valid_on_a_fresh_log(client, admin):
    resp = client.get("/api/admin/logs/verify", headers=admin)
    assert resp.status_code == 200
    assert resp.json["ok"] is True
    assert resp.json["broken_at"] is None


def test_chain_stays_valid_after_normal_activity(client, admin, alice, bob):
    client.post("/api/vault/notes", json={"title": "t", "content": "c"}, headers=alice)
    client.post("/api/logout", headers=bob)
    resp = client.get("/api/admin/logs/verify", headers=admin)
    assert resp.json["ok"] is True
    assert resp.json["checked"] > 0


def test_editing_a_logged_event_breaks_the_chain(app, client, admin):
    conn = db(app)
    row = conn.execute("SELECT id FROM audit_log ORDER BY id ASC LIMIT 1").fetchone()
    conn.execute("UPDATE audit_log SET event = 'something_else' WHERE id = ?", (row[0],))
    conn.commit()
    conn.close()

    resp = client.get("/api/admin/logs/verify", headers=admin)
    assert resp.json["ok"] is False
    assert resp.json["broken_at"] == row[0]


def test_deleting_a_logged_event_breaks_the_chain(app, client, admin, alice):
    client.post("/api/vault/notes", json={"title": "t", "content": "c"}, headers=alice)

    conn = db(app)
    rows = conn.execute("SELECT id FROM audit_log ORDER BY id ASC").fetchall()
    middle_id = rows[len(rows) // 2][0]
    conn.execute("DELETE FROM audit_log WHERE id = ?", (middle_id,))
    conn.commit()
    conn.close()

    resp = client.get("/api/admin/logs/verify", headers=admin)
    assert resp.json["ok"] is False


def test_inserting_a_forged_row_breaks_the_chain(app, client, admin):
    conn = db(app)
    conn.execute(
        "INSERT INTO audit_log (ts, event, username, ip, prev_hash, hash) "
        "VALUES ('2020-01-01T00:00:00', 'forged', 'nobody', '0.0.0.0', 'made-up', 'made-up')"
    )
    conn.commit()
    conn.close()

    resp = client.get("/api/admin/logs/verify", headers=admin)
    assert resp.json["ok"] is False


def test_legacy_rows_with_no_hash_do_not_count_as_broken(app, client, admin):
    """A database upgraded from before this feature existed has old rows with
    no hash at all. Those predate the chain and should not trip verification."""
    conn = db(app)
    conn.execute(
        "INSERT INTO audit_log (ts, event, username, ip, prev_hash, hash) "
        "VALUES ('2020-01-01T00:00:00', 'ancient_event', 'someone', '0.0.0.0', NULL, NULL)"
    )
    conn.commit()
    conn.close()

    resp = client.get("/api/admin/logs/verify", headers=admin)
    assert resp.json["ok"] is True


def test_only_admins_can_verify_the_chain(client, alice):
    assert client.get("/api/admin/logs/verify", headers=alice).status_code == 403
