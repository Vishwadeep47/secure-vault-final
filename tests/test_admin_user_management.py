"""Admin controls over other accounts: disable, re-enable, and clear a lockout
without touching the password. See the new routes in app/admin/routes.py."""
from tests.helpers import PASSWORD
from tests.test_threat_model import login


def _user_id(client, admin, username):
    users = client.get("/api/admin/users", headers=admin).json["users"]
    return next(u["id"] for u in users if u["username"] == username)


def test_a_normal_user_cannot_disable_anyone(client, alice, bob):
    resp = client.post("/api/admin/users/1/disable", headers=alice)
    assert resp.status_code == 403


def test_admin_can_disable_a_user(client, admin, alice):
    alice_id = _user_id(client, admin, "alice")
    resp = client.post(f"/api/admin/users/{alice_id}/disable", headers=admin)
    assert resp.status_code == 200
    assert login(client, "alice", PASSWORD).status_code == 403


def test_disabling_a_user_ends_their_open_session_immediately(client, admin, alice):
    alice_id = _user_id(client, admin, "alice")
    assert client.get("/api/me", headers=alice).status_code == 200
    client.post(f"/api/admin/users/{alice_id}/disable", headers=admin)
    assert client.get("/api/me", headers=alice).status_code == 401


def test_admin_can_re_enable_a_disabled_user(client, admin, alice):
    alice_id = _user_id(client, admin, "alice")
    client.post(f"/api/admin/users/{alice_id}/disable", headers=admin)
    client.post(f"/api/admin/users/{alice_id}/enable", headers=admin)
    assert login(client, "alice", PASSWORD).status_code == 200


def test_admin_cannot_disable_their_own_account(client, admin):
    admin_id = _user_id(client, admin, "root")
    resp = client.post(f"/api/admin/users/{admin_id}/disable", headers=admin)
    assert resp.status_code == 400


def test_disabling_an_unknown_user_is_a_404(client, admin):
    assert client.post("/api/admin/users/99999/disable", headers=admin).status_code == 404


def test_user_list_reports_disabled_state(client, admin, alice):
    alice_id = _user_id(client, admin, "alice")
    client.post(f"/api/admin/users/{alice_id}/disable", headers=admin)
    users = client.get("/api/admin/users", headers=admin).json["users"]
    row = next(u for u in users if u["username"] == "alice")
    assert row["disabled"] is True


def test_admin_can_unlock_a_locked_out_account(client, admin, alice):
    for _ in range(5):
        login(client, "alice", "wrong-password")
    assert login(client, "alice", PASSWORD).status_code == 429

    alice_id = _user_id(client, admin, "alice")
    resp = client.post(f"/api/admin/users/{alice_id}/unlock", headers=admin)
    assert resp.status_code == 200
    assert login(client, "alice", PASSWORD).status_code == 200


def test_unlock_does_not_disable_the_account(client, admin, alice):
    alice_id = _user_id(client, admin, "alice")
    client.post(f"/api/admin/users/{alice_id}/unlock", headers=admin)
    assert login(client, "alice", PASSWORD).status_code == 200
