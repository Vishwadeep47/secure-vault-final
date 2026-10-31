"""Password rules (NIST SP 800-63B style): length first, then a common-password
blocklist and a check against the username. See app/security/password_policy.py."""
from app.security.password_policy import password_error
from tests.helpers import PASSWORD


def test_unit_long_unusual_password_is_fine(app):
    with app.app_context():
        assert password_error(PASSWORD) is None


def test_unit_too_short_password_is_rejected(app):
    with app.app_context():
        assert password_error("short1") is not None


def test_unit_common_password_is_rejected_even_if_long_enough(app):
    with app.app_context():
        assert password_error("administrator") is not None  # 13 chars, meets the length bar


def test_unit_common_password_check_is_case_insensitive(app):
    with app.app_context():
        assert password_error("Administrator") is not None


def test_unit_password_matching_username_is_rejected(app):
    with app.app_context():
        assert password_error("alice-is-great", username="alice-is-great") is not None


def test_register_rejects_common_password(client):
    resp = client.post("/api/register", json={"username": "newbie", "password": "administrator"})
    assert resp.status_code == 400
    assert "common" in resp.json["error"].lower()


def test_register_accepts_a_long_uncommon_password(client):
    resp = client.post("/api/register", json={"username": "newbie", "password": PASSWORD})
    assert resp.status_code == 201


def test_change_password_rejects_common_password(make_user, client):
    from tests.helpers import PASSWORD as CURRENT

    auth = make_user("carol")
    resp = client.post(
        "/api/auth/password/change",
        json={"current_password": CURRENT, "new_password": "administrator"},
        headers=auth,
    )
    assert resp.status_code == 400
    assert "common" in resp.json["error"].lower()


def test_reset_password_rejects_common_password(client, monkeypatch):
    from app.security import mailer

    issued = []
    monkeypatch.setattr(mailer, "send_reset_token", lambda username, token: issued.append((username, token)))

    client.post("/api/register", json={"username": "dave", "password": PASSWORD})
    client.post("/api/auth/password/forgot", json={"username": "dave"})
    token = issued[-1][1]

    resp = client.post("/api/auth/password/reset", json={"token": token, "new_password": "administrator"})
    assert resp.status_code == 400
    assert "common" in resp.json["error"].lower()
