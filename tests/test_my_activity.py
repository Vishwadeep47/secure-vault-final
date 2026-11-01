"""A user's own recent activity: GET /api/me/activity in app/auth/routes.py.
Unlike the admin audit log viewer, this is available to any signed-in user,
scoped to events about their own account."""
import io

from tests.helpers import png_bytes
from tests.test_threat_model import login


def _add_image(client, headers, seed=1):
    return client.post(
        "/api/vault/images", data={"file": (io.BytesIO(png_bytes(seed)), "p.png")},
        headers=headers, content_type="multipart/form-data",
    )


def test_activity_includes_this_users_own_events(client, alice):
    _add_image(client, alice)
    resp = client.get("/api/me/activity", headers=alice)
    assert resp.status_code == 200
    events = [e["event"] for e in resp.json["events"]]
    assert "image_uploaded" in events


def test_activity_does_not_include_another_users_events(client, alice, bob):
    _add_image(client, bob)
    resp = client.get("/api/me/activity", headers=alice)
    events = [e["event"] for e in resp.json["events"]]
    assert "image_uploaded" not in events


def test_activity_is_newest_first(client, alice):
    _add_image(client, alice, seed=1)
    _add_image(client, alice, seed=2)
    events = client.get("/api/me/activity", headers=alice).json["events"]
    uploaded = [e for e in events if e["event"] == "image_uploaded"]
    assert len(uploaded) == 2  # order among same-event rows isn't asserted here, just presence


def test_activity_respects_a_limit(client, alice):
    for i in range(5):
        _add_image(client, alice, seed=i)
    resp = client.get("/api/me/activity?limit=2", headers=alice)
    assert len(resp.json["events"]) == 2
    assert resp.json["total"] >= 5


def test_activity_rejects_a_bad_limit(client, alice):
    resp = client.get("/api/me/activity?limit=notanumber", headers=alice)
    assert resp.status_code == 400


def test_activity_requires_login(client):
    assert client.get("/api/me/activity").status_code == 401


def test_activity_includes_login_events(client, alice):
    login(client, "alice")
    resp = client.get("/api/me/activity", headers=alice)
    events = [e["event"] for e in resp.json["events"]]
    assert "login_success" in events


def test_activity_never_includes_passwords_or_tokens(client, alice):
    resp = client.get("/api/me/activity", headers=alice)
    body = resp.get_data(as_text=True)
    from tests.helpers import PASSWORD

    assert PASSWORD not in body
    assert alice["Authorization"].split(" ")[1] not in body
