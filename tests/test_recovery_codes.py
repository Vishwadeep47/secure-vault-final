"""MFA recovery codes: single-use backup codes for signing in when an
authenticator app is lost. See app.auth.mfa and the /api/mfa/recovery-codes*
routes in app/auth/routes.py."""
import pyotp

from tests.helpers import PASSWORD, db
from tests.test_threat_model import enable_mfa, login


def test_enabling_mfa_returns_recovery_codes(client, alice):
    secret = client.post("/api/mfa/setup", headers=alice).json["secret"]
    resp = client.post("/api/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=alice)
    codes = resp.json["recovery_codes"]
    assert len(codes) == 8
    assert len(set(codes)) == 8  # all distinct


def test_recovery_codes_are_never_stored_in_plaintext(app, client, alice):
    enable_mfa(client, alice)
    rows = db(app).execute("SELECT code_hash FROM recovery_codes").fetchall()
    assert len(rows) == 8
    for (code_hash,) in rows:
        assert len(code_hash) == 64  # a sha256 hex digest, not a plaintext code


def test_a_recovery_code_logs_in_without_the_authenticator_app(client, alice):
    code = _enable_and_get_codes(client, alice)[0]
    resp = login(client, "alice", PASSWORD, recovery_code=code)
    assert resp.status_code == 200
    assert "token" in resp.json


def test_a_recovery_code_cannot_be_used_twice(client, alice):
    code = _enable_and_get_codes(client, alice)[0]
    assert login(client, "alice", PASSWORD, recovery_code=code).status_code == 200
    second = login(client, "alice", PASSWORD, recovery_code=code)
    assert second.status_code == 401
    assert "error" in second.json


def test_an_unknown_recovery_code_is_rejected(client, alice):
    enable_mfa(client, alice)
    resp = login(client, "alice", PASSWORD, recovery_code="zzzzz-zzzzz")
    assert resp.status_code == 401


def test_recovery_code_login_does_not_need_the_totp_field(client, alice):
    """Supplying a recovery code is an alternative to the authenticator code,
    not an extra requirement on top of it."""
    codes = _enable_and_get_codes(client, alice)
    resp = client.post(
        "/api/login", json={"username": "alice", "password": PASSWORD, "recovery_code": codes[0]}
    )
    assert resp.status_code == 200


def test_recovery_code_status_reports_remaining_count(client, alice):
    _enable_and_get_codes(client, alice)
    resp = client.get("/api/mfa/recovery-codes", headers=alice)
    assert resp.json["remaining"] == 8


def test_using_a_recovery_code_reduces_the_remaining_count(client, alice):
    codes = _enable_and_get_codes(client, alice)
    login(client, "alice", PASSWORD, recovery_code=codes[0])
    resp = client.get("/api/mfa/recovery-codes", headers=alice)
    assert resp.json["remaining"] == 7


def test_regenerating_recovery_codes_needs_the_current_password(client, alice):
    _enable_and_get_codes(client, alice)
    resp = client.post("/api/mfa/recovery-codes/regenerate", json={"password": "totally-wrong"}, headers=alice)
    assert resp.status_code == 401


def test_regenerating_recovery_codes_invalidates_the_old_ones(client, alice):
    old_codes = _enable_and_get_codes(client, alice)
    resp = client.post("/api/mfa/recovery-codes/regenerate", json={"password": PASSWORD}, headers=alice)
    new_codes = resp.json["recovery_codes"]
    assert len(new_codes) == 8
    assert set(new_codes).isdisjoint(old_codes)

    # An old code no longer works.
    assert login(client, "alice", PASSWORD, recovery_code=old_codes[0]).status_code == 401
    # A new one does.
    assert login(client, "alice", PASSWORD, recovery_code=new_codes[0]).status_code == 200


def test_recovery_endpoints_require_mfa_to_be_enabled(client, alice):
    assert client.get("/api/mfa/recovery-codes", headers=alice).status_code == 400
    assert client.post("/api/mfa/recovery-codes/regenerate", json={"password": PASSWORD}, headers=alice).status_code == 400


def _enable_and_get_codes(client, headers):
    secret = client.post("/api/mfa/setup", headers=headers).json["secret"]
    resp = client.post("/api/mfa/enable", json={"code": pyotp.TOTP(secret).now()}, headers=headers)
    return resp.json["recovery_codes"]
