"""Shared test setup: a fresh app, database, and keys for every single test."""
import os
import sys

import pytest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), os.pardir))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from argon2 import PasswordHasher  # noqa: E402
from app import create_app  # noqa: E402
from app.auth import passwords  # noqa: E402
from app.security import ratelimit  # noqa: E402
from tests.helpers import PASSWORD, bearer  # noqa: E402

PRODUCTION_HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)

@pytest.fixture(autouse=True)
def fast_password_hashing(monkeypatch):
    """Argon2 is deliberately slow. Tests use cheaper settings so ~90 tests run in seconds.
    It is still Argon2id (the tests check that), only with a lower cost."""
    monkeypatch.setattr(passwords, "_hasher", PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1))


@pytest.fixture()
def app(tmp_path):
    ratelimit.clear_all()
    return create_app({
        "DB_PATH": str(tmp_path / "test.db"),
        "SECRETS_DIR": str(tmp_path / "secrets"),
        "UPLOAD_DIR": str(tmp_path / "uploads"),
        "RESET_ATTEMPTS_PER_WINDOW": 1000,
    })


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture()
def make_user(client):
    """make_user("name") registers and logs in; returns the Authorization header."""
    def _make(name, password=PASSWORD):
        assert client.post("/api/register", json={"username": name, "password": password}).status_code == 201
        token = client.post("/api/login", json={"username": name, "password": password}).json["token"]
        return bearer(token)
    return _make


@pytest.fixture()
def admin(make_user):
    return make_user("root")  # the first account is always the admin


@pytest.fixture()
def alice(admin, make_user):
    return make_user("alice")  # a normal user (the admin slot is already taken)


@pytest.fixture()
def bob(admin, make_user):
    return make_user("bob")
