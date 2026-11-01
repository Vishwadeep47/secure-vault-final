"""SQLite connection and table definitions."""
import sqlite3

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    mfa_secret TEXT,
    mfa_enabled INTEGER NOT NULL DEFAULT 0,
    token_version INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    key_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    original_name TEXT NOT NULL,
    mime TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    key_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS cards (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT NOT NULL UNIQUE,
    label TEXT NOT NULL,
    brand TEXT NOT NULL,
    last4 TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    payload_enc TEXT NOT NULL,
    key_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    UNIQUE (user_id, fingerprint),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at INTEGER NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    event TEXT NOT NULL,
    username TEXT,
    ip TEXT,
    prev_hash TEXT,
    hash TEXT
);

-- Each user's own data key, wrapped (encrypted) by the server master key.
-- A user can have more than one row here: rotating the key adds a new
-- version instead of replacing the old one, so old backups stay readable.
CREATE TABLE IF NOT EXISTS user_keys (
    user_id INTEGER NOT NULL,
    version INTEGER NOT NULL,
    wrapped_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (user_id, version),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- MFA recovery codes: single-use, stored only as a hash.
CREATE TABLE IF NOT EXISTS recovery_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    code_hash TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Login lockouts and request counters, kept in the database so a server
-- restart cannot reset an attack that is in progress.
CREATE TABLE IF NOT EXISTS login_failures (
    username TEXT PRIMARY KEY,
    count INTEGER NOT NULL,
    first_failure_at REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_hits (
    rkey TEXT NOT NULL,
    ts REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_hits_rkey ON rate_hits(rkey);
"""


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DB_PATH"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _add_column_if_missing(db, table, column, ddl):
    columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        db.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def _migrate(db):
    """Add columns that databases from earlier versions are missing."""
    _add_column_if_missing(db, "users", "token_version", "token_version INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(db, "users", "disabled", "disabled INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(db, "users", "key_version", "key_version INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(db, "images", "key_version", "key_version INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(db, "cards", "key_version", "key_version INTEGER NOT NULL DEFAULT 0")
    _add_column_if_missing(db, "audit_log", "prev_hash", "prev_hash TEXT")
    _add_column_if_missing(db, "audit_log", "hash", "hash TEXT")


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    _migrate(db)
    db.commit()


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
