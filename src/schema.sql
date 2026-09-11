PRAGMA foreign_keys = ON;
CREATE TABLE metadata (version INTEGER NOT NULL CHECK(version = 1), id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL);
CREATE TABLE zones (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, private_key TEXT NOT NULL, public_key TEXT NOT NULL,
 fingerprint TEXT NOT NULL, max_duration INTEGER NOT NULL CHECK(max_duration > 0), next_serial INTEGER NOT NULL DEFAULT 1,
 active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX zone_ca_public_key ON zones(public_key);
CREATE UNIQUE INDEX zone_ca_fingerprint ON zones(fingerprint);
CREATE TABLE zone_removals (zone_id TEXT PRIMARY KEY REFERENCES zones(id), removed_at INTEGER NOT NULL);
CREATE TABLE users (
 id TEXT PRIMARY KEY, name TEXT NOT NULL UNIQUE, active INTEGER NOT NULL DEFAULT 1, removed INTEGER NOT NULL DEFAULT 0,
 max_duration INTEGER NOT NULL CHECK(max_duration > 0), totp_secret TEXT, pending_secret TEXT, pending_expires INTEGER,
 last_step INTEGER NOT NULL DEFAULT -1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE TABLE access_tokens (
 id TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id), name TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1, removed INTEGER NOT NULL DEFAULT 0, max_duration INTEGER NOT NULL CHECK(max_duration > 0),
 key_id TEXT NOT NULL UNIQUE, digest BLOB NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
);
CREATE UNIQUE INDEX token_name ON access_tokens(user_id, name) WHERE removed = 0;
CREATE TABLE user_zones (user_id TEXT NOT NULL REFERENCES users(id), zone_id TEXT NOT NULL REFERENCES zones(id), PRIMARY KEY(user_id,zone_id));
CREATE TABLE admin_credentials (id TEXT PRIMARY KEY, key_id TEXT NOT NULL UNIQUE, digest BLOB NOT NULL, active INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
CREATE TABLE issued_certificates (
 zone_id TEXT NOT NULL REFERENCES zones(id), serial INTEGER NOT NULL, user_id TEXT NOT NULL REFERENCES users(id),
 token_id TEXT NOT NULL REFERENCES access_tokens(id), fingerprint TEXT NOT NULL, valid_after INTEGER NOT NULL,
 valid_before INTEGER NOT NULL, request_id TEXT NOT NULL UNIQUE, created_at INTEGER NOT NULL, PRIMARY KEY(zone_id,serial)
);
CREATE TABLE idempotency_records (
 actor TEXT NOT NULL, operation TEXT NOT NULL, request_id TEXT NOT NULL, payload_digest BLOB NOT NULL,
 auth_digest BLOB NOT NULL, response BLOB NOT NULL, secret_response INTEGER NOT NULL, expires_at INTEGER NOT NULL,
 PRIMARY KEY(actor,operation,request_id)
);
CREATE TABLE audit_events (
 id TEXT PRIMARY KEY, actor_type TEXT NOT NULL, actor_id TEXT NOT NULL, operation TEXT NOT NULL,
 result TEXT NOT NULL, request_id TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE INDEX idempotency_expiry ON idempotency_records(expires_at);
