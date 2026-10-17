-- DEV relay only. No plaintext profile, schedule, inventory, or key material.
PRAGMA foreign_keys = ON;
CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE CHECK(length(token_hash) = 64),
  expires_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK(revoked IN (0,1))
);
CREATE TABLE groups (
  id TEXT PRIMARY KEY,
  revision INTEGER NOT NULL DEFAULT 0 CHECK(revision >= 0)
);
CREATE TABLE group_members (
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  PRIMARY KEY(group_id, device_id)
);
CREATE TABLE events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
  event_id TEXT NOT NULL,
  sender_device_id TEXT NOT NULL REFERENCES devices(id),
  revision INTEGER NOT NULL,
  ciphertext TEXT NOT NULL CHECK(length(ciphertext) BETWEEN 4 AND 65536),
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  UNIQUE(group_id, revision),
  UNIQUE(group_id, event_id)
);
CREATE INDEX events_expiry ON events(expires_at);
CREATE TRIGGER advance_group_revision AFTER INSERT ON events
BEGIN
  UPDATE groups SET revision = NEW.revision WHERE id = NEW.group_id;
END;
