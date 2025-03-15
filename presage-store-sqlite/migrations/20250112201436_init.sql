CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL);

-- protocol
CREATE TABLE IF NOT EXISTS sessions (
  address TEXT NOT NULL,
  device_id INTEGER NOT NULL,
  identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
  record BLOB NOT NULL,
  PRIMARY KEY (address, device_id, identity)
);

CREATE TABLE IF NOT EXISTS identities (
  address TEXT NOT NULL,
  device_id INTEGER NOT NULL,
  identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
  record BLOB NOT NULL,
  PRIMARY KEY (address, device_id, identity)
);

CREATE TABLE IF NOT EXISTS pre_keys (
  id INTEGER NOT NULL,
  identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
  record BLOB NOT NULL,
  PRIMARY KEY (id, identity)
);

CREATE TABLE IF NOT EXISTS signed_pre_keys (
  id INTEGER NOT NULL,
  identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
  record BLOB NOT NULL,
  PRIMARY KEY (id, identity)
);

CREATE TABLE IF NOT EXISTS kyber_pre_keys (
  id INTEGER NOT NULL,
  identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
  record BLOB NOT NULL,
  is_last_resort INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (id, identity)
);

CREATE TABLE IF NOT EXISTS sender_keys (
  address TEXT NOT NULL,
  device_id INTEGER NOT NULL,
  identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
  distribution_id TEXT NOT NULL,
  record BLOB NOT NULL,
  PRIMARY KEY (address, device_id, identity, distribution_id)
);

-- content
CREATE TABLE IF NOT EXISTS contacts (
  uuid BLOB NOT NULL PRIMARY KEY,
  phone_number TEXT,
  name TEXT NOT NULL,
  color TEXT,
  profile_key BLOB NOT NULL,
  expire_timer INTEGER NOT NULL,
  expire_timer_version INTEGER NOT NULL DEFAULT 2,
  inbox_position INTEGER NOT NULL,
  archived BOOLEAN NOT NULL,
  avatar BLOB
);

CREATE TABLE IF NOT EXISTS contacts_verification_state (
  destination_aci BLOB NOT NULL PRIMARY KEY,
  identity_key BLOB NOT NULL,
  is_verified BOOLEAN,
  FOREIGN KEY (destination_aci) REFERENCES contacts (uuid) ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS profile_keys (uuid BLOB NOT NULL PRIMARY KEY, key BLOB NOT NULL);

CREATE TABLE IF NOT EXISTS profiles (
  uuid BLOB NOT NULL PRIMARY KEY,
  given_name TEXT,
  family_name TEXT,
  about TEXT,
  about_emoji TEXT,
  avatar TEXT,
  unrestricted_unidentified_access BOOLEAN NOT NULL DEFAULT 0,
  FOREIGN KEY (uuid) REFERENCES profile_keys (uuid) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS profile_avatars (
  uuid BLOB NOT NULL PRIMARY KEY,
  bytes BLOB NOT NULL,
  FOREIGN KEY (uuid) REFERENCES profile_keys (uuid) ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS groups (
  master_key BLOB NOT NULL PRIMARY KEY,
  title TEXT NOT NULL,
  revision INTEGER NOT NULL DEFAULT 0,
  invite_link_password BLOB,
  access_control BLOB,
  avatar TEXT NOT NULL,
  description TEXT,
  members BLOB NOT NULL,
  pending_members BLOB NOT NULL,
  requesting_members BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS group_avatars (
  group_master_key BLOB PRIMARY KEY,
  bytes BLOB NOT NULL,
  FOREIGN KEY (group_master_key) REFERENCES groups (master_key) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS threads (
  id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
  group_master_key BLOB UNIQUE,
  recipient_id TEXT UNIQUE
);

CREATE TABLE IF NOT EXISTS thread_messages (
  ts INTEGER NOT NULL,
  thread_id INTEGER NOT NULL,
  sender_service_id TEXT NOT NULL,
  sender_device_id INTEGER NOT NULL,
  destination_service_id TEXT NOT NULL,
  needs_receipt BOOLEAN NOT NULL,
  unidentified_sender BOOLEAN NOT NULL,
  content_body BLOB NOT NULL,
  was_plaintext BOOLEAN NOT NULL,
  PRIMARY KEY (ts, thread_id),
  FOREIGN KEY (thread_id) REFERENCES threads (id) ON UPDATE CASCADE
);

CREATE TABLE IF NOT EXISTS sticker_packs (
  id BLOB PRIMARY KEY NOT NULL,
  key BLOB NOT NULL,
  manifest BLOB NOT NULL
);
