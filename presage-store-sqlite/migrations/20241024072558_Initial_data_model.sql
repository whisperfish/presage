CREATE TABLE config(
    key TEXT PRIMARY KEY NOT NULL ON CONFLICT REPLACE,
    value BLOB NOT NULL
);

CREATE TABLE sessions (
    address VARCHAR(36) NOT NULL,
    device_id INTEGER NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',

    PRIMARY KEY(address, device_id, identity) ON CONFLICT REPLACE
);

CREATE TABLE identities (
    address VARCHAR(36) NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',

    -- TODO: Signal adds a lot more fields here that I don't yet care about.

    PRIMARY KEY(address, identity) ON CONFLICT REPLACE
);

CREATE TABLE prekeys (
    id INTEGER NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL,

    PRIMARY KEY(id, identity) ON CONFLICT REPLACE
);

CREATE TABLE signed_prekeys (
    id INTEGER,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',

    PRIMARY KEY(id, identity) ON CONFLICT REPLACE
);

CREATE TABLE kyber_prekeys (
    id INTEGER,
    record BLOB NOT NULL,
    is_last_resort BOOLEAN DEFAULT FALSE NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL,

    PRIMARY KEY(id, identity) ON CONFLICT REPLACE
);

CREATE TABLE sender_keys (
    address VARCHAR(36),
    device INTEGER NOT NULL,
    distribution_id TEXT NOT NULL,
    record BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',

    PRIMARY KEY(address, device, distribution_id) ON CONFLICT REPLACE
);

-- Groups
CREATE TABLE groups(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    master_key BLOB NOT NULL,
    title TEXT NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    invite_link_password BLOB,
    access_required BLOB,
    avatar TEXT NOT NULL,
    description TEXT,
    members BLOB NOT NULL,
    pending_members BLOB NOT NULL,
    requesting_members BLOB NOT NULL
);

CREATE TABLE group_avatars(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bytes BLOB NOT NULL,

    FOREIGN KEY(id) REFERENCES groups(id) ON DELETE CASCADE
);

CREATE TABLE contacts(
    uuid VARCHAR(36) NOT NULL,
    -- E.164 numbers should never be longer than 15 chars (excl. international prefix)
    phone_number VARCHAR(20),
    name TEXT NOT NULL,
    color VARCHAR(32),
    profile_key BLOB NOT NULL,
    expire_timer INTEGER NOT NULL,
    expire_timer_version INTEGER NOT NULL DEFAULT 2,
    inbox_position INTEGER NOT NULL,
    archived BOOLEAN NOT NULL,
    avatar BLOB,

    PRIMARY KEY(uuid) ON CONFLICT REPLACE
);

CREATE TABLE contacts_verification_state(
    destination_aci VARCHAR(36) NOT NULL,
    identity_key BLOB NOT NULL,
    is_verified BOOLEAN,

    FOREIGN KEY(destination_aci) REFERENCES contacts(uuid) ON UPDATE CASCADE,
    PRIMARY KEY(destination_aci) ON CONFLICT REPLACE
);

CREATE TABLE profile_keys(
    uuid VARCHAR(36) NOT NULL,
    key BLOB NOT NULL,

    PRIMARY KEY(uuid) ON CONFLICT REPLACE
);

CREATE TABLE profiles(
    uuid VARCHAR(36) NOT NULL,
    given_name TEXT,
    family_name TEXT,
    about TEXT,
    about_emoji TEXT,
    avatar TEXT,

    FOREIGN KEY(uuid) REFERENCES profile_keys(uuid) ON UPDATE CASCADE
    PRIMARY KEY(uuid) ON CONFLICT REPLACE
);

CREATE TABLE profile_avatars(
    uuid VARCHAR(36) NOT NULL,
    bytes BLOB NOT NULL,

    FOREIGN KEY(uuid) REFERENCES profile_keys(uuid) ON UPDATE CASCADE
);

-- Threads
CREATE TABLE threads (
    id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
    group_id BLOB DEFAULT NULL,
    recipient_id VARCHAR(36) DEFAULT NULL,

    FOREIGN KEY(id) REFERENCES groups(id) ON DELETE CASCADE
);

CREATE TABLE thread_messages(
    ts INTEGER NOT NULL,
    thread_id INTEGER NOT NULL,

    sender_service_id TEXT NOT NULL,
    sender_device_id INTEGER NOT NULL,
    destination_service_id TEXT NOT NULL,
    needs_receipt BOOLEAN NOT NULL,
    unidentified_sender BOOLEAN NOT NULL,

    content_body BLOB NOT NULL,

    PRIMARY KEY(ts, thread_id) ON CONFLICT REPLACE,
    FOREIGN KEY(thread_id) REFERENCES threads(id) ON UPDATE CASCADE
);

CREATE TABLE sticker_packs(
    id BLOB PRIMARY KEY NOT NULL,
    key BLOB NOT NULL,
    manifest BLOB NOT NULL
);
