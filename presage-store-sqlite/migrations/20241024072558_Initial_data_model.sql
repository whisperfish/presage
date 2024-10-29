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
CREATE TABLE groups (
    id VARCHAR(64) PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,
    master_key BLOB NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,
    invite_link_password BLOB,
    access_required_for_attributes INTEGER NOT NULL DEFAULT 0,
    access_required_for_members INTEGER NOT NULL DEFAULT 0,
    access_required_for_add_from_invite_link INTEGER NOT NULL DEFAULT 0,
    avatar TEXT,
    description TEXT
);

CREATE TABLE group_members (
    group_id VARCHAR(64) NOT NULL,
    recipient_id INTEGER NOT NULL,
    member_since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    joined_at_revision INTEGER NOT NULL,
    role INTEGER NOT NULL,

    FOREIGN KEY(group_id) REFERENCES groups(id) ON UPDATE CASCADE,
    -- FOREIGN KEY(recipient_id) REFERENCES recipients(id) ON UPDATE RESTRICT,
    PRIMARY KEY(group_id, recipient_id)
);
CREATE INDEX group_member_recipient_id ON group_members(recipient_id DESC);
CREATE INDEX group_member_id ON group_members(group_id);

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

-- Threads
CREATE TABLE threads (
    group_id VARCHAR(64) DEFAULT NULL,
    recipient_id VARCHAR(36) DEFAULT NULL,

    PRIMARY KEY(group_id, recipient_id) ON CONFLICT IGNORE,
    FOREIGN KEY(group_id) REFERENCES groups(id) ON UPDATE CASCADE
    -- FOREIGN KEY(recipient_id) REFERENCES recipients(id) ON UPDATE CASCADE
);

CREATE TABLE thread_messages(
    ts TIMESTAMP NOT NULL,
    thread_id INTEGER NOT NULL,

    sender_service_id TEXT NOT NULL,
    -- destination_service_id TEXT NOT NULL,
    received_at TIMESTAMP NOT NULL,
    needs_receipt BOOLEAN NOT NULL,
    unidentified_sender BOOLEAN NOT NULL,

    content_body BLOB NOT NULL,

    PRIMARY KEY(ts, thread_id) ON CONFLICT REPLACE,
    FOREIGN KEY(thread_id) REFERENCES threads(id) ON UPDATE CASCADE
);