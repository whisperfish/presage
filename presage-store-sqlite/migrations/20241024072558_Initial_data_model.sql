CREATE TABLE session_records (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',

    PRIMARY KEY(address, device_id, identity)
);

CREATE TABLE identity_records (
    address TEXT NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',

    -- TODO: Signal adds a lot more fields here that I don't yet care about.

    PRIMARY KEY(address, identity)
);

CREATE TABLE prekey_records (
    id INTEGER PRIMARY KEY ON CONFLICT REPLACE NOT NULL,
    record BLOB NOT NULL
);

CREATE TABLE signed_prekey_records (
    id INTEGER PRIMARY KEY ON CONFLICT REPLACE NOT NULL,
    record BLOB NOT NULL
);
