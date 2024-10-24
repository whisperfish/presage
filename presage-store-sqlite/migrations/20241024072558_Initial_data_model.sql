CREATE TABLE sessions (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',

    PRIMARY KEY(address, device_id, identity)
);

CREATE TABLE identities (
    address TEXT NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL,

    -- TODO: Signal adds a lot more fields here that I don't yet care about.

    PRIMARY KEY(address, identity)
);

CREATE TABLE prekeys (
    id INTEGER PRIMARY KEY ON CONFLICT REPLACE NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL
);

CREATE TABLE signed_prekeys (
    id INTEGER PRIMARY KEY ON CONFLICT REPLACE NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci'
);

CREATE TABLE kyber_prekeys (
    id INTEGER PRIMARY KEY ON CONFLICT REPLACE NOT NULL,
    record BLOB NOT NULL,
    is_last_resort BOOLEAN DEFAULT FALSE NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL
);
