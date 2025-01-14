CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);

-- protocol

CREATE TABLE IF NOT EXISTS sessions (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    identity TEXT NOT NULL CHECK(identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    PRIMARY KEY (address, device_id, identity)
);

CREATE TABLE IF NOT EXISTS identities (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    identity TEXT NOT NULL CHECK(identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    PRIMARY KEY (address, device_id, identity)
);

CREATE TABLE IF NOT EXISTS pre_keys (
    id INTEGER NOT NULL,
    identity TEXT NOT NULL CHECK(identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    PRIMARY KEY (id, identity)
);

CREATE TABLE IF NOT EXISTS signed_pre_keys (
    id INTEGER NOT NULL,
    identity TEXT NOT NULL CHECK(identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    PRIMARY KEY (id, identity)
);

CREATE TABLE IF NOT EXISTS kyber_pre_keys (
    id INTEGER NOT NULL,
    identity TEXT NOT NULL CHECK(identity IN ('aci', 'pni')),
    record BLOB NOT NULL,
    is_last_resort INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (id, identity)
);

CREATE TABLE sender_keys (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    identity TEXT NOT NULL CHECK(identity IN ('aci', 'pni')),
    distribution_id TEXT NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY(address, device_id, identity, distribution_id)
);
