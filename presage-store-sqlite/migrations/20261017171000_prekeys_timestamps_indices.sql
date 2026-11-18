-- Copied from Whisperfish: https://gitlab.com/whisperfish/whisperfish/-/merge_requests/797
-- Note that Whisperfish uses `prekey` without underscore.

-- pre_keys

CREATE TABLE pre_keys_new (
    id INTEGER NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',
    stale_at TIMESTAMP DEFAULT NULL,
    PRIMARY KEY (id, identity) ON CONFLICT REPLACE
);

INSERT INTO pre_keys_new (id, record, identity, stale_at)
    SELECT id, record, identity, NULL FROM pre_keys;

DROP TABLE pre_keys;
ALTER TABLE pre_keys_new RENAME TO pre_keys;

-- kyber_pre_keys

CREATE TABLE kyber_pre_keys_new (
    id INTEGER NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',
    is_last_resort BOOLEAN DEFAULT FALSE NOT NULL,
    stale_at TIMESTAMP DEFAULT NULL,
    PRIMARY KEY (id, identity) ON CONFLICT REPLACE
);

INSERT INTO kyber_pre_keys_new (id, record, identity, is_last_resort, stale_at)
    SELECT id, record, identity, is_last_resort, NULL FROM kyber_pre_keys;

DROP TABLE kyber_pre_keys;
ALTER TABLE kyber_pre_keys_new RENAME TO kyber_pre_keys;

CREATE INDEX kyber_pre_keys_identity_last_resort ON kyber_pre_keys(identity, is_last_resort);

-- signed_pre_keys

CREATE TABLE signed_pre_keys_new (
    id INTEGER NOT NULL,
    record BLOB NOT NULL,
    identity TEXT CHECK(identity IN ('aci', 'pni')) NOT NULL DEFAULT 'aci',
    PRIMARY KEY (id, identity) ON CONFLICT REPLACE
);

INSERT INTO signed_pre_keys_new (id, record, identity)
    SELECT id, record, identity FROM signed_pre_keys;

DROP TABLE signed_pre_keys;
ALTER TABLE signed_pre_keys_new RENAME TO signed_pre_keys;

CREATE INDEX signed_pre_keys_identity ON signed_pre_keys(identity);

