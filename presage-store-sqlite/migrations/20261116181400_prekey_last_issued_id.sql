-- Copied from Whisperfish: https://gitlab.com/whisperfish/whisperfish/-/merge_requests/797
-- Note that Whisperfish uses `prekey` without underscore.

-- The three pre-key id counters change meaning: they used to hold the id to
-- use *next*, they now hold the id most recently *issued* (0 meaning none
-- yet), with generation starting one past it. The stored value was always
-- `last issued + 1`, so subtract one; a never-used counter stays at 0.

CREATE TABLE pre_key_metadata_new (
    identity TEXT NOT NULL PRIMARY KEY CHECK(identity IN ('aci', 'pni')) DEFAULT 'aci',
    last_ec_pre_key_id INTEGER NOT NULL DEFAULT 0,
    last_signed_pre_key_id INTEGER NOT NULL DEFAULT 0,
    last_kyber_pre_key_id INTEGER NOT NULL DEFAULT 0,
    active_signed_pre_key_id INTEGER,
    active_last_resort_kyber_pre_key_id INTEGER,
    last_pre_key_rotation_at TIMESTAMP DEFAULT NULL
);

INSERT INTO pre_key_metadata_new (
    identity,
    last_ec_pre_key_id,
    last_signed_pre_key_id,
    last_kyber_pre_key_id,
    active_signed_pre_key_id,
    active_last_resort_kyber_pre_key_id,
    last_pre_key_rotation_at
)
    SELECT
        identity,
        MAX(next_ec_pre_key_id - 1, 0),
        MAX(next_signed_pre_key_id - 1, 0),
        MAX(next_kyber_pre_key_id - 1, 0),
        active_signed_pre_key_id,
        active_last_resort_kyber_pre_key_id,
        last_pre_key_rotation_at
    FROM pre_key_metadata;

DROP TABLE pre_key_metadata;
ALTER TABLE pre_key_metadata_new RENAME TO pre_key_metadata;

