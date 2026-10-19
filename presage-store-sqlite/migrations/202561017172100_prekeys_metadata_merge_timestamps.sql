-- Copied from Whisperfish: https://gitlab.com/whisperfish/whisperfish/-/merge_requests/797
-- Note that Whisperfish uses `prekey` without underscore.

CREATE TABLE pre_key_metadata_new (
    identity TEXT NOT NULL PRIMARY KEY CHECK(identity IN ('aci', 'pni')) DEFAULT 'aci',
    next_ec_pre_key_id INTEGER NOT NULL DEFAULT 0,
    next_signed_pre_key_id INTEGER NOT NULL DEFAULT 0,
    next_kyber_pre_key_id INTEGER NOT NULL DEFAULT 0,
    active_signed_pre_key_id INTEGER,
    active_last_resort_kyber_pre_key_id INTEGER,
    last_pre_key_rotation_at TIMESTAMP DEFAULT NULL
);

INSERT INTO pre_key_metadata_new (
    identity,
    next_ec_pre_key_id,
    next_signed_pre_key_id,
    next_kyber_pre_key_id,
    active_signed_pre_key_id,
    active_last_resort_kyber_pre_key_id,
    last_pre_key_rotation_at
)
    SELECT
        identity,
        next_ec_pre_key_id,
        next_signed_pre_key_id,
        next_kyber_pre_key_id,
        active_signed_pre_key_id,
        active_last_resort_kyber_pre_key_id,
        COALESCE(
            last_signed_pre_key_rotation_at,
            last_last_resort_kyber_rotation_at
        )
    FROM pre_key_metadata;

DROP TABLE pre_key_metadata;
ALTER TABLE pre_key_metadata_new RENAME TO pre_key_metadata;

