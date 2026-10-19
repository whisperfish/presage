-- Copied from Whisperfish: https://gitlab.com/whisperfish/whisperfish/-/merge_requests/797
-- Note that Whisperfish uses `prekey` without underscore.

CREATE TABLE pre_key_metadata (
    identity TEXT NOT NULL PRIMARY KEY CHECK(identity IN ('aci', 'pni')) DEFAULT 'aci',
    next_ec_pre_key_id INTEGER NOT NULL DEFAULT 0,
    next_signed_pre_key_id INTEGER NOT NULL DEFAULT 0,
    next_kyber_pre_key_id INTEGER NOT NULL DEFAULT 0,
    active_signed_pre_key_id INTEGER,
    active_last_resort_kyber_pre_key_id INTEGER,
    last_signed_pre_key_rotation_at TIMESTAMP DEFAULT NULL,
    last_last_resort_kyber_rotation_at TIMESTAMP DEFAULT NULL
);

INSERT INTO pre_key_metadata (
    identity,
    next_ec_pre_key_id,
    next_signed_pre_key_id,
    next_kyber_pre_key_id,
    active_signed_pre_key_id,
    active_last_resort_kyber_pre_key_id
) VALUES (
    'aci',
    COALESCE((SELECT MAX(id) + 1 FROM pre_keys        WHERE lower(identity) = 'aci'), 0),
    COALESCE((SELECT MAX(id) + 1 FROM signed_pre_keys WHERE lower(identity) = 'aci'), 0),
    COALESCE((SELECT MAX(id) + 1 FROM kyber_pre_keys  WHERE lower(identity) = 'aci'), 0),
    (SELECT MAX(id) FROM signed_pre_keys WHERE identity = 'aci'),
    (SELECT MAX(id) FROM kyber_pre_keys  WHERE identity = 'aci' AND is_last_resort = 1)
), (
    'pni',
    COALESCE((SELECT MAX(id) + 1 FROM pre_keys        WHERE lower(identity) = 'pni'), 0),
    COALESCE((SELECT MAX(id) + 1 FROM signed_pre_keys WHERE lower(identity) = 'pni'), 0),
    COALESCE((SELECT MAX(id) + 1 FROM kyber_pre_keys  WHERE lower(identity) = 'pni'), 0),
    (SELECT MAX(id) FROM signed_pre_keys WHERE identity = 'pni'),
    (SELECT MAX(id) FROM kyber_pre_keys  WHERE identity = 'pni' AND is_last_resort = 1)
);

