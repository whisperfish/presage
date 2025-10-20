CREATE TABLE IF NOT EXISTS base_keys_seen (
  kyber_pre_key_id INTEGER NOT NULL,
  signed_pre_key_id INTEGER NOT NULL,
  identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
  base_key BLOB NOT NULL,
  PRIMARY KEY (identity, kyber_pre_key_id, signed_pre_key_id, base_key),
  FOREIGN KEY (kyber_pre_key_id, identity) REFERENCES kyber_pre_keys(id, identity) ON DELETE CASCADE,
  FOREIGN KEY (signed_pre_key_id, identity) REFERENCES signed_pre_keys(id, identity) ON DELETE CASCADE
);
