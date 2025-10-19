CREATE TABLE IF NOT EXISTS base_keys_seen (
  kyber_pre_key_id INTEGER NOT NULL,
  signed_pre_key_id INTEGER NOT NULL,
  base_key BLOB NOT NULL,
  PRIMARY KEY (kyber_pre_key_id, signed_pre_key_id, base_key)
);
