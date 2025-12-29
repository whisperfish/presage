CREATE TABLE IF NOT EXISTS new_identities (
  address TEXT NOT NULL,
  identity TEXT NOT NULL CHECK (identity IN ('aci', 'pni')),
  record BLOB NOT NULL,
  PRIMARY KEY (address, identity)
);
INSERT INTO new_identities(address, identity, record) SELECT address, identity, record FROM identities WHERE device_id IN (SELECT MIN(i.device_id) FROM identities AS i WHERE i.address = address AND i.identity = identity AND i.record = record);
DROP TABLE identities;
ALTER TABLE new_identities RENAME TO identities;
