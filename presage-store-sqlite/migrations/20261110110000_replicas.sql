-- How current the copies of what the server has are: profiles, the storage manifest.
CREATE TABLE replicas (
  kind TEXT NOT NULL,
  id BLOB NOT NULL,
  version INTEGER,
  fetched_at INTEGER NOT NULL,
  PRIMARY KEY (kind, id)
);
