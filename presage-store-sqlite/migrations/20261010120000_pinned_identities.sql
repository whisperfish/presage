CREATE TABLE IF NOT EXISTS pinned_identities (
  address TEXT PRIMARY KEY NOT NULL,
  record BLOB NOT NULL
);
