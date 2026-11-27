CREATE TABLE IF NOT EXISTS stories (
  sender_uuid BLOB NOT NULL,
  ts INTEGER NOT NULL,
  story_message BLOB NOT NULL,
  viewed BOOLEAN NOT NULL DEFAULT FALSE,
  PRIMARY KEY (sender_uuid, ts)
);

CREATE INDEX IF NOT EXISTS stories_ts ON stories (ts);

CREATE TABLE IF NOT EXISTS hidden_story_contacts (
  uuid BLOB NOT NULL PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS hidden_story_groups (
  master_key BLOB NOT NULL PRIMARY KEY
);
