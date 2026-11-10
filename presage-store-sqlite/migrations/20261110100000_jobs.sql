-- Work owed after a message, kept until done. A job that takes another's place under its key
-- keeps the id and counts a generation.
CREATE TABLE jobs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  job TEXT NOT NULL,
  generation INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  due_at INTEGER NOT NULL DEFAULT 0
);
