-- A message is its sender's at its time: two senders' messages at one millisecond are both kept.
CREATE TABLE thread_messages_by_sender (
  ts INTEGER NOT NULL,
  thread_id INTEGER NOT NULL,
  sender_service_id TEXT NOT NULL,
  sender_device_id INTEGER NOT NULL,
  destination_service_id TEXT NOT NULL,
  needs_receipt BOOLEAN NOT NULL,
  unidentified_sender BOOLEAN NOT NULL,
  content_body BLOB NOT NULL,
  was_plaintext BOOLEAN NOT NULL,
  server_ts INTEGER,
  pni_verified TEXT,
  PRIMARY KEY (ts, thread_id, sender_service_id),
  FOREIGN KEY (thread_id) REFERENCES threads (id) ON UPDATE CASCADE
);

INSERT INTO thread_messages_by_sender (
  ts, thread_id, sender_service_id, sender_device_id, destination_service_id, needs_receipt,
  unidentified_sender, content_body, was_plaintext, server_ts, pni_verified
)
SELECT
  ts, thread_id, sender_service_id, sender_device_id, destination_service_id, needs_receipt,
  unidentified_sender, content_body, was_plaintext, server_ts, pni_verified
FROM thread_messages;

DROP TABLE thread_messages;

ALTER TABLE thread_messages_by_sender RENAME TO thread_messages;
