-- Contents decrypted and not handled yet, kept in the transaction that decrypted them: see
-- `ContentsStore::keep_decrypted`.
CREATE TABLE decrypted_contents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts INTEGER NOT NULL,
    server_ts INTEGER,
    sender_service_id TEXT NOT NULL,
    sender_device_id INTEGER NOT NULL,
    destination_service_id TEXT NOT NULL,
    needs_receipt BOOLEAN NOT NULL,
    unidentified_sender BOOLEAN NOT NULL,
    content_body BLOB NOT NULL,
    was_plaintext BOOLEAN NOT NULL,
    pni_verified TEXT
);
