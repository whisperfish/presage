-- How often a kept content was tried after a stop of the receiver: see `ContentsStore::tried`.
ALTER TABLE decrypted_contents ADD COLUMN tries INTEGER NOT NULL DEFAULT 0;
