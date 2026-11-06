-- The identity last refused for sending because another is pinned: theirs now, which the
-- identity store never saw.
ALTER TABLE pinned_identities ADD COLUMN offered BLOB;
