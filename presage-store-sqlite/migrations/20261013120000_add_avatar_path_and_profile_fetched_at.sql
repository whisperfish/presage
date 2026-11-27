ALTER TABLE profile_avatars ADD COLUMN path TEXT;
ALTER TABLE group_avatars ADD COLUMN path TEXT;
ALTER TABLE profiles ADD COLUMN fetched_at INTEGER;
