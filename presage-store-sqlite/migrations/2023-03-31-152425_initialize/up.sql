
CREATE TABLE states (
  id SERIAL PRIMARY KEY,
  registration BINARY NOT NULL,
  pre_keys_offset_id INTEGER NOT NULL,
  next_signed_pre_key_id INTEGER NOT NULL
);


CREATE TABLE recipients (
    id INTEGER PRIMARY KEY NOT NULL,

    -- Recipient identification with Signal
    e164 VARCHAR(25) UNIQUE,
    uuid VARCHAR(36) UNIQUE,
    username TEXT UNIQUE,
    email TEXT UNIQUE,

    is_blocked BOOLEAN DEFAULT FALSE NOT NULL,

    -- Signal profile
    profile_key BLOB, -- Signal Android stores these as base64
    profile_key_credential BLOB,
    profile_given_name TEXT,
    profile_family_name TEXT,
    profile_joined_name TEXT,
    signal_profile_avatar TEXT, -- This is a pointer to the avatar, not the real thing.
    profile_sharing_enabled BOOLEAN DEFAULT FALSE NOT NULL,
    last_profile_fetch TIMESTAMP,

    unidentified_access_mode TINYINT DEFAULT 0 NOT NULL, -- 0 is UNKNOWN

    storage_service_id BLOB,
    storage_proto BLOB, -- This is set when an account update contains unknown fields

    capabilities INTEGER DEFAULT 0 NOT NULL, -- These are flags

    last_session_reset TIMESTAMP, about TEXT, about_emoji TEXT, is_deleted BOOLEAN DEFAULT FALSE,

    -- Either e164 or uuid should be entered in recipients
    CHECK(NOT(e164 == NULL AND uuid == NULL))
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY NOT NULL,
    conversation_id INTEGER NOT NULL,
    text TEXT,

    -- for group messages, this refers to the sender.
    sender_recipient_id INTEGER,

    received_timestamp TIMESTAMP,
    sent_timestamp TIMESTAMP,
    server_timestamp TIMESTAMP NOT NULL,

    -- This `is_read` flag indicates that the local user read the incoming message.
    is_read BOOLEAN DEFAULT FALSE NOT NULL,
    is_outbound BOOLEAN NOT NULL,
    flags INTEGER NOT NULL,

    -- expiring messages
    -- NOT NULL means that the message gets deleted at `expires_in + expiry_started`.
    expires_in INTEGER,
    expiry_started TIMESTAMP,

    -- scheduled messages
    schedule_send_time TIMESTAMP,

    is_bookmarked BOOLEAN DEFAULT FALSE NOT NULL,

    -- misc flags
    use_unidentified BOOLEAN DEFAULT FALSE NOT NULL,
    is_remote_deleted BOOLEAN DEFAULT FALSE NOT NULL, sending_has_failed BOOLEAN DEFAULT FALSE NOT NULL, quote_id INTEGER DEFAULT NULL,

    FOREIGN KEY(sender_recipient_id) REFERENCES recipients(id) ON DELETE CASCADE,
    FOREIGN KEY(conversation_id) REFERENCES conversations(id) ON DELETE CASCADE
);

CREATE TABLE attachments (
    id INTEGER PRIMARY KEY NOT NULL,
    json TEXT,
    message_id INTEGER NOT NULL,
    content_type TEXT DEFAULT "" NOT NULL,
    name TEXT,
    content_disposition TEXT,
    content_location TEXT,
    attachment_path TEXT,
    is_pending_upload BOOLEAN DEFAULT FALSE NOT NULL,
    transfer_file_path TEXT,
    size INTEGER,
    file_name TEXT,
    unique_id TEXT,
    digest TEXT,
    is_voice_note BOOLEAN NOT NULL,
    is_borderless BOOLEAN NOT NULL,
    is_quote BOOLEAN NOT NULL,

    width INTEGER,
    height INTEGER,

    sticker_pack_id TEXT DEFAULT NULL,
    sticker_pack_key BLOB DEFAULT NULL,
    sticker_id INTEGER DEFAULT NULL,
    sticker_emoji TEXT DEFAULT NULL,

    data_hash BLOB,
    visual_hash TEXT,
    transform_properties TEXT,

    -- This is the encrypted file, used for resumable uploads (#107)
    transfer_file TEXT,
    display_order INTEGER DEFAULT 0 NOT NULL,
    -- default is timestamp of this migration.
    upload_timestamp TIMESTAMP DEFAULT "2021-02-14T18:05:49Z" NOT NULL,
    cdn_number INTEGER DEFAULT 0, caption TEXT DEFAULT NULL,

    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY(sticker_pack_id, sticker_id) REFERENCES stickers(pack_id, sticker_id) ON DELETE CASCADE
);

CREATE TABLE stickers (
    pack_id TEXT,
    sticker_id INTEGER NOT NULL,
    -- Cover is the ID of the sticker of this pack to be used as "cover".
    cover_sticker_id INTEGER NOT NULL,

    key BLOB NOT NULL,

    title TEXT NOT NULL,
    author TEXT NOT NULL,

    pack_order INTEGER NOT NULL,
    emoji TEXT NOT NULL,
    content_type TEXT,
    last_used TIMESTAMP NOT NULL,
    installed TIMESTAMP NOT NULL,
    file_path TEXT NOT NULL,
    file_length INTEGER NOT NULL,
    file_random BLOB NOT NULL,

    PRIMARY KEY(pack_id, sticker_id),
    FOREIGN KEY(pack_id, cover_sticker_id) REFERENCES stickers(pack_id, sticker_id) ON DELETE CASCADE,
    UNIQUE(pack_id, sticker_id, cover_sticker_id)
);

CREATE TABLE group_v2s (
    id VARCHAR(64) PRIMARY KEY NOT NULL,
    name TEXT NOT NULL,

    master_key VARCHAR(64) NOT NULL,
    revision INTEGER NOT NULL DEFAULT 0,

    invite_link_password BLOB,

    -- Access control.
    -- enum AccessRequired {
    --  UNKNOWN       = 0;
    --  ANY           = 1;
    --  MEMBER        = 2;
    --  ADMINISTRATOR = 3;
    --  UNSATISFIABLE = 4;
    --}
    access_required_for_attributes INTEGER NOT NULL DEFAULT 0,
    access_required_for_members INTEGER NOT NULL DEFAULT 0,
    access_required_for_add_from_invite_link INTEGER NOT NULL DEFAULT 0
, avatar TEXT, description TEXT);

CREATE TABLE group_v2_members (
    group_v2_id VARCHAR(64) NOT NULL,
    recipient_id INTEGER NOT NULL,
    member_since TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    joined_at_revision INTEGER NOT NULL,
    role INTEGER NOT NULL,

    FOREIGN KEY(group_v2_id) REFERENCES group_v2s(id),
    FOREIGN KEY(recipient_id) REFERENCES recipients(id), -- on delete RESTRICT because we shouldn't delete a group member because we don't like the receiver.
    -- artificial primary key
    PRIMARY KEY(group_v2_id, recipient_id)
);

CREATE TABLE conversations (
    id INTEGER PRIMARY KEY NOT NULL,

    -- Exactly one of these three should be filed
    direct_message_recipient_id INTEGER,
    group_v2_id VARCHAR(64),

    is_archived BOOLEAN DEFAULT FALSE NOT NULL,
    is_pinned BOOLEAN DEFAULT FALSE NOT NULL,

    -- silent: notification without sound or vibration
    is_silent BOOLEAN DEFAULT FALSE NOT NULL,
    -- muted: no notification at all
    is_muted BOOLEAN DEFAULT FALSE NOT NULL,

    draft TEXT,

    expiring_message_timeout INTEGER,

    -- Deleting recipients should be separate from deleting sessions. ON DELETE RESTRICT
    FOREIGN KEY(direct_message_recipient_id) REFERENCES recipients(id),
    FOREIGN KEY(group_v2_id) REFERENCES group_v2s(id),

    -- Either a session is dm, gv2
    CHECK (NOT(direct_message_recipient_id IS NULL AND group_v2_id IS NULL))
);

CREATE TABLE IF NOT EXISTS "reactions" (
    reaction_id INTEGER PRIMARY KEY NOT NULL,

    message_id INTEGER NOT NULL,
    author INTEGER NOT NULL,

    emoji TEXT NOT NULL,
    sent_time TIMESTAMP NOT NULL,
    received_time TIMESTAMP NOT NULL,

    -- In Signal, only one emoji per author is allowed
    UNIQUE (author, message_id),

    FOREIGN KEY(message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY(author) REFERENCES recipients(id)
);

CREATE TABLE IF NOT EXISTS "receipts" (
    message_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,

    delivered TIMESTAMP,
    read TIMESTAMP,
    viewed TIMESTAMP,

    PRIMARY KEY (message_id, recipient_id),
    FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES recipients(id)
);

CREATE TABLE session_records (
    address TEXT NOT NULL,
    device_id INTEGER NOT NULL,
    record BLOB NOT NULL,

    PRIMARY KEY(address, device_id)
);

CREATE TABLE identity_records (
    address TEXT NOT NULL,
    record BLOB NOT NULL,

    -- TODO: Signal adds a lot more fields here that I don't yet care about.

    PRIMARY KEY(address)
);

CREATE TABLE sender_key_records (
    address TEXT NOT NULL,
    device INTEGER NOT NULL,
    distribution_id TEXT NOT NULL,
    record BLOB NOT NULL,
    created_at TIMESTAMP NOT NULL,

    PRIMARY KEY(address, device, distribution_id),
    UNIQUE(address, device, distribution_id) ON CONFLICT REPLACE
);

CREATE TABLE signed_prekeys (
    id INTEGER PRIMARY KEY ON CONFLICT REPLACE NOT NULL,
    record BLOB NOT NULL
);

CREATE TABLE prekeys (
    id INTEGER PRIMARY KEY ON CONFLICT REPLACE NOT NULL,
    record BLOB NOT NULL
);

CREATE INDEX recipient_e164 ON recipients(e164);
CREATE INDEX recipient_uuid ON recipients(uuid);
CREATE INDEX recipient_username ON recipients(username);
CREATE INDEX recipient_email ON recipients(email);
CREATE INDEX recipient_last_profile_fetch ON recipients(last_profile_fetch DESC);
CREATE INDEX recipient_last_session_reset ON recipients(last_session_reset DESC);
CREATE INDEX message_received ON messages(received_timestamp);
CREATE INDEX message_sent ON messages(sent_timestamp);
CREATE INDEX message_server ON messages(server_timestamp);
CREATE INDEX message_schedule ON messages(schedule_send_time);
CREATE INDEX message_expiry ON messages(expiry_started);
CREATE INDEX message_conversation_id ON messages(conversation_id);
CREATE INDEX message_recipient_id ON messages(sender_recipient_id);
CREATE INDEX group_v2_member_recipient_id ON group_v2_members(recipient_id DESC);
CREATE INDEX group_v2_members_v2_id ON group_v2_members(group_v2_id);
CREATE INDEX conversations_group_v2_id ON conversations(group_v2_id);
CREATE TRIGGER validate_group_message_has_sender
  BEFORE INSERT ON messages
BEGIN
  SELECT
    RAISE (ABORT, 'sender of inbound group message is not set')
  WHERE EXISTS (
    SELECT
      group_v2_id IS NOT NULL AS is_group,
      NOT NEW.is_outbound AS is_inbound
    FROM conversations
    WHERE conversations.id = NEW.conversation_id
      AND is_group
      AND is_inbound
      AND NEW.sender_recipient_id IS NULL
  );
END;
CREATE TRIGGER assert_uuid_for_group_v2_members
  BEFORE INSERT ON group_v2_members
BEGIN
  SELECT
    RAISE (ABORT, 'UUID or profile key of GroupV2 member is not set')
  WHERE EXISTS (
    SELECT
      recipients.id
    FROM recipients
    WHERE recipients.id = NEW.recipient_id
      AND (recipients.uuid IS NULL
          OR recipients.profile_key IS NULL)
  );
END;
