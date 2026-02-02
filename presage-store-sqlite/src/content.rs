use std::ops::{Bound, RangeBounds};

use presage::{
    AvatarBytes,
    libsignal_service::{
        Profile,
        content::Metadata,
        prelude::{Content, ProfileKey, Uuid},
        protocol::ServiceId,
        zkgroup::GroupMasterKeyBytes,
    },
    model::{contacts::Contact, groups::Group},
    proto::{Verified, verified},
    store::{ContentsStore, StickerPack, Thread},
};
use sqlx::{query, query_as, query_scalar, types::Json};

use crate::{
    SqliteStore, SqliteStoreError,
    data::{SqlContact, SqlGroup, SqlMessage, SqlProfile, SqlStickerPack},
    error::SqlxErrorExt,
};

impl ContentsStore for SqliteStore {
    type ContentsStoreError = SqliteStoreError;

    type ContactsIter =
        Box<dyn Iterator<Item = Result<Contact, Self::ContentsStoreError>> + Send + Sync>;

    type GroupsIter = Box<
        dyn Iterator<Item = Result<(GroupMasterKeyBytes, Group), Self::ContentsStoreError>>
            + Send
            + Sync,
    >;

    type MessagesIter =
        Box<dyn Iterator<Item = Result<Content, Self::ContentsStoreError>> + Send + Sync>;

    type StickerPacksIter =
        Box<dyn Iterator<Item = Result<StickerPack, Self::ContentsStoreError>> + Send + Sync>;

    async fn clear_profiles(&mut self) -> Result<(), Self::ContentsStoreError> {
        let mut transaction = self.db.begin().await.into_protocol_error()?;
        query!("DELETE FROM profiles")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM profile_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM profile_avatars")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn clear_contents(&mut self) -> Result<(), Self::ContentsStoreError> {
        let mut transaction = self.db.begin().await.into_protocol_error()?;
        query!("DELETE FROM thread_messages")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM threads")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM contacts")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM contacts_verification_state")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM groups")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM group_avatars")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM sticker_packs")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn clear_messages(&mut self) -> Result<(), Self::ContentsStoreError> {
        let mut transaction = self.db.begin().await.into_protocol_error()?;
        query!("DELETE FROM thread_messages")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM threads")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn clear_thread(&mut self, thread: &Thread) -> Result<(), Self::ContentsStoreError> {
        let (group_master_key, recipient_id) = thread.unzip();
        query!(
            "DELETE FROM thread_messages WHERE thread_id = (
                SELECT id FROM threads WHERE group_master_key = ? OR recipient_id = ?)",
            group_master_key,
            recipient_id,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn save_message(
        &self,
        thread: &Thread,
        Content { metadata, body }: Content,
    ) -> Result<(), Self::ContentsStoreError> {
        let mut tx = self.db.begin().await?;

        let thread_id = match thread {
            Thread::Contact(uuid) => {
                query_scalar!(
                    "INSERT INTO threads(recipient_id, group_master_key) VALUES (?1, NULL)
                    ON CONFLICT DO UPDATE SET recipient_id = ?1 RETURNING id",
                    uuid,
                )
                .fetch_one(&mut *tx)
                .await?
            }
            Thread::Group(master_key_bytes) => {
                let master_key_bytes = master_key_bytes.as_slice();
                query_scalar!(
                    "INSERT INTO threads(recipient_id, group_master_key) VALUES (NULL, ?1)
                    ON CONFLICT DO UPDATE SET group_master_key = ?1 RETURNING id",
                    master_key_bytes
                )
                .fetch_one(&mut *tx)
                .await?
            }
        };

        let Metadata {
            sender,
            destination,
            sender_device,
            timestamp,
            needs_receipt,
            unidentified_sender,
            server_guid: _,
            was_plaintext,
        } = metadata;

        let sender_device: u8 = sender_device.into();
        let sender_service_id = sender.service_id_string();
        let destination_service_id = destination.service_id_string();

        let proto_bytes = prost::Message::encode_to_vec(&body.into_proto());
        let timestamp: i64 = timestamp
            .try_into()
            .map_err(|_| SqliteStoreError::InvalidFormat)?;

        query!(
            "INSERT OR REPLACE INTO thread_messages (
                ts,
                thread_id,
                sender_service_id,
                sender_device_id,
                destination_service_id,
                needs_receipt,
                unidentified_sender,
                content_body,
                was_plaintext
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)",
            timestamp,
            thread_id,
            sender_service_id,
            sender_device,
            destination_service_id,
            needs_receipt,
            unidentified_sender,
            proto_bytes,
            was_plaintext,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn delete_message(
        &mut self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<bool, Self::ContentsStoreError> {
        let timestamp: i64 = timestamp
            .try_into()
            .map_err(|_| SqliteStoreError::InvalidFormat)?;
        let (group_master_key, recipient_id) = thread.unzip();
        let res = query!(
            "DELETE FROM thread_messages
            WHERE ts = ? AND thread_id = (
                SELECT id FROM threads WHERE group_master_key = ? OR recipient_id = ?)",
            timestamp,
            group_master_key,
            recipient_id,
        )
        .execute(&self.db)
        .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<Content>, Self::ContentsStoreError> {
        let timestamp: i64 = timestamp
            .try_into()
            .map_err(|_| SqliteStoreError::InvalidFormat)?;
        let (group_master_key, recipient_id) = thread.unzip();
        let message = query_as!(
            SqlMessage,
            r#"SELECT
                ts AS "ts: _",
                sender_service_id,
                sender_device_id AS "sender_device_id: _",
                destination_service_id,
                needs_receipt,
                unidentified_sender,
                content_body,
                was_plaintext
            FROM thread_messages
            WHERE ts = ? AND thread_id = (
                SELECT id FROM threads WHERE group_master_key = ? OR recipient_id = ?)"#,
            timestamp,
            group_master_key,
            recipient_id,
        )
        .fetch_optional(&self.db)
        .await?;
        message.map(|m| m.try_into()).transpose()
    }

    async fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Self::ContentsStoreError> {
        let (group_master_key, recipient_id) = thread.unzip();

        let (start_incl, start_excl) = range.start_bound().into_sql_bound();
        let (end_incl, end_excl) = range.end_bound().into_sql_bound();

        let rows = query_as!(
            SqlMessage,
            r#"SELECT
                ts AS "ts: _",
                sender_service_id,
                sender_device_id AS "sender_device_id: _",
                destination_service_id,
                needs_receipt,
                unidentified_sender,
                content_body,
                was_plaintext
            FROM thread_messages
            WHERE thread_id = (
                SELECT id FROM threads WHERE group_master_key = ? OR recipient_id = ?)
                AND coalesce(ts > ?, ts >= ?, true)
                AND coalesce(ts < ?, ts <= ?, true)
            ORDER BY ts DESC"#,
            group_master_key,
            recipient_id,
            start_incl,
            start_excl,
            end_incl,
            end_excl
        )
        .fetch_all(&self.db)
        .await?;

        Ok(Box::new(rows.into_iter().map(TryInto::try_into)))
    }

    async fn clear_contacts(&mut self) -> Result<(), Self::ContentsStoreError> {
        let mut transaction = self.db.begin().await.into_protocol_error()?;
        query!("DELETE FROM contacts")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM contacts_verification_state")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn save_contact(&mut self, contact: &Contact) -> Result<(), Self::ContentsStoreError> {
        let profile_key: &[u8] = contact.profile_key.as_ref();
        let avatar_bytes = contact.avatar.as_ref().map(|a| a.reader.to_vec());
        let phone_number = contact.phone_number.as_ref().map(|p| p.to_string());

        let mut tx = self.db.begin().await?;

        query!(
            "INSERT OR REPLACE INTO contacts
            VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            contact.uuid,
            phone_number,
            contact.name,
            profile_key,
            contact.expire_timer,
            contact.expire_timer_version,
            contact.inbox_position,
            avatar_bytes,
        )
        .execute(&mut *tx)
        .await?;

        let Verified {
            destination_aci,
            identity_key,
            state,
            ..
        } = &contact.verified;
        let is_verified = match verified::State::try_from(state.unwrap_or_default()) {
            Err(_) | Ok(verified::State::Default) => None,
            Ok(verified::State::Unverified) => Some(false),
            Ok(verified::State::Verified) => Some(true),
        };

        if let Some((destination_aci, identity_key)) =
            destination_aci.as_ref().zip(identity_key.as_ref())
        {
            query!(
                "INSERT OR REPLACE INTO contacts_verification_state(
                    destination_aci, identity_key, is_verified
                ) VALUES(?, ?, ?)",
                destination_aci,
                identity_key,
                is_verified,
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(())
    }

    async fn contacts(&self) -> Result<Self::ContactsIter, Self::ContentsStoreError> {
        let sql_contacts = query_as!(
            SqlContact,
            r#"SELECT
                uuid AS "uuid: _",
                phone_number,
                name,
                profile_key,
                expire_timer,
                expire_timer_version,
                inbox_position,
                avatar,
                destination_aci AS "destination_aci: _",
                identity_key,
                is_verified
            FROM contacts c
            LEFT JOIN contacts_verification_state cv ON c.uuid = cv.destination_aci
            ORDER BY c.inbox_position"#
        )
        .fetch_all(&self.db)
        .await?;
        Ok(Box::new(sql_contacts.into_iter().map(TryInto::try_into)))
    }

    async fn contact_by_id(&self, id: &Uuid) -> Result<Option<Contact>, Self::ContentsStoreError> {
        query_as!(
            SqlContact,
            r#"SELECT
                uuid AS "uuid: _",
                phone_number,
                name,
                profile_key,
                expire_timer,
                expire_timer_version,
                inbox_position,
                avatar,
                destination_aci AS "destination_aci: _",
                identity_key,
                is_verified
            FROM contacts c
            LEFT JOIN contacts_verification_state cv ON c.uuid = cv.destination_aci
            WHERE c.uuid = ?"#,
            id
        )
        .fetch_optional(&self.db)
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn clear_groups(&mut self) -> Result<(), Self::ContentsStoreError> {
        let mut transaction = self.db.begin().await.into_protocol_error()?;
        query!("DELETE FROM groups")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM group_avatars")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn save_group(
        &self,
        master_key: GroupMasterKeyBytes,
        group: impl Into<Group>,
    ) -> Result<(), Self::ContentsStoreError> {
        let g = SqlGroup::from_group(&master_key, group.into());
        let master_key = g.master_key.as_ref();
        query!(
            "INSERT OR REPLACE INTO groups VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            master_key,
            g.title,
            g.revision,
            g.invite_link_password,
            g.access_control,
            g.avatar,
            g.description,
            g.members,
            g.pending_members,
            g.requesting_members,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn groups(&self) -> Result<Self::GroupsIter, Self::ContentsStoreError> {
        let sql_groups = query_as!(
            SqlGroup,
            r#"SELECT
                master_key,
                title,
                revision AS "revision: _",
                invite_link_password,
                access_control AS "access_control: _",
                avatar,
                description,
                members AS "members: _",
                pending_members AS "pending_members: _",
                requesting_members AS "requesting_members: _"
            FROM groups"#,
        )
        .fetch_all(&self.db)
        .await?;
        Ok(Box::new(sql_groups.into_iter().map(SqlGroup::into_group)))
    }

    async fn group(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> Result<Option<Group>, Self::ContentsStoreError> {
        let master_key_bytes = master_key.as_slice();
        query_as!(
            SqlGroup,
            r#"SELECT
                master_key,
                title,
                revision AS "revision: _",
                invite_link_password,
                access_control AS "access_control: _",
                avatar,
                description,
                members AS "members: _",
                pending_members AS "pending_members: _",
                requesting_members AS "requesting_members: _"
            FROM groups
            WHERE master_key = ?
            LIMIT 1"#,
            master_key_bytes,
        )
        .fetch_optional(&self.db)
        .await?
        .map(|g| g.into_group().map(|(_master_key, group)| group))
        .transpose()
    }

    async fn save_group_avatar(
        &self,
        master_key: GroupMasterKeyBytes,
        avatar: &AvatarBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        let master_key_bytes = master_key.as_slice();
        query!(
            "INSERT OR REPLACE INTO group_avatars(group_master_key, bytes) VALUES (?, ?)",
            master_key_bytes,
            avatar,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn group_avatar(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> Result<Option<AvatarBytes>, Self::ContentsStoreError> {
        let master_key_bytes = master_key.as_slice();
        query_scalar!(
            "SELECT bytes FROM group_avatars WHERE group_master_key = ?",
            master_key_bytes,
        )
        .fetch_optional(&self.db)
        .await
        .map_err(From::from)
    }

    async fn upsert_profile_key(
        &mut self,
        uuid: &Uuid,
        key: ProfileKey,
    ) -> Result<bool, Self::ContentsStoreError> {
        let profile_key_bytes = key.bytes.as_slice();
        let res = query_scalar!(
            "INSERT OR REPLACE INTO profile_keys (uuid, key) VALUES (?, ?)",
            uuid,
            profile_key_bytes
        )
        .execute(&self.db)
        .await?;
        Ok(res.rows_affected() == 0)
    }

    async fn profile_key(
        &self,
        service_id: &ServiceId,
    ) -> Result<Option<ProfileKey>, Self::ContentsStoreError> {
        let uuid = service_id.raw_uuid();
        let profile_key = query_scalar!("SELECT key FROM profile_keys WHERE uuid = ?", uuid)
            .fetch_optional(&self.db)
            .await?
            .and_then(|bytes| bytes.try_into().ok().map(ProfileKey::create));
        Ok(profile_key)
    }

    async fn save_profile(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: Profile,
    ) -> Result<(), Self::ContentsStoreError> {
        self.upsert_profile_key(&uuid, key).await?;
        let Profile {
            name,
            about,
            about_emoji,
            avatar,
            unrestricted_unidentified_access,
        } = profile;
        let (given_name, family_name) = name.map(|n| (n.given_name, n.family_name)).unzip();
        let family_name = family_name.flatten();
        query!(
            "INSERT OR REPLACE INTO profiles VALUES (?, ?, ?, ?, ?, ?, ?)",
            uuid,
            given_name,
            family_name,
            about,
            about_emoji,
            avatar,
            unrestricted_unidentified_access,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn profile(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> Result<Option<Profile>, Self::ContentsStoreError> {
        let profile_key_bytes = key.bytes.as_slice();
        let profile = query_as!(
            SqlProfile,
            "SELECT
                p.given_name,
                p.family_name,
                p.about,
                p.about_emoji,
                p.avatar,
                p.unrestricted_unidentified_access
            FROM profile_keys pk
            INNER JOIN profiles p ON p.uuid = pk.uuid
            WHERE pk.uuid = ? AND pk.key = ?",
            uuid,
            profile_key_bytes,
        )
        .fetch_optional(&self.db)
        .await?;
        Ok(profile.map(|p| p.into()))
    }

    async fn save_profile_avatar(
        &mut self,
        uuid: Uuid,
        _key: ProfileKey,
        profile: &AvatarBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        query!(
            "INSERT OR REPLACE INTO profile_avatars(uuid, bytes) VALUES (?, ?)",
            uuid,
            profile,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn profile_avatar(
        &self,
        uuid: Uuid,
        _key: ProfileKey,
    ) -> Result<Option<AvatarBytes>, Self::ContentsStoreError> {
        query_scalar!("SELECT bytes FROM profile_avatars WHERE uuid = ?", uuid)
            .fetch_optional(&self.db)
            .await
            .map_err(From::from)
    }

    async fn add_sticker_pack(
        &mut self,
        pack: &StickerPack,
    ) -> Result<(), Self::ContentsStoreError> {
        let manifest_json = Json(&pack.manifest);
        query!(
            "INSERT OR REPLACE INTO sticker_packs(id, key, manifest) VALUES(?, ?, ?)",
            pack.id,
            pack.key,
            manifest_json,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn sticker_pack(
        &self,
        id: &[u8],
    ) -> Result<Option<StickerPack>, Self::ContentsStoreError> {
        let pack = query_as!(
            SqlStickerPack,
            r#"SELECT id, key, manifest AS "manifest: _" FROM sticker_packs WHERE id = ?"#,
            id
        )
        .fetch_optional(&self.db)
        .await?;
        Ok(pack.map(From::from))
    }

    async fn remove_sticker_pack(&mut self, id: &[u8]) -> Result<bool, Self::ContentsStoreError> {
        let res = query!("DELETE FROM sticker_packs WHERE id = ?", id)
            .execute(&self.db)
            .await?;
        Ok(res.rows_affected() > 0)
    }

    async fn sticker_packs(&self) -> Result<Self::StickerPacksIter, Self::ContentsStoreError> {
        let sql_packs = query_as!(
            SqlStickerPack,
            r#"SELECT id, key, manifest AS "manifest: _" FROM sticker_packs"#,
        )
        .fetch_all(&self.db)
        .await?;
        Ok(Box::new(sql_packs.into_iter().map(|pack| Ok(pack.into()))))
    }
}

trait ThreadExt {
    fn group_master_key(&self) -> Option<&[u8]>;
    fn recipient_id(&self) -> Option<Uuid>;

    fn unzip(&self) -> (Option<&[u8]>, Option<Uuid>) {
        (self.group_master_key(), self.recipient_id())
    }
}

impl ThreadExt for Thread {
    fn group_master_key(&self) -> Option<&[u8]> {
        match self {
            Thread::Contact(_) => None,
            Thread::Group(master_key) => Some(master_key.as_slice()),
        }
    }

    fn recipient_id(&self) -> Option<Uuid> {
        match self {
            Thread::Contact(uuid) => Some(*uuid),
            Thread::Group(_) => None,
        }
    }
}

trait BoundExt {
    fn into_sql_bound(self) -> (Option<i64>, Option<i64>);
}

impl BoundExt for Bound<&u64> {
    fn into_sql_bound(self) -> (Option<i64>, Option<i64>) {
        match self {
            Bound::Excluded(x) => (Some(*x as i64), None),
            Bound::Included(x) => (None, Some(*x as i64)),
            Bound::Unbounded => (None, None),
        }
    }
}
