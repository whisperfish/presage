use std::marker::PhantomData;

use bytes::Bytes;
use presage::{
    libsignal_service::{
        self,
        content::{ContentBody, Metadata},
        models::Attachment,
        prelude::{
            phonenumber::{self, PhoneNumber},
            AccessControl, Content, GroupMasterKey, Member, ProfileKey, ServiceError,
        },
        profile_name::ProfileName,
        protocol::ServiceId,
        zkgroup::{self, GroupMasterKeyBytes},
        Profile, ServiceAddress,
    },
    model::{
        contacts::Contact,
        groups::{Group, PendingMember, RequestingMember},
    },
    proto::{self, verified, Verified},
    store::{ContentsStore, StickerPack, Thread},
};
use sqlx::{query, query_as, query_scalar, types::Uuid, QueryBuilder, Sqlite};
use tracing::warn;
use uuid::timestamp;

use crate::{
    data::{SqlContact, SqlGroup, SqlMessage, SqlProfile},
    SqliteStore, SqliteStoreError,
};

impl ContentsStore for SqliteStore {
    type ContentsStoreError = SqliteStoreError;

    type ContactsIter = Box<dyn Iterator<Item = Result<Contact, Self::ContentsStoreError>>>;

    type GroupsIter =
        Box<dyn Iterator<Item = Result<(GroupMasterKeyBytes, Group), Self::ContentsStoreError>>>;

    type MessagesIter = Box<dyn Iterator<Item = Result<Content, Self::ContentsStoreError>>>;

    type StickerPacksIter = Box<dyn Iterator<Item = Result<StickerPack, Self::ContentsStoreError>>>;

    async fn clear_profiles(&mut self) -> Result<(), Self::ContentsStoreError> {
        query!("DELETE FROM profiles").execute(&self.db).await?;
        Ok(())
    }

    async fn clear_contents(&mut self) -> Result<(), Self::ContentsStoreError> {
        let mut tx = self.db.begin().await?;

        query!("DELETE FROM groups").execute(&mut *tx).await;
        query!("DELETE FROM contacts").execute(&mut *tx).await;

        tx.commit().await?;
        Ok(())
    }

    async fn clear_messages(&mut self) -> Result<(), Self::ContentsStoreError> {
        let mut tx = self.db.begin().await?;
        query!("DELETE FROM thread_messages")
            .execute(&mut *tx)
            .await?;
        query!("DELETE FROM threads").execute(&mut *tx).await?;
        tx.commit().await?;

        Ok(())
    }

    async fn clear_thread(&mut self, thread: &Thread) -> Result<(), Self::ContentsStoreError> {
        if let Some(thread_id) = self.thread_id(thread).await? {
            query!("DELETE FROM thread_messages WHERE thread_id = ?", thread_id)
                .execute(&self.db)
                .await?;
        };

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
                    "INSERT INTO threads(recipient_id, group_id) VALUES (?, NULL) RETURNING id",
                    metadata.sender.uuid,
                )
                .fetch_one(&mut *tx)
                .await?
            }
            Thread::Group(master_key_bytes) => {
                let master_key_bytes = master_key_bytes.as_slice();
                query_scalar!(
                    "INSERT INTO threads(group_id) SELECT id FROM groups WHERE groups.master_key = ? RETURNING id",
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
            server_guid,
        } = metadata;

        let proto_bytes = prost::Message::encode_to_vec(&body.into_proto());

        let timestamp: i64 = timestamp.try_into()?;

        query!(
            "INSERT INTO
                thread_messages(ts, thread_id, sender_service_id, needs_receipt, unidentified_sender, content_body)
                VALUES(?, ?, ?, ?, ?, ?)",
            timestamp,
            thread_id,
            sender.uuid,
            needs_receipt,
            unidentified_sender,
            proto_bytes
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
        let timestamp: i64 = timestamp.try_into()?;
        let deleted: u64 = match thread {
            Thread::Contact(uuid) => query_scalar!(
                "DELETE FROM thread_messages WHERE ts = ? AND thread_id IN (
                    SELECT thread_id FROM threads
                    WHERE recipient_id = ?
                )",
                timestamp,
                uuid
            )
            .execute(&self.db)
            .await?
            .rows_affected(),
            Thread::Group(master_key) => {
                let master_key = master_key.as_slice();
                query_scalar!(
                    "
                    DELETE FROM thread_messages WHERE ts = ? AND thread_id IN (
                        SELECT thread_id FROM threads
                        WHERE group_id = ?
                    )",
                    timestamp,
                    master_key
                )
                .execute(&self.db)
                .await?
                .rows_affected()
            }
        };
        Ok(deleted > 0)
    }

    async fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<Content>, Self::ContentsStoreError> {
        let timestamp: i64 = timestamp.try_into()?;
        let Some(thread_id) = self.thread_id(thread).await? else {
            warn!(%thread, "thread not found");
            return Ok(None);
        };

        query_as!(
            SqlMessage,
            "SELECT * FROM thread_messages WHERE ts = ? AND thread_id = ?",
            timestamp,
            thread_id
        )
        .fetch_optional(&self.db)
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn messages(
        &self,
        thread: &Thread,
        range: impl std::ops::RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Self::ContentsStoreError> {
        let Some(thread_id) = self.thread_id(thread).await? else {
            warn!(%thread, "thread not found");
            return Ok(Box::new(std::iter::empty()));
        };

        let start = range.start_bound();

        let end = range.end_bound();

        let mut query_builder: QueryBuilder<Sqlite> =
            QueryBuilder::new("SELECT * FROM thread_messages WHERE thread_id = ");
        query_builder.push_bind(thread_id);
        match range.start_bound() {
            std::ops::Bound::Included(ts) => {
                query_builder.push("AND ts >= ");
                query_builder.push_bind(*ts as i64);
            }
            std::ops::Bound::Excluded(ts) => {
                query_builder.push("AND ts > ");
                query_builder.push_bind(*ts as i64);
            }
            std::ops::Bound::Unbounded => (),
        }
        match range.end_bound() {
            std::ops::Bound::Included(ts) => {
                query_builder.push("AND ts <= ");
                query_builder.push_bind(*ts as i64);
            }
            std::ops::Bound::Excluded(ts) => {
                query_builder.push("AND ts < ");
                query_builder.push_bind(*ts as i64);
            }
            std::ops::Bound::Unbounded => (),
        }

        query_builder.push("ORDER BY ts DESC");

        let messages: Vec<SqlMessage> = query_builder.build_query_as().fetch_all(&self.db).await?;
        Ok(Box::new(messages.into_iter().map(TryInto::try_into)))
    }

    async fn clear_contacts(&mut self) -> Result<(), Self::ContentsStoreError> {
        query!("DELETE FROM contacts").execute(&self.db).await?;
        Ok(())
    }

    async fn save_contact(&mut self, contact: Contact) -> Result<(), Self::ContentsStoreError> {
        let profile_key: &[u8] = contact.profile_key.as_ref();
        let avatar_bytes = contact.avatar.map(|a| a.reader.to_vec());
        let phone_number = contact.phone_number.map(|p| p.to_string());

        let mut tx = self.db.begin().await?;

        query!(
            "INSERT INTO contacts
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            contact.uuid,
            phone_number,
            contact.name,
            contact.color,
            profile_key,
            contact.expire_timer,
            contact.expire_timer_version,
            contact.inbox_position,
            contact.archived,
            avatar_bytes,
        )
        .execute(&mut *tx)
        .await?;

        let Verified {
            destination_aci,
            identity_key,
            state,
            ..
        } = contact.verified;
        let verified_state = match verified::State::from_i32(state.unwrap_or_default()) {
            None | Some(verified::State::Default) => None,
            Some(verified::State::Unverified) => Some("unverified"),
            Some(verified::State::Verified) => Some("verified"),
        };

        query!(
            "INSERT INTO contacts_verification_state(destination_aci, identity_key, is_verified)
            VALUES(?, ?, ?)",
            destination_aci,
            identity_key,
            verified_state,
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }

    async fn contacts(&self) -> Result<Self::ContactsIter, Self::ContentsStoreError> {
        let contacts = query_as!(
            SqlContact,
            "SELECT *
                FROM contacts c
                LEFT JOIN contacts_verification_state cv ON c.uuid = cv.destination_aci
                ORDER BY inbox_position
            "
        )
        .fetch_all(&self.db)
        .await?
        .into_iter()
        .map(TryInto::try_into);

        Ok(Box::new(contacts))
    }

    async fn contact_by_id(
        &self,
        uuid: &Uuid,
    ) -> Result<Option<presage::model::contacts::Contact>, Self::ContentsStoreError> {
        query_as!(
            SqlContact,
            "SELECT *
                FROM contacts c
                LEFT JOIN contacts_verification_state cv ON c.uuid = cv.destination_aci
                WHERE c.uuid = ?
                ORDER BY inbox_position
                LIMIT 1
            ",
            uuid
        )
        .fetch_optional(&self.db)
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn clear_groups(&mut self) -> Result<(), Self::ContentsStoreError> {
        query!("DELETE FROM groups").execute(&self.db).await?;
        Ok(())
    }

    async fn save_group(
        &self,
        master_key: zkgroup::GroupMasterKeyBytes,
        group: impl Into<presage::model::groups::Group>,
    ) -> Result<(), Self::ContentsStoreError> {
        let group = SqlGroup::from_group(master_key, group.into())?;
        query_as!(
            SqlGroup,
            "INSERT INTO groups(
                id,
                master_key,
                title,
                revision,
                invite_link_password,
                access_required,
                avatar,
                description,
                members,
                pending_members,
                requesting_members
            ) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            group.master_key,
            group.title,
            group.revision,
            group.invite_link_password,
            group.access_required,
            group.avatar,
            group.description,
            group.members,
            group.pending_members,
            group.requesting_members,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn groups(&self) -> Result<Self::GroupsIter, Self::ContentsStoreError> {
        let groups = query_as!(SqlGroup, "SELECT * FROM groups")
            .fetch_all(&self.db)
            .await?
            .into_iter()
            .map(|g| {
                let group_master_key_bytes: GroupMasterKeyBytes =
                    g.master_key.clone().try_into().expect("invalid master key");
                let group = g.into_group()?;
                Ok((group_master_key_bytes, group))
            });
        Ok(Box::new(groups))
    }

    async fn group(
        &self,
        master_key: zkgroup::GroupMasterKeyBytes,
    ) -> Result<Option<presage::model::groups::Group>, Self::ContentsStoreError> {
        query_as!(SqlGroup, "SELECT * FROM groups")
            .fetch_optional(&self.db)
            .await?
            .map(|g| g.into_group())
            .transpose()
    }

    async fn save_group_avatar(
        &self,
        master_key: zkgroup::GroupMasterKeyBytes,
        avatar: &presage::AvatarBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        let mut tx = self.db.begin().await?;

        let group_id = self.group_id(&master_key).await?;
        query!(
            "INSERT INTO group_avatars(id, bytes) VALUES(?, ?)",
            group_id,
            avatar
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(())
    }

    async fn group_avatar(
        &self,
        master_key: zkgroup::GroupMasterKeyBytes,
    ) -> Result<Option<presage::AvatarBytes>, Self::ContentsStoreError> {
        let group_id = self.group_id(&master_key).await?;
        query_scalar!("SELECT bytes FROM group_avatars WHERE id = ?", group_id)
            .fetch_optional(&self.db)
            .await
            .map_err(Into::into)
    }

    async fn upsert_profile_key(
        &mut self,
        uuid: &Uuid,
        key: ProfileKey,
    ) -> Result<bool, Self::ContentsStoreError> {
        let profile_key_bytes = key.get_bytes();
        let profile_key_slice = profile_key_bytes.as_slice();
        let rows_upserted = query!(
            "INSERT INTO profile_keys VALUES(?, ?)",
            uuid,
            profile_key_slice
        )
        .execute(&self.db)
        .await?
        .rows_affected();
        Ok(rows_upserted == 1)
    }

    async fn profile_key(
        &self,
        uuid: &Uuid,
    ) -> Result<Option<ProfileKey>, Self::ContentsStoreError> {
        let profile_key =
            query_scalar!("SELECT key FROM profile_keys WHERE uuid = ? LIMIT 1", uuid)
                .fetch_optional(&self.db)
                .await?
                .and_then(|key_bytes| key_bytes.try_into().ok().map(ProfileKey::create));
        Ok(profile_key)
    }

    async fn save_profile(
        &mut self,
        uuid: Uuid,
        _key: ProfileKey,
        profile: Profile,
    ) -> Result<(), Self::ContentsStoreError> {
        let given_name = profile.name.clone().map(|n| n.given_name);
        let family_name = profile.name.map(|n| n.family_name).flatten();
        query!(
            "INSERT INTO profiles VALUES(?, ?, ?, ?, ?, ?)",
            uuid,
            given_name,
            family_name,
            profile.about,
            profile.about_emoji,
            profile.avatar
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
        let key_bytes = key.get_bytes();
        let key_slice = key_bytes.as_slice();
        query_as!(
            SqlProfile,
            "SELECT pk.key, p.* FROM profile_keys pk
             LEFT JOIN profiles p ON pk.uuid = p.uuid
             WHERE pk.uuid = ?
             LIMIT 1",
            uuid
        )
        .fetch_optional(&self.db)
        .await?
        .map(TryInto::try_into)
        .transpose()
    }

    async fn save_profile_avatar(
        &mut self,
        uuid: Uuid,
        _key: ProfileKey,
        profile: &presage::AvatarBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        query!(
            "INSERT INTO profile_avatars(uuid, bytes) VALUES(?, ?)",
            uuid,
            profile
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn profile_avatar(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> Result<Option<presage::AvatarBytes>, Self::ContentsStoreError> {
        query_scalar!("SELECT bytes FROM profile_avatars WHERE uuid = ?", uuid)
            .fetch_optional(&self.db)
            .await
            .map_err(Into::into)
    }

    async fn add_sticker_pack(
        &mut self,
        pack: &StickerPack,
    ) -> Result<(), Self::ContentsStoreError> {
        let manifest_json = postcard::to_allocvec(&pack.manifest)?;
        query!(
            "INSERT INTO sticker_packs(id, key, manifest) VALUES(?, ?, ?)",
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
        query_scalar!("SELECT manifest FROM sticker_packs WHERE id = ?", id)
            .fetch_optional(&self.db)
            .await?
            .map(|bytes| postcard::from_bytes(&bytes).map_err(Into::into))
            .transpose()
    }

    async fn remove_sticker_pack(&mut self, id: &[u8]) -> Result<bool, Self::ContentsStoreError> {
        query!("DELETE FROM sticker_packs WHERE id = ?", id)
            .execute(&self.db)
            .await
            .map_err(Into::into)
            .map(|r| r.rows_affected() > 0)
    }

    async fn sticker_packs(&self) -> Result<Self::StickerPacksIter, Self::ContentsStoreError> {
        let sticker_packs = query!("SELECT * FROM sticker_packs")
            .fetch_all(&self.db)
            .await?
            .into_iter()
            .map(|r| {
                Ok(StickerPack {
                    id: r.id,
                    key: r.key,
                    manifest: postcard::from_bytes(&r.manifest)?,
                })
            });
        Ok(Box::new(sticker_packs))
    }
}

impl SqliteStore {
    async fn group_id(&self, master_key: &[u8]) -> Result<i64, SqliteStoreError> {
        query_scalar!(
            "SELECT id FROM groups WHERE groups.master_key = ?",
            master_key
        )
        .fetch_one(&self.db)
        .await
        .map_err(Into::into)
    }

    async fn thread_id(&self, thread: &Thread) -> Result<Option<i64>, SqliteStoreError> {
        Ok(match thread {
            Thread::Contact(uuid) => {
                query_scalar!(
                    "SELECT id FROM threads WHERE recipient_id = ? LIMIT 1",
                    uuid
                )
                .fetch_optional(&self.db)
                .await?
            }
            Thread::Group(master_key) => {
                let master_key = master_key.as_slice();
                query_scalar!(
                    "SELECT id FROM threads WHERE group_id = ? LIMIT 1",
                    master_key
                )
                .fetch_optional(&self.db)
                .await?
            }
        })
    }
}
