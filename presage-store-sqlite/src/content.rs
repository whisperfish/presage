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
    model::{
        contacts::Contact,
        groups::Group,
        jobs::{Job, QueuedJob},
        replicas::{Freshness, Replica},
    },
    proto::{Verified, verified},
    store::{ContentsStore, StickerPack, Thread},
};
use sqlx::{query, query_as, query_scalar, types::Json};
use tracing::warn;

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
        let mut transaction = self.begin_write().await.into_protocol_error()?;
        query!("DELETE FROM profiles")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM profile_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM profile_avatars")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM replicas WHERE kind = 'profile'")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn clear_contents(&mut self) -> Result<(), Self::ContentsStoreError> {
        let mut transaction = self.begin_write().await.into_protocol_error()?;
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
        // Nothing is owed for what is gone, and the groups the storage service lists are read
        // again.
        query!("DELETE FROM jobs")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM replicas WHERE kind = 'storage-manifest'")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn clear_messages(&mut self) -> Result<(), Self::ContentsStoreError> {
        let mut transaction = self.begin_write().await.into_protocol_error()?;
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
        let mut tx = self.begin_write().await?;

        let thread_id = match thread {
            Thread::Contact(service_id) => {
                let uuid = service_id.raw_uuid();
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
            client_timestamp: timestamp,
            needs_receipt,
            unidentified_sender,
            server_guid: _,
            was_plaintext,
            server_timestamp: _,
            pni_verified,
        } = metadata;

        let sender_device: u8 = sender_device.into();
        let sender_service_id = sender.service_id_string();
        let destination_service_id = destination.service_id_string();

        let proto_bytes = prost::Message::encode_to_vec(&body.into_proto());
        let timestamp = timestamp.timestamp_millis();

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
                was_plaintext,
                pni_verified
            )
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            timestamp,
            thread_id,
            sender_service_id,
            sender_device,
            destination_service_id,
            needs_receipt,
            unidentified_sender,
            proto_bytes,
            was_plaintext,
            pni_verified.as_ref().map(|p| p.service_id_string())
        )
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    async fn delete_message(
        &mut self,
        thread: &Thread,
        sender: &ServiceId,
        timestamp: u64,
    ) -> Result<bool, Self::ContentsStoreError> {
        let timestamp: i64 = timestamp
            .try_into()
            .map_err(|_| SqliteStoreError::InvalidFormat)?;
        let sender_service_id = sender.service_id_string();
        let (group_master_key, recipient_id) = thread.unzip();
        let res = query!(
            "DELETE FROM thread_messages
            WHERE ts = ? AND sender_service_id = ? AND thread_id = (
                SELECT id FROM threads WHERE group_master_key = ? OR recipient_id = ?)",
            timestamp,
            sender_service_id,
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
        sender: &ServiceId,
        timestamp: u64,
    ) -> Result<Option<Content>, Self::ContentsStoreError> {
        let timestamp: i64 = timestamp
            .try_into()
            .map_err(|_| SqliteStoreError::InvalidFormat)?;
        let sender_service_id = sender.service_id_string();
        let (group_master_key, recipient_id) = thread.unzip();
        let message = query_as!(
            SqlMessage,
            r#"SELECT
                ts AS "ts: _",
                server_ts AS "server_ts: _",
                sender_service_id,
                sender_device_id AS "sender_device_id: _",
                destination_service_id,
                needs_receipt,
                unidentified_sender,
                content_body,
                was_plaintext,
                pni_verified
            FROM thread_messages
            WHERE ts = ? AND sender_service_id = ? AND thread_id = (
                SELECT id FROM threads WHERE group_master_key = ? OR recipient_id = ?)"#,
            timestamp,
            sender_service_id,
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
                server_ts AS "server_ts: _",
                sender_service_id,
                sender_device_id AS "sender_device_id: _",
                destination_service_id,
                needs_receipt,
                unidentified_sender,
                content_body,
                was_plaintext,
                pni_verified
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
        let mut transaction = self.begin_write().await.into_protocol_error()?;
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

        let mut tx = self.begin_write().await?;

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

    async fn contact_by_id(
        &self,
        id: &ServiceId,
    ) -> Result<Option<Contact>, Self::ContentsStoreError> {
        let id = id.raw_uuid();
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
        let mut transaction = self.begin_write().await.into_protocol_error()?;
        query!("DELETE FROM groups")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM group_avatars")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM left_groups")
            .execute(&mut *transaction)
            .await?;
        // The groups the storage service lists are read again.
        query!("DELETE FROM replicas WHERE kind = 'storage-manifest'")
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
        let mut transaction = self.begin_write().await?;
        query!(
            "INSERT OR REPLACE INTO groups VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
            g.disappearing_messages_timer,
        )
        .execute(&mut *transaction)
        .await?;
        query!("DELETE FROM left_groups WHERE master_key = ?", master_key)
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn mark_group_left(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        let master_key = master_key.as_slice();
        query!(
            "INSERT OR IGNORE INTO left_groups (master_key) VALUES (?)",
            master_key
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn is_group_left(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> Result<bool, Self::ContentsStoreError> {
        let master_key = master_key.as_slice();
        let left = query_scalar!(
            "SELECT EXISTS(SELECT 1 FROM left_groups WHERE master_key = ?)",
            master_key
        )
        .fetch_one(&self.db)
        .await?;
        Ok(left != 0)
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
                requesting_members AS "requesting_members: _",
                disappearing_messages_timer
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
                requesting_members AS "requesting_members: _",
                disappearing_messages_timer
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
        Ok(res.rows_affected() > 0)
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

    async fn replica(
        &self,
        replica: &Replica,
    ) -> Result<Option<Freshness>, Self::ContentsStoreError> {
        let (kind, id) = (replica.kind(), replica.id());
        let row = query!(
            r#"SELECT version AS "version: u64", fetched_at AS "fetched_at: u64"
            FROM replicas WHERE kind = ? AND id = ?"#,
            kind,
            id,
        )
        .fetch_optional(&self.db)
        .await?;
        Ok(row.map(|row| Freshness {
            version: row.version,
            fetched_at: row.fetched_at,
        }))
    }

    async fn set_replica(
        &mut self,
        replica: &Replica,
        freshness: Freshness,
    ) -> Result<(), Self::ContentsStoreError> {
        let (kind, id) = (replica.kind(), replica.id());
        let version = freshness.version.map(|version| version as i64);
        let fetched_at = freshness.fetched_at as i64;
        query!(
            "INSERT OR REPLACE INTO replicas (kind, id, version, fetched_at) VALUES (?, ?, ?, ?)",
            kind,
            id,
            version,
            fetched_at,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn enqueue_job(&mut self, job: &Job) -> Result<(), Self::ContentsStoreError> {
        let key = job.key();
        let job = serde_json::to_string(job)?;
        query!(
            "INSERT INTO jobs (key, job) VALUES (?, ?)
            ON CONFLICT (key) DO UPDATE SET
                job = excluded.job, generation = generation + 1, attempts = 0, due_at = 0
            WHERE job <> excluded.job",
            key,
            job,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn jobs(&self) -> Result<Vec<QueuedJob>, Self::ContentsStoreError> {
        let rows = query!(
            r#"SELECT
                id AS "id!: i64",
                job,
                generation AS "generation: u64",
                attempts AS "attempts: u32",
                due_at AS "due_at: u64"
            FROM jobs ORDER BY id"#
        )
        .fetch_all(&self.db)
        .await?;
        let mut jobs = Vec::with_capacity(rows.len());
        for row in rows {
            match serde_json::from_str(&row.job) {
                Ok(job) => jobs.push(QueuedJob {
                    id: u64::try_from(row.id).map_err(|_| SqliteStoreError::InvalidFormat)?,
                    job,
                    generation: row.generation,
                    attempts: row.attempts,
                    due_at: row.due_at,
                }),
                // Another version's: dropped, lest the others don't run for it.
                Err(error) => {
                    warn!(%error, id = row.id, "dropping a queued job that doesn't read");
                    query!("DELETE FROM jobs WHERE id = ?", row.id)
                        .execute(&self.db)
                        .await?;
                }
            }
        }
        Ok(jobs)
    }

    async fn finish_job(&mut self, job: &QueuedJob) -> Result<(), Self::ContentsStoreError> {
        let (id, generation) = (job.id as i64, job.generation as i64);
        query!(
            "DELETE FROM jobs WHERE id = ? AND generation = ?",
            id,
            generation
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn retry_job(
        &mut self,
        job: &QueuedJob,
        due_at: u64,
    ) -> Result<(), Self::ContentsStoreError> {
        let (id, generation) = (job.id as i64, job.generation as i64);
        let due_at = due_at as i64;
        query!(
            "UPDATE jobs SET attempts = attempts + 1, due_at = ?
            WHERE id = ? AND generation = ?",
            due_at,
            id,
            generation,
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn thread_for_sender_and_timestamp(
        &self,
        sender: &ServiceId,
        timestamp: u64,
    ) -> Result<Option<Thread>, Self::ContentsStoreError> {
        let timestamp: i64 = timestamp
            .try_into()
            .map_err(|_| SqliteStoreError::InvalidFormat)?;
        let sender_service_id = sender.service_id_string();
        let thread = query!(r#"SELECT group_master_key, recipient_id AS "recipient_id: Uuid" FROM threads JOIN thread_messages ON threads.id = thread_messages.thread_id WHERE sender_service_id = ? AND ts = ?"#, sender_service_id, timestamp)
            .fetch_optional(&self.db).await?;

        let Some(thread) = thread else {
            return Ok(None);
        };

        match (thread.group_master_key, thread.recipient_id) {
            (Some(group_master_key), None) => {
                Ok(group_master_key.try_into().ok().map(Thread::Group))
            }
            (None, Some(contact)) => Ok(Some(Thread::Contact(ServiceId::Aci(contact.into())))),
            _ => panic!("Thread table stored both group master key and recipient"),
        }
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
            Thread::Contact(service_id) => Some(service_id.raw_uuid()),
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::OnNewIdentity;

    #[tokio::test]
    async fn upsert_profile_key_reports_the_write() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let uuid = Uuid::nil();
        let key = ProfileKey::create([1u8; 32]);

        assert!(store.upsert_profile_key(&uuid, key).await?);
        assert!(store.upsert_profile_key(&uuid, key).await?);

        Ok(())
    }

    #[tokio::test]
    async fn saving_a_left_group_clears_the_mark() -> Result<(), Box<dyn std::error::Error>> {
        let store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let master_key = [1u8; 32];

        assert!(!store.is_group_left(master_key).await?);
        store.mark_group_left(master_key).await?;
        store.mark_group_left(master_key).await?;
        assert!(store.is_group_left(master_key).await?);

        let group = Group {
            title: "group".into(),
            avatar: String::new(),
            disappearing_messages_timer: None,
            access_control: None,
            revision: 1,
            members: vec![],
            pending_members: vec![],
            requesting_members: vec![],
            invite_link_password: vec![],
            description: None,
        };
        store.save_group(master_key, group).await?;
        assert!(!store.is_group_left(master_key).await?);

        Ok(())
    }

    fn message(sender: ServiceId, ts: u64, body: presage::proto::DataMessage) -> Content {
        use chrono::TimeZone;
        let at = chrono::Utc.timestamp_millis_opt(ts as i64).unwrap();
        Content {
            metadata: Metadata {
                sender,
                destination: sender,
                sender_device: 1.try_into().unwrap(),
                client_timestamp: at,
                server_timestamp: at,
                needs_receipt: false,
                unidentified_sender: false,
                server_guid: None,
                was_plaintext: false,
                pni_verified: None,
            },
            body: body.into(),
        }
    }

    fn data(timestamp: u64) -> presage::proto::DataMessage {
        presage::proto::DataMessage {
            body: Some(format!("{timestamp}")),
            timestamp: Some(timestamp),
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn finds_a_message_by_its_latest_edit() -> Result<(), Box<dyn std::error::Error>> {
        use presage::libsignal_service::content::ContentBody;
        use presage::proto::EditMessage;
        use presage::store::ContentExt;

        let store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let sender = ServiceId::Aci(Uuid::from_u128(7).into());
        let other = ServiceId::Aci(Uuid::from_u128(8).into());
        let thread = Thread::Contact(sender);
        store
            .save_message(&thread, message(sender, 1_000, data(1_000)))
            .await?;
        // An edit takes its message's place, as presage stores it.
        let mut edit = message(sender, 1_000, data(1_000));
        edit.body = ContentBody::EditMessage(EditMessage {
            target_sent_timestamp: Some(1_000),
            data_message: Some(data(2_000)),
        });
        store.save_message(&thread, edit).await?;

        let (store, thread) = (&store, &thread);
        let found = |sender, timestamp| async move {
            let found = store.message_sent_or_edited_at(thread, sender, timestamp);
            found.await.map(|found| found.map(|c| c.edited_at()))
        };
        assert_eq!(found(&sender, 1_000).await?, Some(Some(2_000)));
        assert_eq!(found(&sender, 2_000).await?, Some(Some(2_000)));
        assert_eq!(found(&sender, 3_000).await?, None);
        // Only its sender's.
        assert_eq!(found(&other, 1_000).await?, None);
        assert_eq!(found(&other, 2_000).await?, None);
        Ok(())
    }

    #[tokio::test]
    async fn stored_messages_survive_the_change_of_their_key()
    -> Result<(), Box<dyn std::error::Error>> {
        use sqlx::migrate::Migrator;
        use sqlx::sqlite::SqlitePoolOptions;

        // One connection: the database is in memory.
        let db = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await?;
        let all = sqlx::migrate!();
        let before = Migrator {
            migrations: all
                .migrations
                .iter()
                .filter(|migration| migration.version < 20261110120000)
                .cloned()
                .collect(),
            ..sqlx::migrate!()
        };
        before.run(&db).await?;

        let sender = ServiceId::Aci(Uuid::from_u128(7).into());
        let body = prost::Message::encode_to_vec(
            &presage::libsignal_service::content::ContentBody::from(data(1_000)).into_proto(),
        );
        sqlx::query("INSERT INTO threads (id, recipient_id) VALUES (1, ?)")
            .bind(sender.raw_uuid())
            .execute(&db)
            .await?;
        sqlx::query(
            "INSERT INTO thread_messages (ts, thread_id, sender_service_id, sender_device_id,
                destination_service_id, needs_receipt, unidentified_sender, content_body,
                was_plaintext)
            VALUES (1000, 1, ?, 1, ?, false, false, ?, false)",
        )
        .bind(sender.service_id_string())
        .bind(sender.service_id_string())
        .bind(body)
        .execute(&db)
        .await?;

        all.run(&db).await?;
        let store = SqliteStore {
            db,
            trust_new_identities: OnNewIdentity::Trust,
        };
        let thread = Thread::Contact(sender);
        let stored = store.message(&thread, &sender, 1_000).await?.unwrap();
        assert_eq!(stored.metadata.sender, sender);
        // Another sender's message at the same time is kept beside it now.
        let other = ServiceId::Aci(Uuid::from_u128(8).into());
        store
            .save_message(&thread, message(other, 1_000, data(1_000)))
            .await?;
        assert_eq!(store.messages(&thread, ..).await?.count(), 2);
        Ok(())
    }

    #[tokio::test]
    async fn keeps_two_senders_at_one_millisecond() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let (ann, bob) = (
            ServiceId::Aci(Uuid::from_u128(7).into()),
            ServiceId::Aci(Uuid::from_u128(8).into()),
        );
        let thread = Thread::Group([1; 32]);
        for (sender, ts) in [(ann, 1), (ann, 2), (bob, 2), (ann, 3)] {
            store
                .save_message(&thread, message(sender, ts, data(ts)))
                .await?;
        }
        let sender_at = |content: Option<Content>| content.map(|c| c.metadata.sender);
        assert_eq!(sender_at(store.message(&thread, &ann, 2).await?), Some(ann));
        assert_eq!(sender_at(store.message(&thread, &bob, 2).await?), Some(bob));
        assert_eq!(store.messages(&thread, ..).await?.count(), 4);

        assert!(store.delete_message(&thread, &bob, 2).await?);
        assert!(store.message(&thread, &bob, 2).await?.is_none());
        assert_eq!(sender_at(store.message(&thread, &ann, 2).await?), Some(ann));
        Ok(())
    }

    fn fetch_profile(profile_key: [u8; 32]) -> Job {
        Job::FetchProfile {
            aci: [1; 16],
            profile_key,
            expire_timer: 0,
            expire_timer_version: 1,
        }
    }

    #[tokio::test]
    async fn a_job_waits_until_finished() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let install = Job::InstallStickerPack {
            pack_id: vec![1; 16],
            pack_key: vec![2; 32],
        };
        let update = Job::UpdateGroup {
            master_key: [3; 32],
            revision: 4,
        };
        store.enqueue_job(&install).await?;
        store.enqueue_job(&update).await?;

        let jobs = store.jobs().await?;
        assert_eq!(
            jobs.iter().map(|queued| &queued.job).collect::<Vec<_>>(),
            [&install, &update]
        );

        store.retry_job(&jobs[0], 5_000).await?;
        let retried = &store.jobs().await?[0];
        assert_eq!((retried.attempts, retried.due_at), (1, 5_000));

        store.finish_job(&jobs[0]).await?;
        assert_eq!(store.jobs().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn a_job_queued_again_takes_the_place_of_the_one_waiting()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        store.enqueue_job(&fetch_profile([2; 32])).await?;
        let running = store.jobs().await?.remove(0);
        store.retry_job(&running, 5_000).await?;

        store.enqueue_job(&fetch_profile([3; 32])).await?;
        let jobs = store.jobs().await?;
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].job, fetch_profile([3; 32]));
        assert_eq!((jobs[0].attempts, jobs[0].due_at), (0, 0));

        // The one that ran meanwhile doesn't take the new one with it.
        store.finish_job(&running).await?;
        assert_eq!(store.jobs().await?.len(), 1);
        Ok(())
    }

    #[tokio::test]
    async fn the_same_job_queued_again_keeps_waiting() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        store.enqueue_job(&Job::SyncStorage).await?;
        let failed = store.jobs().await?.remove(0);
        store.retry_job(&failed, 5_000).await?;

        store.enqueue_job(&Job::SyncStorage).await?;
        let waiting = &store.jobs().await?[0];
        assert_eq!((waiting.attempts, waiting.due_at), (1, 5_000));
        Ok(())
    }

    #[tokio::test]
    async fn a_run_settles_only_the_job_it_began_with() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        store.enqueue_job(&fetch_profile([2; 32])).await?;
        let running = store.jobs().await?.remove(0);

        // Another took its place meanwhile, and one the same as it took that one's.
        store.enqueue_job(&fetch_profile([3; 32])).await?;
        store.enqueue_job(&fetch_profile([2; 32])).await?;
        store.retry_job(&running, 5_000).await?;
        store.finish_job(&running).await?;
        let waiting = store.jobs().await?.remove(0);
        assert_eq!(
            (waiting.id, waiting.attempts, waiting.due_at),
            (running.id, 0, 0)
        );

        store.finish_job(&waiting).await?;
        assert!(store.jobs().await?.is_empty());
        Ok(())
    }

    #[tokio::test]
    async fn a_job_that_does_not_read_is_dropped() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        sqlx::query(r#"INSERT INTO jobs (key, job) VALUES ('later', '"OfALaterVersion"')"#)
            .execute(&store.db)
            .await?;
        store.enqueue_job(&Job::AnswerKeys).await?;

        let jobs = store.jobs().await?;
        assert_eq!(
            jobs.iter().map(|queued| &queued.job).collect::<Vec<_>>(),
            [&Job::AnswerKeys]
        );
        let kept: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs")
            .fetch_one(&store.db)
            .await?;
        assert_eq!(kept, 1);
        Ok(())
    }

    #[tokio::test]
    async fn clearing_forgets_the_jobs_and_the_manifest_read()
    -> Result<(), Box<dyn std::error::Error>> {
        use presage::store::{StateStore, Store};

        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let manifest = Freshness {
            version: Some(3),
            fetched_at: 1_000,
        };
        for clear in 0..3 {
            store.enqueue_job(&Job::SyncStorage).await?;
            store
                .set_replica(&Replica::StorageManifest, manifest)
                .await?;
            match clear {
                0 => store.clear_contents().await?,
                1 => store.clear_registration().await?,
                _ => store.clear().await?,
            }
            assert!(store.jobs().await?.is_empty());
            assert_eq!(store.replica(&Replica::StorageManifest).await?, None);
        }
        Ok(())
    }

    #[tokio::test]
    async fn a_replica_is_as_fresh_as_last_noted() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let profile = Replica::Profile(Uuid::from_u128(7));
        assert_eq!(store.replica(&profile).await?, None);

        let fetched = |fetched_at| Freshness {
            version: None,
            fetched_at,
        };
        store.set_replica(&profile, fetched(1_000)).await?;
        store.set_replica(&profile, fetched(2_000)).await?;
        assert_eq!(store.replica(&profile).await?, Some(fetched(2_000)));
        assert_eq!(
            store.replica(&Replica::Profile(Uuid::from_u128(8))).await?,
            None
        );

        let manifest = Freshness {
            version: Some(3),
            fetched_at: 1_000,
        };
        store
            .set_replica(&Replica::StorageManifest, manifest)
            .await?;
        store.clear_groups().await?;
        assert_eq!(store.replica(&Replica::StorageManifest).await?, None);
        assert_eq!(store.replica(&profile).await?, Some(fetched(2_000)));

        store.clear_profiles().await?;
        assert_eq!(store.replica(&profile).await?, None);
        Ok(())
    }
}
