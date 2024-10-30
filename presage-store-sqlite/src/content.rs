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
use sqlx::{query, query_as, query_scalar, types::Uuid};
use tracing::warn;
use uuid::timestamp;

use crate::{SqliteStore, SqliteStoreError};

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
        Ok(())
    }

    async fn clear_messages(&mut self) -> Result<(), Self::ContentsStoreError> {
        query!("DELETE FROM threads").execute(&self.db).await?;
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
                "
                    DELETE FROM thread_messages WHERE ts = ? AND thread_id IN (
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
            warn!("no thread found");
            // TODO: return error?
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
        todo!()
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

        tx.commit().await;

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
                access_required_for_attributes,
                access_required_for_members,
                access_required_for_add_from_invite_link,
                avatar,
                description,
                members,
                pending_members,
                requesting_members
            ) VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            group.master_key,
            group.title,
            group.revision,
            group.invite_link_password,
            group.access_required_for_attributes,
            group.access_required_for_members,
            group.access_required_for_add_from_invite_link,
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
        todo!()
    }

    async fn group_avatar(
        &self,
        master_key: zkgroup::GroupMasterKeyBytes,
    ) -> Result<Option<presage::AvatarBytes>, Self::ContentsStoreError> {
        todo!()
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
        todo!()
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
        key: ProfileKey,
        profile: &presage::AvatarBytes,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn profile_avatar(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> Result<Option<presage::AvatarBytes>, Self::ContentsStoreError> {
        todo!()
    }

    async fn add_sticker_pack(
        &mut self,
        pack: &StickerPack,
    ) -> Result<(), Self::ContentsStoreError> {
        todo!()
    }

    async fn sticker_pack(
        &self,
        id: &[u8],
    ) -> Result<Option<StickerPack>, Self::ContentsStoreError> {
        todo!()
    }

    async fn remove_sticker_pack(&mut self, id: &[u8]) -> Result<bool, Self::ContentsStoreError> {
        todo!()
    }

    async fn sticker_packs(&self) -> Result<Self::StickerPacksIter, Self::ContentsStoreError> {
        todo!()
    }
}

impl SqliteStore {
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

struct SqlContact {
    uuid: String,
    phone_number: Option<String>,
    name: String,
    color: Option<String>,
    profile_key: Vec<u8>,
    expire_timer: i64,
    expire_timer_version: i64,
    inbox_position: i64,
    archived: bool,
    avatar: Option<Vec<u8>>,

    destination_aci: Option<String>,
    identity_key: Option<Vec<u8>>,
    is_verified: Option<bool>,
}

impl TryInto<Contact> for SqlContact {
    type Error = SqliteStoreError;

    fn try_into(self) -> Result<Contact, Self::Error> {
        Ok(Contact {
            uuid: self.uuid.parse()?,
            phone_number: self
                .phone_number
                .map(|p| phonenumber::parse(None, &p))
                .transpose()?,
            name: self.name,
            color: self.color,
            verified: Verified {
                destination_aci: self.destination_aci,
                identity_key: self.identity_key,
                state: self.is_verified.map(|v| {
                    match v {
                        true => verified::State::Verified,
                        false => verified::State::Unverified,
                    }
                    .into()
                }),
                null_message: None,
            },
            profile_key: self.profile_key,
            expire_timer: self.expire_timer as u32,
            expire_timer_version: self.expire_timer_version as u32,
            inbox_position: self.inbox_position as u32,
            archived: self.archived,
            avatar: self.avatar.map(|b| Attachment {
                content_type: "application/octet-stream".into(),
                reader: Bytes::from(b),
            }),
        })
    }
}

struct SqlProfile {
    uuid: String,
    key: Vec<u8>,
    given_name: Option<String>,
    family_name: Option<String>,
    about: Option<String>,
    about_emoji: Option<String>,
    avatar: Option<String>,
}

impl TryInto<Profile> for SqlProfile {
    type Error = SqliteStoreError;

    fn try_into(self) -> Result<Profile, Self::Error> {
        Ok(Profile {
            name: self.given_name.map(|gn| ProfileName {
                given_name: gn,
                family_name: self.family_name,
            }),
            about: self.about,
            about_emoji: self.about_emoji,
            avatar: self.avatar,
        })
    }
}

struct SqlMessage {
    ts: i64,
    thread_id: i64,

    sender_service_id: String,
    sender_device_id: i64,
    destination_service_id: String,
    needs_receipt: bool,
    unidentified_sender: bool,

    content_body: Vec<u8>,
}

impl TryInto<Content> for SqlMessage {
    type Error = SqliteStoreError;

    fn try_into(self) -> Result<Content, Self::Error> {
        let body: proto::Content = prost::Message::decode(&self.content_body[..]).unwrap();
        let sender_service_id =
            ServiceId::parse_from_service_id_string(&self.sender_service_id).unwrap();
        let destination_service_id =
            ServiceId::parse_from_service_id_string(&self.destination_service_id).unwrap();
        Content::from_proto(
            body,
            Metadata {
                sender: sender_service_id.into(),
                destination: destination_service_id.into(),
                sender_device: self.sender_device_id.try_into().unwrap(),
                timestamp: self.ts.try_into().unwrap(),
                needs_receipt: self.needs_receipt,
                unidentified_sender: self.unidentified_sender,
                server_guid: None,
            },
        )
        .map_err(|err| SqliteStoreError::InvalidFormat)
    }
}

struct SqlGroup {
    pub id: Option<i64>,
    pub master_key: Vec<u8>,
    pub title: String,
    pub revision: i64,
    pub invite_link_password: Option<Vec<u8>>,
    pub access_required_for_attributes: i64,
    pub access_required_for_members: i64,
    pub access_required_for_add_from_invite_link: i64,
    pub avatar: String,
    pub description: Option<String>,
    pub members: Vec<u8>,
    pub pending_members: Vec<u8>,
    pub requesting_members: Vec<u8>,
}

impl SqlGroup {
    fn from_group(
        master_key: GroupMasterKeyBytes,
        group: Group,
    ) -> Result<SqlGroup, SqliteStoreError> {
        let (
            access_required_for_attributes,
            access_required_for_members,
            access_required_for_add_from_invite_link,
        ) = match group.access_control {
            Some(AccessControl {
                attributes,
                members,
                add_from_invite_link,
            }) => {
                // TODO: talk to Ruben about making AccessRequired some indexed enum? with repr(u8)
                (0, 0, 0)
            }
            None => (0, 0, 0),
        };

        Ok(SqlGroup {
            id: None,
            master_key: master_key.to_vec(),
            title: group.title,
            revision: group.revision as i64,
            invite_link_password: Some(group.invite_link_password),
            access_required_for_attributes: 0,
            access_required_for_members: 0,
            access_required_for_add_from_invite_link: 0,
            avatar: group.avatar,
            description: group.description,
            members: serde_json::to_vec(&group.members)?,
            pending_members: serde_json::to_vec(&group.pending_members)?,
            requesting_members: serde_json::to_vec(&group.requesting_members)?,
        })
    }

    fn into_group(self) -> Result<Group, SqliteStoreError> {
        let members: Vec<Member> = serde_json::from_slice(&self.members)?;
        let pending_members: Vec<PendingMember> = serde_json::from_slice(&self.pending_members)?;
        let requesting_members: Vec<RequestingMember> =
            serde_json::from_slice(&self.requesting_members)?;
        Ok(Group {
            title: self.title,
            avatar: self.avatar,
            disappearing_messages_timer: None,
            access_control: None,
            revision: self.revision.try_into()?,
            members,
            pending_members,
            requesting_members,
            invite_link_password: self.invite_link_password.unwrap_or_default(),
            description: self.description,
        })
    }
}
