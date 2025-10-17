use std::borrow::Cow;

use bytes::Bytes;
use presage::{
    libsignal_service::{
        Profile,
        content::Metadata,
        models::Attachment,
        prelude::{AccessControl, Content, phonenumber},
        profile_name::ProfileName,
        protocol::ServiceId,
        zkgroup::GroupMasterKeyBytes,
    },
    model::{
        contacts::Contact,
        groups::{Group, Member, PendingMember, RequestingMember},
    },
    proto::{self, Verified, verified},
    store::{StickerPack, StickerPackManifest},
};
use sqlx::types::Json;
use uuid::Uuid;

use crate::SqliteStoreError;

#[derive(Debug)]
pub struct SqlContact {
    pub uuid: Uuid,
    pub phone_number: Option<String>,
    pub name: String,
    pub profile_key: Vec<u8>,
    pub expire_timer: i64,
    pub expire_timer_version: i64,
    pub inbox_position: i64,
    pub avatar: Option<Vec<u8>>,

    pub destination_aci: Option<String>,
    pub identity_key: Option<Vec<u8>>,
    pub is_verified: Option<bool>,
}

impl TryInto<Contact> for SqlContact {
    type Error = SqliteStoreError;

    #[tracing::instrument]
    fn try_into(self) -> Result<Contact, Self::Error> {
        Ok(Contact {
            uuid: self.uuid,
            phone_number: self
                .phone_number
                .map(|p| phonenumber::parse(None, &p))
                .transpose()?,
            name: self.name,
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
            avatar: self.avatar.map(|b| Attachment {
                content_type: "application/octet-stream".to_owned(),
                reader: Bytes::from(b),
            }),
        })
    }
}

#[derive(Debug)]
pub struct SqlProfile {
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub about: Option<String>,
    pub about_emoji: Option<String>,
    pub avatar: Option<String>,
    pub unrestricted_unidentified_access: bool,
}

impl From<SqlProfile> for Profile {
    fn from(
        SqlProfile {
            given_name,
            family_name,
            about,
            about_emoji,
            avatar,
            unrestricted_unidentified_access,
        }: SqlProfile,
    ) -> Self {
        Profile {
            name: given_name.map(|gn| ProfileName {
                given_name: gn,
                family_name,
            }),
            about,
            about_emoji,
            avatar,
            unrestricted_unidentified_access,
        }
    }
}

#[derive(Debug)]
pub(crate) struct SqlGroup<'a> {
    pub(crate) master_key: Cow<'a, [u8]>,
    pub(crate) title: String,
    pub(crate) revision: u32,
    pub(crate) invite_link_password: Option<Vec<u8>>,
    pub(crate) access_control: Option<Json<AccessControl>>,
    pub(crate) avatar: String,
    pub(crate) description: Option<String>,
    pub(crate) members: Json<Vec<Member>>,
    pub(crate) pending_members: Json<Vec<PendingMember>>,
    pub(crate) requesting_members: Json<Vec<RequestingMember>>,
}

impl SqlGroup<'_> {
    #[tracing::instrument]
    pub fn from_group(master_key: &GroupMasterKeyBytes, group: Group) -> SqlGroup<'_> {
        SqlGroup {
            master_key: Cow::Borrowed(master_key.as_slice()),
            title: group.title,
            revision: group.revision,
            invite_link_password: Some(group.invite_link_password),
            access_control: group.access_control.map(Json),
            avatar: group.avatar,
            description: group.description,
            members: Json(group.members),
            pending_members: Json(group.pending_members),
            requesting_members: Json(group.requesting_members),
        }
    }

    #[tracing::instrument]
    pub fn into_group(self) -> Result<(GroupMasterKeyBytes, Group), SqliteStoreError> {
        let Self {
            master_key,
            title,
            revision,
            invite_link_password,
            access_control,
            avatar,
            description,
            members: Json(members),
            pending_members: Json(pending_members),
            requesting_members: Json(requesting_members),
        } = self;
        let master_key = master_key
            .as_ref()
            .try_into()
            .map_err(|_| SqliteStoreError::InvalidFormat)?;
        let access_control = access_control.map(|Json(x)| x);
        let group = Group {
            title,
            avatar,
            disappearing_messages_timer: None,
            access_control,
            revision,
            members,
            pending_members,
            requesting_members,
            invite_link_password: invite_link_password.unwrap_or_default(),
            description,
        };
        Ok((master_key, group))
    }
}

#[derive(Debug)]
pub struct SqlMessage {
    pub ts: u64,

    pub sender_service_id: String,
    pub sender_device_id: u8,
    pub destination_service_id: String,
    pub needs_receipt: bool,
    pub unidentified_sender: bool,

    pub content_body: Vec<u8>,
    pub was_plaintext: bool,
}

impl TryInto<Content> for SqlMessage {
    type Error = SqliteStoreError;

    #[tracing::instrument]
    fn try_into(self) -> Result<Content, Self::Error> {
        let Self {
            ts,
            sender_service_id,
            sender_device_id,
            destination_service_id,
            needs_receipt,
            unidentified_sender,
            content_body,
            was_plaintext,
        } = self;
        let body: proto::Content =
            prost::Message::decode(&*content_body).map_err(|_| SqliteStoreError::InvalidFormat)?;
        let sender = ServiceId::parse_from_service_id_string(&sender_service_id)
            .ok_or_else(|| SqliteStoreError::InvalidFormat)?;
        let destination = ServiceId::parse_from_service_id_string(&destination_service_id)
            .ok_or_else(|| SqliteStoreError::InvalidFormat)?;
        let metadata = Metadata {
            sender,
            destination,
            sender_device: sender_device_id.try_into()?,
            timestamp: ts,
            needs_receipt,
            unidentified_sender,
            server_guid: None,
            was_plaintext,
        };
        Content::from_proto(body, metadata).map_err(|_| SqliteStoreError::InvalidFormat)
    }
}

pub(crate) struct SqlStickerPack {
    pub(crate) id: Vec<u8>,
    pub(crate) key: Vec<u8>,
    pub(crate) manifest: Json<StickerPackManifest>,
}

impl From<SqlStickerPack> for StickerPack {
    fn from(
        SqlStickerPack {
            id,
            key,
            manifest: Json(manifest),
        }: SqlStickerPack,
    ) -> Self {
        StickerPack { id, key, manifest }
    }
}
