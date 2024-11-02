use bytes::Bytes;
use presage::{
    libsignal_service::{
        content::Metadata,
        models::Attachment,
        prelude::{phonenumber, Content},
        profile_name::ProfileName,
        protocol::ServiceId,
        zkgroup::GroupMasterKeyBytes,
        Profile,
    },
    model::{
        contacts::Contact,
        groups::{Group, Member, PendingMember, RequestingMember},
    },
    proto::{self, verified, Verified},
};

use crate::SqliteStoreError;

#[derive(Debug, sqlx::FromRow)]
pub struct SqlContact {
    pub uuid: String,
    pub phone_number: Option<String>,
    pub name: String,
    pub color: Option<String>,
    pub profile_key: Vec<u8>,
    pub expire_timer: i64,
    pub expire_timer_version: i64,
    pub inbox_position: i64,
    pub archived: bool,
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

#[derive(Debug, sqlx::FromRow)]
pub struct SqlProfile {
    pub uuid: String,
    pub key: Vec<u8>,
    pub given_name: Option<String>,
    pub family_name: Option<String>,
    pub about: Option<String>,
    pub about_emoji: Option<String>,
    pub avatar: Option<String>,
}

impl TryInto<Profile> for SqlProfile {
    type Error = SqliteStoreError;

    #[tracing::instrument]
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

#[derive(Debug, sqlx::FromRow)]
pub struct SqlGroup {
    pub id: Option<i64>,
    pub master_key: Vec<u8>,
    pub title: String,
    pub revision: i64,
    pub invite_link_password: Option<Vec<u8>>,
    pub access_required: Option<Vec<u8>>,
    pub avatar: String,
    pub description: Option<String>,
    pub members: Vec<u8>,
    pub pending_members: Vec<u8>,
    pub requesting_members: Vec<u8>,
}

impl SqlGroup {
    #[tracing::instrument]
    pub fn from_group(
        master_key: GroupMasterKeyBytes,
        group: Group,
    ) -> Result<SqlGroup, SqliteStoreError> {
        Ok(SqlGroup {
            id: None,
            master_key: master_key.to_vec(),
            title: group.title,
            revision: group.revision as i64,
            invite_link_password: Some(group.invite_link_password),
            access_required: group
                .access_control
                .map(|ac| postcard::to_allocvec(&ac))
                .transpose()?,
            avatar: group.avatar,
            description: group.description,
            members: postcard::to_allocvec(&group.members)?,
            pending_members: postcard::to_allocvec(&group.pending_members)?,
            requesting_members: postcard::to_allocvec(&group.requesting_members)?,
        })
    }

    #[tracing::instrument]
    pub fn into_group(self) -> Result<Group, SqliteStoreError> {
        let members: Vec<Member> = postcard::from_bytes(&self.members)?;
        let pending_members: Vec<PendingMember> = postcard::from_bytes(&self.pending_members)?;
        let requesting_members: Vec<RequestingMember> =
            postcard::from_bytes(&self.requesting_members)?;
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

#[derive(Debug, sqlx::FromRow)]
pub struct SqlMessage {
    pub ts: i64,
    pub thread_id: i64,

    pub sender_service_id: String,
    pub sender_device_id: i64,
    pub destination_service_id: String,
    pub needs_receipt: bool,
    pub unidentified_sender: bool,

    pub content_body: Vec<u8>,
}

impl TryInto<Content> for SqlMessage {
    type Error = SqliteStoreError;

    #[tracing::instrument]
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
