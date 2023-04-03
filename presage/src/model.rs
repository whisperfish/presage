use std::{collections::HashSet, fmt::Display};

use crate::{prelude::proto, Error};
use libsignal_service::{
    content::{ContentBody, DataMessageFlags},
    prelude::{phonenumber::PhoneNumber, Content, Uuid},
    proto::{
        access_control::AccessRequired,
        data_message::{Contact, Sticker},
        member::Role,
        receipt_message::Type,
        sync_message::Sent,
        AttachmentPointer, DataMessage, GroupContextV2, Preview, SyncMessage,
    },
    Profile,
};

use libsignal_service::groups_v2 as lssg;

pub type Timestamp = u64;
pub type ProfileKey = [u8; 32];
pub type GroupId = [u8; 16];
pub type GroupRevision = u32;
pub type MessageId = (Timestamp, ConversationId);

/// A user of Signal.
#[derive(Debug, Clone)]
pub struct Recipient {
    pub uuid: Uuid,
    pub phone_number: Option<PhoneNumber>,
    /// The name you gave this user.
    pub username: Option<String>,

    pub blocked: bool,
    pub archived: bool,

    pub color: Option<String>,

    pub profile_key: ProfileKey,
    // pub profile_key_credential: Option<Vec<u8>>,
    /// The profile of this user including the information he published himself.
    pub profile: Option<Profile>,
    // pub signal_profile_avatar: Option<String>,
    // pub profile_sharing: bool,

    // pub last_profile_fetch: Option<NaiveDateTime>,
    // pub unidentified_access_mode: bool,
    // pub storage_service_id: Option<Vec<u8>>,
    // pub storage_proto: Option<Vec<u8>>,

    // pub capabilities: i32,
    // pub last_session_reset: Option<NaiveDateTime>,

    // TODO: Better type?
    pub expire_timer: u32,
}

impl Into<Recipient> for crate::prelude::Contact {
    fn into(self) -> Recipient {
        Recipient {
            uuid: self.uuid,
            phone_number: self.phone_number,
            username: if self.name.is_empty() {
                None
            } else {
                Some(self.name)
            },
            blocked: self.blocked,
            archived: self.archived,
            color: self.color,
            // XXX: Maybe try_into?
            profile_key: self
                .profile_key
                .try_into()
                .expect("Profile Key to have 32 bytes"),
            // XXX: Automatically set in manager.
            profile: None,
            expire_timer: self.expire_timer,
        }
    }
}

impl Into<crate::prelude::Contact> for Recipient {
    fn into(self) -> crate::prelude::Contact {
        crate::prelude::Contact {
            uuid: self.uuid,
            phone_number: self.phone_number,
            name: self.username.unwrap_or_default(),
            color: self.color,
            // XXX: Fill out?
            verified: Default::default(),
            profile_key: self.profile_key.into(),
            blocked: self.blocked,
            expire_timer: self.expire_timer,
            // XXX: Fill out?
            inbox_position: 0,
            archived: self.archived,
            // XXX: Fill out?
            avatar: None,
        }
    }
}

impl Display for Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(name) = self.username.as_ref() {
            write!(f, "{}", name)
        } else if let Some(profile_name) = self.profile.as_ref().and_then(|p| p.name.as_ref()) {
            if let Some(family_name) = profile_name.family_name.as_ref() {
                // XXX: Maybe implement right-to-left?
                write!(f, "{} {}", profile_name.given_name, family_name)
            } else {
                write!(f, "{}", profile_name.given_name)
            }
        } else if let Some(phone) = self.phone_number.as_ref() {
            write!(f, "{}", phone)
        } else {
            write!(f, "{}", self.uuid)
        }
    }
}

#[derive(Debug, Clone)]
pub struct GroupAccessControl {
    pub attributes: AccessRequired,
    pub members: AccessRequired,
    pub add_from_invite_link: AccessRequired,
}

#[derive(Debug, Clone)]
pub struct Group {
    pub id: GroupId,
    pub name: String,

    pub master_key: [u8; 16],
    pub revision: GroupRevision,

    pub invite_link_password: Option<String>,

    pub access: Option<GroupAccessControl>,

    // pub avatar: Option<String>,
    pub description: Option<String>,
    pub expire_timer: Option<u32>,
    pub announcements_only: bool,

    pub members: Vec<GroupMember>,
    pub pending_members: Vec<PendingGroupMember>,
    pub requesting_members: Vec<RequestingGroupMember>,
    // TODO: For some reason not in `lssg::Group`, but in `proto::Group`,
    // pub banned_members: Vec<BannedGroupMember>,
}

impl Into<lssg::Group> for Group {
    fn into(self) -> lssg::Group {
        lssg::Group {
            title: self.name,
            // XXX: Fill out?
            avatar: Default::default(),
            disappearing_messages_timer: self.expire_timer.map(|t| lssg::Timer { duration: t }),
            access_control: self.access.map(|a| proto::AccessControl {
                attributes: a.attributes as i32,
                members: a.members as i32,
                add_from_invite_link: a.add_from_invite_link as i32,
            }),
            revision: self.revision,
            members: vec![],
            pending_members: vec![],
            requesting_members: vec![],
            invite_link_password: self.invite_link_password.unwrap_or_default().into(),
            description: self.description,
            // // TODO: What is this?
            // public_key: vec![],
            // title: self.name.into(),
            // // XXX: Fill out?
            // avatar: Default::default(),
            // // TODO: Is this correct?
            // disappearing_messages_timer: self.expire_timer.to_le_bytes().into(),
            // access_control: self.access.map(|a| proto::AccessControl {
            //     attributes: a.attributes as i32,
            //     members: a.members as i32,
            //     add_from_invite_link: a.add_from_invite_link as i32,
            // }),
            // revision: self.revision,
            // members: self.members.into_iter().map(Into::into).collect(),
            // pending_members: self.pending_members.into_iter().map(Into::into).collect(),
            // requesting_members: self
            //     .requesting_members
            //     .into_iter()
            //     .map(Into::into)
            //     .collect(),
            // invite_link_password: self
            //     .invite_link_password
            //     .map(|d| d.into())
            //     .unwrap_or_default(),
            // description: self.description.map(|d| d.into()).unwrap_or_default(),
            // announcements_only: self.announcements_only,
            // banned_members: self.banned_members.into_iter().map(Into::into).collect(),
        }
    }
}

impl Into<Group> for lssg::Group {
    fn into(self) -> Group {
        Group {
            // TODO: Where is this?
            id: [0; 16],
            name: self.title,
            // TODO: Where is this?
            master_key: [0; 16],
            revision: self.revision,
            invite_link_password: if self.invite_link_password.is_empty() {
                None
            } else {
                String::from_utf8(self.invite_link_password).ok()
            },
            access: self.access_control.map(|a| GroupAccessControl {
                attributes: a.attributes(),
                members: a.members(),
                add_from_invite_link: a.add_from_invite_link(),
            }),
            description: self.description,
            // TODO: Correct?
            expire_timer: self.disappearing_messages_timer.map(|t| t.duration),
            // TODO: Where is this?
            announcements_only: false,
            members: self.members.into_iter().map(Into::into).collect(),
            pending_members: self.pending_members.into_iter().map(Into::into).collect(),
            requesting_members: self
                .requesting_members
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct GroupMember {
    pub uuid: Uuid,
    pub member_since: Timestamp,
    pub joined_at_revision: GroupRevision,
    pub role: Role,
}

impl Into<lssg::Member> for GroupMember {
    fn into(self) -> lssg::Member {
        lssg::Member {
            uuid: self.uuid,
            role: self.role,
            joined_at_revision: self.joined_at_revision,
            /// XXX: Set?
            profile_key: libsignal_service::prelude::ProfileKey { bytes: [0; 32] },
        }
    }
}

impl Into<GroupMember> for lssg::Member {
    fn into(self) -> GroupMember {
        GroupMember {
            uuid: self.uuid,
            // XXX: Fill out?
            member_since: 0,
            joined_at_revision: self.joined_at_revision,
            role: self.role,
        }
    }
}

/// XXX: Maybe use `llsg::PendingMember` instead?
#[derive(Debug, Clone)]
pub struct PendingGroupMember {
    pub uuid: Uuid,
    pub role: Role,
    pub added_by_uuid: Uuid,
    pub timestamp: Timestamp,
}

impl Into<lssg::PendingMember> for PendingGroupMember {
    fn into(self) -> lssg::PendingMember {
        lssg::PendingMember {
            uuid: self.uuid,
            added_by_uuid: self.added_by_uuid,
            timestamp: self.timestamp,
            role: self.role,
        }
    }
}

impl Into<PendingGroupMember> for lssg::PendingMember {
    fn into(self) -> PendingGroupMember {
        PendingGroupMember {
            uuid: self.uuid,
            role: self.role,
            added_by_uuid: self.added_by_uuid,
            timestamp: self.timestamp,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RequestingGroupMember {
    pub uuid: Uuid,
    pub profile_key: ProfileKey,
    pub timestamp: Timestamp,
}

impl Into<lssg::RequestingMember> for RequestingGroupMember {
    fn into(self) -> lssg::RequestingMember {
        lssg::RequestingMember {
            uuid: self.uuid,
            profile_key: libsignal_service::prelude::ProfileKey {
                bytes: self.profile_key,
            },
            timestamp: self.timestamp,
        }
    }
}

impl Into<RequestingGroupMember> for lssg::RequestingMember {
    fn into(self) -> RequestingGroupMember {
        RequestingGroupMember {
            uuid: self.uuid,
            profile_key: self.profile_key.bytes,
            timestamp: self.timestamp,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BannedGroupMember {
    pub uuid: Uuid,
    pub banned_at: Timestamp,
}

impl Into<proto::BannedMember> for BannedGroupMember {
    fn into(self) -> proto::BannedMember {
        proto::BannedMember {
            user_id: self.uuid.into_bytes().into(),
            timestamp: self.banned_at,
        }
    }
}

impl Into<BannedGroupMember> for proto::BannedMember {
    fn into(self) -> BannedGroupMember {
        BannedGroupMember {
            uuid: Uuid::from_bytes(self.user_id.try_into().unwrap_or_default()),
            banned_at: self.timestamp,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ConversationType {
    Group(Group),
    Direct(Recipient),
}

impl Into<ConversationType> for Group {
    fn into(self) -> ConversationType {
        ConversationType::Group(self)
    }
}

impl Into<ConversationType> for Recipient {
    fn into(self) -> ConversationType {
        ConversationType::Direct(self)
    }
}

#[derive(Debug, Clone)]
pub struct Conversation {
    r#type: ConversationType,
    muted: bool,
    archived: bool,
    unread_message_count: u32,
}

#[derive(Debug, Clone)]
pub enum ConversationId {
    Group(GroupId),
    Direct(Uuid),
}

impl Conversation {
    pub fn id(&self) -> ConversationId {
        match &self.r#type {
            ConversationType::Group(g) => ConversationId::Group(g.id),
            ConversationType::Direct(r) => ConversationId::Direct(r.uuid),
        }
    }
}

impl Display for Conversation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.r#type {
            ConversationType::Group(g) => write!(f, "{}", g.name),
            ConversationType::Direct(r) => write!(f, "{}", r),
        }
    }
}

impl TryFrom<&Content> for ConversationId {
    type Error = Error;

    fn try_from(content: &Content) -> Result<Self, Error> {
        match &content.body {
            // Case 1: SyncMessage sent from other device notifying about a message sent to someone else.
            // => The recipient of the message mentioned in the SyncMessage is the thread.
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        destination_uuid: Some(uuid),
                        ..
                    }),
                ..
            }) => Ok(Self::Direct(Uuid::parse_str(&uuid)?)),
            // Case 2: Received a group message
            // => The group is the thread.
            ContentBody::DataMessage(DataMessage {
                group_v2:
                    Some(GroupContextV2 {
                        master_key: Some(key),
                        ..
                    }),
                ..
            })
            | ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        message:
                            Some(DataMessage {
                                group_v2:
                                    Some(GroupContextV2 {
                                        master_key: Some(key),
                                        ..
                                    }),
                                ..
                            }),
                        ..
                    }),
                ..
            }) => Ok(Self::Group(
                // TODO: Convert the master key to the group ID.
                [0; 16],
            )),
            // Case 3: Received a 1-1 message
            // => The message sender is the thread.
            _ => Ok(Self::Direct(content.metadata.sender.uuid)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Message {
    pub timestamp: Timestamp,
    pub conversation_id: ConversationId,
    pub sender_uuid: Uuid,

    pub text: Option<String>,

    pub server_timestamp: Timestamp,
    pub is_read: bool,
    pub is_outbound: bool,
    pub flags: HashSet<DataMessageFlags>,
    pub expires_in: Option<u32>,
    pub expiry_started: Option<Timestamp>,
    pub schedule_send_time: Option<Timestamp>,
    pub is_bookmarked: bool,
    pub use_unidentified: bool,

    pub is_deleted: bool,
    pub is_view_once: bool,

    pub sending_has_failed: bool,

    pub quote_id: Option<MessageId>,
    pub contacts: Vec<Contact>,
    pub previews: Vec<Preview>,   // TODO: Custom preview type?
    pub sticker: Option<Sticker>, // TODO: Custom sticker type?

    pub attachments: Vec<AttachmentPointer>, // TODO: Custom attachment pointer type?

    /// Receipts available for this message.
    pub receipts: Vec<Receipt>,

    /// Reactions available for this message.
    pub reactions: Vec<Reaction>,
}

impl Into<proto::DataMessage> for Message {
    fn into(self) -> proto::DataMessage {
        proto::DataMessage {
            body: self.text,
            attachments: self.attachments,
            // TODO: Somehow set.
            group_v2: None,
            // XXX: Is Some(0) equivalent to None?
            flags: Some(
                self.flags
                    .into_iter()
                    .map(|f| f as u32)
                    .fold(0u32, |acc, f| acc & f),
            ),
            expire_timer: self.expires_in,
            profile_key: None,
            timestamp: Some(self.timestamp),
            // TODO: Set
            quote: None,
            contact: self.contacts,
            preview: self.previews,
            sticker: self.sticker,
            required_protocol_version: None,
            is_view_once: Some(self.is_view_once),
            reaction: None,
            delete: None,
            body_ranges: vec![],
            group_call_update: None,
            payment: None,
            story_context: None,
            gift_badge: None,
        }
    }
}

impl TryInto<Message> for crate::prelude::Content {
    type Error = ();

    fn try_into(self) -> Result<Message, Self::Error> {
        let conversation_id: ConversationId = (&self).try_into().map_err(|_| ())?;
        let body = match self.body {
            crate::prelude::ContentBody::DataMessage(d)
            | crate::prelude::ContentBody::SynchronizeMessage(proto::SyncMessage {
                sent:
                    Some(proto::sync_message::Sent {
                        message: Some(d), ..
                    }),
                ..
            }) => Ok(d),
            _ => Err(()),
        }?;

        // TODO: Filter unimportant messages (delete, recipient).

        Ok(Message {
            // XXX: unwrap_or_default?
            timestamp: self.metadata.timestamp,
            // TODO.
            conversation_id: conversation_id.clone(),
            sender_uuid: self.metadata.sender.uuid,
            text: body.body,
            // TODO.
            server_timestamp: 0,
            is_read: false,
            is_outbound: false,
            // TODO.
            flags: [
                DataMessageFlags::EndSession,
                DataMessageFlags::ExpirationTimerUpdate,
                DataMessageFlags::ProfileKeyUpdate,
            ]
            .into_iter()
            .filter(|f| body.flags.unwrap_or_default() & (*f as u32) != 0)
            .collect(),
            expires_in: body.expire_timer,
            // TODO.
            expiry_started: None,
            schedule_send_time: None,
            is_bookmarked: false,
            // TODO.
            use_unidentified: false,
            is_deleted: false,
            is_view_once: false,
            sending_has_failed: false,
            quote_id: body
                .quote
                .and_then(|q| q.id)
                .map(|id| (id, conversation_id)),
            contacts: body.contact,
            previews: body.preview,
            sticker: body.sticker,
            attachments: body.attachments,
            receipts: vec![],
            reactions: vec![],
        })
    }
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub message_id: MessageId,
    pub sender_uuid: Uuid,
    pub timestamp: Timestamp,
    pub r#type: Type,
}

#[derive(Debug, Clone)]
pub struct Reaction {
    pub message_id: MessageId,
    pub author: Uuid,
    pub emoji: String,
    pub sent_time: Timestamp,
    pub received_time: Timestamp,
}

pub fn generate_deleted_message_for_id(id: MessageId) -> Message {
    Message {
        is_deleted: true,
        timestamp: id.0,
        conversation_id: id.1,
        sender_uuid: Uuid::nil(),
        text: None,
        server_timestamp: 0,
        is_read: true,
        is_outbound: false,
        flags: HashSet::new(),
        expires_in: None,
        expiry_started: None,
        schedule_send_time: None,
        is_bookmarked: false,
        use_unidentified: false,
        is_view_once: false,
        sending_has_failed: false,
        quote_id: None,
        contacts: vec![],
        previews: vec![],
        sticker: None,
        attachments: vec![],
        receipts: vec![],
        reactions: vec![],
    }
}
