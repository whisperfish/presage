use chrono::prelude::*;
use libsignal_service::prelude::Uuid;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct GroupV2 {
    pub id: String,
    pub name: String,

    pub master_key: String,
    pub revision: i32,

    pub invite_link_password: Option<Vec<u8>>,

    pub access_required_for_attributes: i32,
    pub access_required_for_members: i32,
    pub access_required_for_add_from_invite_link: i32,

    pub avatar: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone)]
pub struct GroupV2Member {
    pub group_v2_id: String,
    pub recipient_id: i32,
    pub member_since: NaiveDateTime,
    pub joined_at_revision: i32,
    pub role: i32,
}

#[derive(Clone, PartialEq, Eq)]
pub struct Message {
    pub id: i32,
    pub session_id: i32,

    pub text: Option<String>,
    pub sender_recipient_id: Option<i32>,

    pub received_timestamp: Option<NaiveDateTime>,
    pub sent_timestamp: Option<NaiveDateTime>,
    pub server_timestamp: NaiveDateTime,
    pub is_read: bool,
    pub is_outbound: bool,
    pub flags: i32,
    pub expires_in: Option<i32>,
    pub expiry_started: Option<NaiveDateTime>,
    pub schedule_send_time: Option<NaiveDateTime>,
    pub is_bookmarked: bool,
    pub use_unidentified: bool,
    pub is_remote_deleted: bool,

    pub sending_has_failed: bool,

    pub quote_id: Option<i32>,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            id: Default::default(),
            session_id: Default::default(),
            text: Default::default(),
            sender_recipient_id: Default::default(),
            received_timestamp: Default::default(),
            sent_timestamp: Default::default(),
            server_timestamp: NaiveDateTime::from_timestamp_opt(0, 0).unwrap(),
            is_read: Default::default(),
            is_outbound: Default::default(),
            flags: Default::default(),
            expires_in: Default::default(),
            expiry_started: Default::default(),
            schedule_send_time: Default::default(),
            is_bookmarked: Default::default(),
            use_unidentified: Default::default(),
            is_remote_deleted: Default::default(),
            sending_has_failed: Default::default(),
            quote_id: Default::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Recipient {
    pub id: i32,
    pub e164: Option<String>,
    pub uuid: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub blocked: bool,

    pub profile_key: Option<Vec<u8>>,
    pub profile_key_credential: Option<Vec<u8>>,

    pub profile_given_name: Option<String>,
    pub profile_family_name: Option<String>,
    pub profile_joined_name: Option<String>,
    pub signal_profile_avatar: Option<String>,
    pub profile_sharing: bool,

    pub last_profile_fetch: Option<NaiveDateTime>,
    pub unidentified_access_mode: bool,

    pub storage_service_id: Option<Vec<u8>>,
    pub storage_proto: Option<Vec<u8>>,

    pub capabilities: i32,
    pub last_session_reset: Option<NaiveDateTime>,

    pub about: Option<String>,
    pub about_emoji: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SessionRecord {
    pub address: String,
    pub device_id: i32,
    pub record: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct IdentityRecord {
    pub address: String,
    pub record: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SignedPrekey {
    pub id: i32,
    pub record: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct Prekey {
    pub id: i32,
    pub record: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct SenderKeyRecord {
    pub address: String,
    pub device: i32,
    pub distribution_id: String,
    pub record: Vec<u8>,
    pub created_at: NaiveDateTime,
}

impl Recipient {
    pub fn profile_key(&self) -> Option<[u8; 32]> {
        if let Some(pk) = self.profile_key.as_ref() {
            if pk.len() != 32 {
                log::warn!("Profile key is {} bytes", pk.len());
                None
            } else {
                let mut key = [0u8; 32];
                key.copy_from_slice(pk);
                Some(key)
            }
        } else {
            None
        }
    }

    pub fn to_service_address(&self) -> Option<libsignal_service::ServiceAddress> {
        self.uuid
            .as_ref()
            .map(|uuid| libsignal_service::ServiceAddress {
                uuid: Uuid::parse_str(uuid).expect("only valid UUIDs in db"),
            })
    }

    pub fn uuid(&self) -> &str {
        self.uuid.as_deref().or(Some("")).expect("uuid")
    }

    pub fn e164_or_uuid(&self) -> &str {
        self.e164
            .as_deref()
            .or(self.uuid.as_deref())
            .expect("either uuid or e164")
    }

    pub fn name(&self) -> &str {
        self.profile_joined_name
            .as_deref()
            .or_else(|| Some(self.e164_or_uuid()))
            .expect("either joined name, uuid or e164")
    }
}

#[derive(Debug, Clone)]
pub struct DbConversation {
    pub id: i32,

    pub direct_message_recipient_id: Option<i32>,
    pub group_v2_id: Option<String>,

    pub is_archived: bool,
    pub is_pinned: bool,

    pub is_silent: bool,
    pub is_muted: bool,

    pub draft: Option<String>,

    pub expiring_message_timeout: Option<i32>,
}

#[derive(Debug, Clone)]
pub struct Attachment {
    pub id: i32,
    pub json: Option<String>,
    pub message_id: i32,
    pub content_type: String,
    pub name: Option<String>,
    pub content_disposition: Option<String>,
    pub content_location: Option<String>,
    pub attachment_path: Option<String>,
    pub is_pending_upload: bool,
    pub transfer_file_path: Option<String>,
    pub size: Option<i32>,
    pub file_name: Option<String>,
    pub unique_id: Option<String>,
    pub digest: Option<String>,
    pub is_voice_note: bool,
    pub is_borderless: bool,
    pub is_quote: bool,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub sticker_pack_id: Option<String>,
    pub sticker_pack_key: Option<Vec<u8>>,
    pub sticker_id: Option<i32>,
    pub sticker_emoji: Option<String>,
    pub data_hash: Option<Vec<u8>>,
    pub visual_hash: Option<String>,
    pub transform_properties: Option<String>,
    pub transfer_file: Option<String>,
    pub display_order: i32,
    pub upload_timestamp: NaiveDateTime,
    pub cdn_number: Option<i32>,
    pub caption: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Conversation {
    pub id: i32,

    pub is_archived: bool,
    pub is_pinned: bool,

    pub is_silent: bool,
    pub is_muted: bool,

    pub expiring_message_timeout: Option<Duration>,

    pub draft: Option<String>,
    pub r#type: ConversationType,
}

#[derive(Debug, Clone)]
pub struct Reaction {
    pub reaction_id: i32,
    pub message_id: i32,
    pub author: i32,
    pub emoji: String,
    pub sent_time: NaiveDateTime,
    pub received_time: NaiveDateTime,
}

#[derive(Debug, Clone)]
pub struct Receipt {
    pub message_id: i32,
    pub recipient_id: i32,
    pub delivered: Option<NaiveDateTime>,
    pub read: Option<NaiveDateTime>,
    pub viewed: Option<NaiveDateTime>,
}

impl Conversation {
    pub fn is_dm(&self) -> bool {
        self.r#type.is_dm()
    }

    pub fn is_group(&self) -> bool {
        self.r#type.is_group_v2()
    }

    pub fn is_group_v2(&self) -> bool {
        self.r#type.is_group_v2()
    }

    pub fn unwrap_dm(&self) -> &Recipient {
        self.r#type.unwrap_dm()
    }

    pub fn unwrap_group_v2(&self) -> &GroupV2 {
        self.r#type.unwrap_group_v2()
    }
}

impl From<(DbConversation, Option<Recipient>, Option<GroupV2>)> for Conversation {
    fn from(
        (conversation, recipient, groupv2): (DbConversation, Option<Recipient>, Option<GroupV2>),
    ) -> Conversation {
        assert_eq!(
            conversation.direct_message_recipient_id.is_some(),
            recipient.is_some(),
            "direct session requires recipient"
        );
        assert_eq!(
            conversation.group_v2_id.is_some(),
            groupv2.is_some(),
            "groupv2 session requires groupv2"
        );

        let t = match (recipient, groupv2) {
            (Some(recipient), None) => ConversationType::DirectMessage(recipient),
            (None, Some(gv2)) => ConversationType::GroupV2(gv2),
            _ => unreachable!("case handled above"),
        };

        let DbConversation {
            id,

            direct_message_recipient_id: _,
            group_v2_id: _,

            is_archived,
            is_pinned,

            is_silent,
            is_muted,

            draft,

            expiring_message_timeout,
        } = conversation;
        Conversation {
            id,

            is_archived,
            is_pinned,

            is_silent,
            is_muted,

            draft,

            expiring_message_timeout: expiring_message_timeout
                .map(|i| i as u64)
                .map(Duration::from_secs),

            r#type: t,
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum ConversationType {
    // XXX clippy suggests to put Recipient, 322 bytes, on the heap.
    DirectMessage(Recipient),
    GroupV2(GroupV2),
}

impl ConversationType {
    pub fn is_dm(&self) -> bool {
        matches!(self, Self::DirectMessage(_))
    }

    pub fn is_group_v2(&self) -> bool {
        matches!(self, Self::GroupV2(_))
    }

    pub fn unwrap_dm(&self) -> &Recipient {
        assert!(self.is_dm(), "unwrap panicked at unwrap_dm()");
        match self {
            Self::DirectMessage(r) => r,
            _ => unreachable!(),
        }
    }

    pub fn unwrap_group_v2(&self) -> &GroupV2 {
        assert!(self.is_group_v2(), "unwrap panicked at unwrap_group_v2()");
        match self {
            Self::GroupV2(g) => g,
            _ => unreachable!(),
        }
    }
}

// Some extras

/// [`Message`] augmented with its sender, attachment count and receipts.
#[derive(Clone, Default)]
pub struct AugmentedMessage {
    pub inner: Message,
    pub attachments: usize,
    pub receipts: Vec<(Receipt, Recipient)>,
}

impl std::ops::Deref for AugmentedMessage {
    type Target = Message;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl AugmentedMessage {
    pub fn sent(&self) -> bool {
        self.inner.sent_timestamp.is_some()
    }

    pub fn delivered(&self) -> u32 {
        self.receipts
            .iter()
            .filter(|(r, _)| r.delivered.is_some())
            .count() as _
    }

    pub fn read(&self) -> u32 {
        self.receipts
            .iter()
            .filter(|(r, _)| r.read.is_some())
            .count() as _
    }

    pub fn viewed(&self) -> u32 {
        self.receipts
            .iter()
            .filter(|(r, _)| r.viewed.is_some())
            .count() as _
    }

    pub fn queued(&self) -> bool {
        self.is_outbound && self.sent_timestamp.is_none() && !self.sending_has_failed
    }

    pub fn attachments(&self) -> u32 {
        self.attachments as _
    }
}

pub struct AugmentedConversation {
    pub inner: Conversation,
    pub last_message: Option<AugmentedMessage>,
}

impl std::ops::Deref for AugmentedConversation {
    type Target = Conversation;

    fn deref(&self) -> &Conversation {
        &self.inner
    }
}

impl AugmentedConversation {
    pub fn timestamp(&self) -> Option<NaiveDateTime> {
        self.last_message.as_ref().map(|m| m.inner.server_timestamp)
    }

    pub fn group_name(&self) -> Option<&str> {
        match &self.inner.r#type {
            ConversationType::GroupV2(group) => Some(&group.name),
            ConversationType::DirectMessage(_) => None,
        }
    }

    pub fn group_description(&self) -> Option<String> {
        match &self.inner.r#type {
            ConversationType::GroupV2(group) => group.description.to_owned(),
            ConversationType::DirectMessage(_) => None,
        }
    }

    pub fn group_id(&self) -> Option<&str> {
        match &self.inner.r#type {
            ConversationType::GroupV2(group) => Some(&group.id),
            ConversationType::DirectMessage(_) => None,
        }
    }

    pub fn sent(&self) -> bool {
        if let Some(m) = &self.last_message {
            m.sent_timestamp.is_some()
        } else {
            false
        }
    }

    pub fn recipient_id(&self) -> i32 {
        match &self.inner.r#type {
            ConversationType::GroupV2(_group) => -1,
            ConversationType::DirectMessage(recipient) => recipient.id,
        }
    }

    pub fn recipient_name(&self) -> &str {
        match &self.inner.r#type {
            ConversationType::GroupV2(_group) => "",
            ConversationType::DirectMessage(recipient) => {
                recipient.profile_joined_name.as_deref().unwrap_or_default()
            }
        }
    }

    pub fn recipient_uuid(&self) -> &str {
        match &self.inner.r#type {
            ConversationType::GroupV2(_group) => "",
            ConversationType::DirectMessage(recipient) => recipient.uuid(),
        }
    }

    pub fn recipient_e164(&self) -> &str {
        match &self.inner.r#type {
            ConversationType::GroupV2(_group) => "",
            ConversationType::DirectMessage(recipient) => {
                recipient.e164.as_deref().unwrap_or_default()
            }
        }
    }

    pub fn recipient_emoji(&self) -> &str {
        match &self.inner.r#type {
            ConversationType::GroupV2(_group) => "",
            ConversationType::DirectMessage(recipient) => {
                recipient.about_emoji.as_deref().unwrap_or_default()
            }
        }
    }

    pub fn recipient_about(&self) -> &str {
        match &self.inner.r#type {
            ConversationType::GroupV2(_group) => "",
            ConversationType::DirectMessage(recipient) => {
                recipient.about.as_deref().unwrap_or_default()
            }
        }
    }

    pub fn has_avatar(&self) -> bool {
        match &self.r#type {
            ConversationType::GroupV2(group) => group.avatar.is_some(),
            ConversationType::DirectMessage(recipient) => recipient.signal_profile_avatar.is_some(),
        }
    }

    pub fn has_attachment(&self) -> bool {
        if let Some(m) = &self.last_message {
            m.attachments > 0
        } else {
            false
        }
    }

    pub fn draft(&self) -> String {
        self.draft.clone().unwrap_or_default()
    }

    pub fn last_message_text(&self) -> Option<&str> {
        self.last_message.as_ref().and_then(|m| m.text.as_deref())
    }

    // TODO: Keep or make it GUI-specific?
    // TODO: If keep, this should probably return an enum.
    pub fn section(&self) -> String {
        if self.is_pinned {
            return String::from("pinned");
        }

        // XXX: stub
        let now = chrono::Utc::now();
        let today = Utc
            .with_ymd_and_hms(now.year(), now.month(), now.day(), 0, 0, 0)
            .unwrap()
            .naive_utc();

        let last_message = if let Some(m) = &self.last_message {
            &m.inner
        } else {
            return String::from("today");
        };
        let diff = today.signed_duration_since(last_message.server_timestamp);

        if diff.num_seconds() <= 0 {
            String::from("today")
        } else if diff.num_hours() <= 24 {
            String::from("yesterday")
        } else if diff.num_hours() <= (7 * 24) {
            let wd = last_message.server_timestamp.weekday().number_from_monday() % 7;
            wd.to_string()
        } else {
            String::from("older")
        }
    }

    pub fn is_read(&self) -> bool {
        self.last_message
            .as_ref()
            .map(|m| m.is_read)
            .unwrap_or(false)
    }

    pub fn delivered(&self) -> u32 {
        if let Some(m) = &self.last_message {
            m.receipts
                .iter()
                .filter(|(r, _)| r.delivered.is_some())
                .count() as _
        } else {
            0
        }
    }

    pub fn read(&self) -> u32 {
        if let Some(m) = &self.last_message {
            m.receipts.iter().filter(|(r, _)| r.read.is_some()).count() as _
        } else {
            0
        }
    }

    pub fn is_muted(&self) -> bool {
        self.is_muted
    }

    pub fn is_archived(&self) -> bool {
        self.is_archived
    }

    pub fn is_pinned(&self) -> bool {
        self.is_pinned
    }

    pub fn viewed(&self) -> u32 {
        if let Some(m) = &self.last_message {
            m.receipts
                .iter()
                .filter(|(r, _)| r.viewed.is_some())
                .count() as _
        } else {
            0
        }
    }
}
