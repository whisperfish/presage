use std::{fmt, ops::RangeBounds};

use crate::{manager::Registered, GroupMasterKeyBytes};
use libsignal_service::{
    content::ContentBody,
    groups_v2::Group,
    models::Contact,
    prelude::{Content, ProfileKey, Uuid, UuidError},
    proto::{
        sync_message::{self, Sent},
        DataMessage, EditMessage, GroupContextV2, SyncMessage,
    },
    protocol::{ProtocolStore, SenderKeyStore},
    session_store::SessionStoreExt,
    Profile,
};
use serde::{Deserialize, Serialize};

pub trait StoreError: std::error::Error + Sync + Send + 'static {}

pub trait Store: ProtocolStore + SenderKeyStore + SessionStoreExt + Sync + Clone {
    type Error: StoreError;

    type ContactsIter: Iterator<Item = Result<Contact, Self::Error>>;
    type GroupsIter: Iterator<Item = Result<(GroupMasterKeyBytes, Group), Self::Error>>;
    type MessagesIter: Iterator<Item = Result<Content, Self::Error>>;
    type StickerPacksIter: Iterator<Item = Result<StickerPack, Self::Error>>;

    /// State

    /// Load registered (or linked) state
    fn load_state(&self) -> Result<Option<Registered>, Self::Error>;

    /// Save registered (or linked) state
    fn save_state(&mut self, state: &Registered) -> Result<(), Self::Error>;

    /// Returns whether this store contains registration data or not
    fn is_registered(&self) -> bool;

    /// Clear registration data (including keys), but keep received messages, groups and contacts.
    fn clear_registration(&mut self) -> Result<(), Self::Error>;

    /// Clear the entire store: this can be useful when resetting an existing client.
    fn clear(&mut self) -> Result<(), Self::Error>;

    /// Pre-keys

    fn pre_keys_offset_id(&self) -> Result<u32, Self::Error>;

    fn set_pre_keys_offset_id(&mut self, id: u32) -> Result<(), Self::Error>;

    fn next_signed_pre_key_id(&self) -> Result<u32, Self::Error>;

    fn next_pq_pre_key_id(&self) -> Result<u32, Self::Error>;

    fn set_next_signed_pre_key_id(&mut self, id: u32) -> Result<(), Self::Error>;

    fn set_next_pq_pre_key_id(&mut self, id: u32) -> Result<(), Self::Error>;

    /// Messages

    // Clear all stored messages.
    fn clear_messages(&mut self) -> Result<(), Self::Error>;

    // Clear the messages in a thread.
    fn clear_thread(&mut self, thread: &Thread) -> Result<(), Self::Error>;

    /// Save a message in a [Thread] identified by a timestamp.
    fn save_message(&mut self, thread: &Thread, message: Content) -> Result<(), Self::Error>;

    /// Delete a single message, identified by its received timestamp from a thread.
    #[deprecated = "message deletion is now handled internally"]
    fn delete_message(&mut self, thread: &Thread, timestamp: u64) -> Result<bool, Self::Error>;

    /// Retrieve a message from a [Thread] by its timestamp.
    fn message(&self, thread: &Thread, timestamp: u64) -> Result<Option<Content>, Self::Error>;

    /// Retrieve all messages from a [Thread] within a range in time
    fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Self::Error>;

    /// Get the expire timer from a [Thread], which corresponds to either [Contact::expire_timer]
    /// or [Group::disappearing_messages_timer].
    fn expire_timer(&self, thread: &Thread) -> Result<Option<u32>, Self::Error> {
        match thread {
            Thread::Contact(uuid) => Ok(self.contact_by_id(*uuid)?.map(|c| c.expire_timer)),
            Thread::Group(key) => Ok(self
                .group(*key)?
                .and_then(|g| g.disappearing_messages_timer)
                .map(|t| t.duration)),
        }
    }

    /// Contacts

    /// Clear all saved synchronized contact data
    fn clear_contacts(&mut self) -> Result<(), Self::Error>;

    /// Replace all contact data
    fn save_contacts(&mut self, contacts: impl Iterator<Item = Contact>)
        -> Result<(), Self::Error>;

    /// Get an iterator on all stored (synchronized) contacts
    fn contacts(&self) -> Result<Self::ContactsIter, Self::Error>;

    /// Get contact data for a single user by its [Uuid].
    fn contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Self::Error>;

    /// Delete all cached group data
    fn clear_groups(&mut self) -> Result<(), Self::Error>;

    /// Save a group in the cache
    fn save_group(&self, master_key: GroupMasterKeyBytes, group: &Group)
        -> Result<(), Self::Error>;

    /// Get an iterator on all cached groups
    fn groups(&self) -> Result<Self::GroupsIter, Self::Error>;

    /// Retrieve a single unencrypted group indexed by its `[GroupMasterKeyBytes]`
    fn group(&self, master_key: GroupMasterKeyBytes) -> Result<Option<Group>, Self::Error>;

    /// Profiles

    /// Insert or update the profile key of a contact
    fn upsert_profile_key(&mut self, uuid: &Uuid, key: ProfileKey) -> Result<bool, Self::Error>;

    /// Get the profile key for a contact
    fn profile_key(&self, uuid: &Uuid) -> Result<Option<ProfileKey>, Self::Error>;

    /// Save a profile by [Uuid] and [ProfileKey].
    fn save_profile(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: Profile,
    ) -> Result<(), Self::Error>;

    /// Retrieve a profile by [Uuid] and [ProfileKey].
    fn profile(&self, uuid: Uuid, key: ProfileKey) -> Result<Option<Profile>, Self::Error>;

    /// Stickers

    /// Add a sticker pack
    fn add_sticker_pack(&mut self, pack: StickerPack) -> Result<(), Self::Error>;

    /// Gets a cached sticker pack
    fn sticker_pack(&self, id: &[u8]) -> Result<Option<StickerPack>, Self::Error>;

    /// Removes a sticker pack
    fn remove_sticker_pack(&mut self, id: &[u8]) -> Result<bool, Self::Error>;

    /// Get an iterator on all installed stickerpacks
    fn sticker_packs(&self) -> Result<Self::StickerPacksIter, Self::Error>;

    /// Get the manifest-less sticker pack queue
    fn sticker_pack_queue(&self) -> Result<Vec<StickerPack>, Self::Error>;

    /// Set the manifest-less sticker pack queue
    fn set_sticker_pack_queue(&mut self, queue: Vec<StickerPack>) -> Result<(), Self::Error>;
}

/// A thread specifies where a message was sent, either to or from a contact or in a group.
#[derive(Debug, Hash, Eq, PartialEq, Clone, Deserialize, Serialize)]
pub enum Thread {
    /// The message was sent inside a contact-chat.
    Contact(Uuid),
    // Cannot use GroupMasterKey as unable to extract the bytes.
    /// The message was sent inside a groups-chat with the [GroupMasterKey](crate::prelude::GroupMasterKey) (specified as bytes).
    Group(GroupMasterKeyBytes),
}

impl fmt::Display for Thread {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Thread::Contact(uuid) => write!(f, "Thread(contact={uuid})"),
            Thread::Group(master_key_bytes) => {
                write!(f, "Thread(group={:x?})", &master_key_bytes[..4])
            }
        }
    }
}

impl TryFrom<&Content> for Thread {
    type Error = UuidError;

    fn try_from(content: &Content) -> Result<Self, Self::Error> {
        match &content.body {
            // [1-1] Message sent by us with another device
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        destination_service_id: Some(uuid),
                        ..
                    }),
                ..
            }) => Ok(Self::Contact(Uuid::parse_str(uuid)?)),
            // [Group] message from somebody else
            ContentBody::DataMessage(DataMessage {
                group_v2:
                    Some(GroupContextV2 {
                        master_key: Some(key),
                        ..
                    }),
                ..
            })
            // [Group] message sent by us with another device
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
            })
            // [Group] message edit sent by us with another device
            | ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        edit_message:
                            Some(EditMessage {
                                data_message:
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
                    }),
                ..
            })
            // [Group] Message edit sent by somebody else
            | ContentBody::EditMessage(EditMessage {
                data_message:
                    Some(DataMessage {
                        group_v2:
                            Some(GroupContextV2 {
                                master_key: Some(key),
                                ..
                            }),
                        ..
                    }),
                ..
            }) => Ok(Self::Group(
                key.clone()
                    .try_into()
                    .expect("Group master key to have 32 bytes"),
            )),
            // [1-1] Any other message directly to us
            _ => Ok(Thread::Contact(content.metadata.sender.uuid)),
        }
    }
}

pub trait ContentTimestamp {
    fn timestamp(&self) -> u64;
}

impl ContentTimestamp for Content {
    /// The original timestamp of the message.
    fn timestamp(&self) -> u64 {
        match self.body {
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(sync_message::Sent {
                        timestamp: Some(ts),
                        ..
                    }),
                ..
            }) => ts,
            ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(sync_message::Sent {
                        edit_message:
                            Some(EditMessage {
                                target_sent_timestamp: Some(ts),
                                ..
                            }),
                        ..
                    }),
                ..
            }) => ts,
            ContentBody::EditMessage(EditMessage {
                target_sent_timestamp: Some(ts),
                ..
            }) => ts,
            _ => self.metadata.timestamp,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StickerPack {
    pub id: Vec<u8>,
    pub key: Vec<u8>,
    pub manifest: Option<Pack>,
}

/// equivalent to [Pack](crate::prelude::proto::Pack)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pack {
    pub title: String,
    pub author: String,
    pub cover: Option<Sticker>,
    pub stickers: Vec<Sticker>,
}
impl From<libsignal_service::proto::Pack> for Pack {
    fn from(value: libsignal_service::proto::Pack) -> Self {
        Self {
            title: value.title().to_owned(),
            author: value.author().to_owned(),
            cover: value.cover.map(|s| s.into()),
            stickers: value.stickers.into_iter().map(|s| s.into()).collect(),
        }
    }
}

/// equivalent to [Sticker](crate::prelude::proto::pack::Sticker)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sticker {
    pub id: u32,
    pub emoji: Option<String>,
    pub content_type: Option<String>,
}
impl From<libsignal_service::proto::pack::Sticker> for Sticker {
    fn from(value: libsignal_service::proto::pack::Sticker) -> Self {
        Self {
            id: value.id(),
            emoji: value.emoji,
            content_type: value.content_type,
        }
    }
}
