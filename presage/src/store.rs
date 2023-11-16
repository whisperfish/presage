//! Traits that are used by the manager for storing the data.

use std::{fmt, ops::RangeBounds};

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
    zkgroup::GroupMasterKeyBytes,
    Profile,
};
use serde::{Deserialize, Serialize};

use crate::manager::Registered;

/// An error trait implemented by store error types
pub trait StoreError: std::error::Error + Sync + Send + 'static {}

/// Stores the registered state of the manager
pub trait StateStore {
    type StateStoreError: StoreError;

    /// Load registered (or linked) state
    fn load_state(&self) -> Result<Option<Registered>, Self::StateStoreError>;

    /// Save registered (or linked) state
    fn save_state(&mut self, state: &Registered) -> Result<(), Self::StateStoreError>;

    /// Returns whether this store contains registration data or not
    fn is_registered(&self) -> bool;

    /// Clear registration data (including keys), but keep received messages, groups and contacts.
    fn clear_registration(&mut self) -> Result<(), Self::StateStoreError>;
}

/// Stores the keys published ahead of time, pre-keys
///
/// <https://signal.org/docs/specifications/x3dh/>
pub trait PreKeyStoreExt {
    type PreKeyStoreExtError: StoreError;

    fn pre_keys_offset_id(&self) -> Result<u32, Self::PreKeyStoreExtError>;

    fn set_pre_keys_offset_id(&mut self, id: u32) -> Result<(), Self::PreKeyStoreExtError>;

    fn next_signed_pre_key_id(&self) -> Result<u32, Self::PreKeyStoreExtError>;

    fn next_pq_pre_key_id(&self) -> Result<u32, Self::PreKeyStoreExtError>;

    fn set_next_signed_pre_key_id(&mut self, id: u32) -> Result<(), Self::PreKeyStoreExtError>;

    fn set_next_pq_pre_key_id(&mut self, id: u32) -> Result<(), Self::PreKeyStoreExtError>;
}

/// Stores messages, contacts, groups and profiles
pub trait ContentsStore {
    type ContentsStoreError: StoreError;

    /// Iterator over the contacts
    type ContactsIter: Iterator<Item = Result<Contact, Self::ContentsStoreError>>;

    /// Iterator over all stored groups
    ///
    /// Each items is a tuple consisting of the group master key and its corresponding data.
    type GroupsIter: Iterator<Item = Result<(GroupMasterKeyBytes, Group), Self::ContentsStoreError>>;

    /// Iterator over all stored messages
    type MessagesIter: Iterator<Item = Result<Content, Self::ContentsStoreError>>;

    // Messages

    /// Clear all stored messages.
    fn clear_messages(&mut self) -> Result<(), Self::ContentsStoreError>;

    /// Clear the messages in a thread.
    fn clear_thread(&mut self, thread: &Thread) -> Result<(), Self::ContentsStoreError>;

    /// Save a message in a [Thread] identified by a timestamp.
    fn save_message(
        &mut self,
        thread: &Thread,
        message: Content,
    ) -> Result<(), Self::ContentsStoreError>;

    /// Retrieve a message from a [Thread] by its timestamp.
    fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<Content>, Self::ContentsStoreError>;

    /// Retrieve all messages from a [Thread] within a range in time
    fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Self::ContentsStoreError>;

    /// Get the expire timer from a [Thread], which corresponds to either [Contact::expire_timer]
    /// or [Group::disappearing_messages_timer].
    fn expire_timer(&self, thread: &Thread) -> Result<Option<u32>, Self::ContentsStoreError> {
        match thread {
            Thread::Contact(uuid) => Ok(self.contact_by_id(*uuid)?.map(|c| c.expire_timer)),
            Thread::Group(key) => Ok(self
                .group(*key)?
                .and_then(|g| g.disappearing_messages_timer)
                .map(|t| t.duration)),
        }
    }

    // Contacts

    /// Clear all saved synchronized contact data
    fn clear_contacts(&mut self) -> Result<(), Self::ContentsStoreError>;

    /// Replace all contact data
    fn save_contacts(
        &mut self,
        contacts: impl Iterator<Item = Contact>,
    ) -> Result<(), Self::ContentsStoreError>;

    /// Get an iterator on all stored (synchronized) contacts
    fn contacts(&self) -> Result<Self::ContactsIter, Self::ContentsStoreError>;

    /// Get contact data for a single user by its [Uuid].
    fn contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Self::ContentsStoreError>;

    /// Delete all cached group data
    fn clear_groups(&mut self) -> Result<(), Self::ContentsStoreError>;

    /// Save a group in the cache
    fn save_group(
        &self,
        master_key: GroupMasterKeyBytes,
        group: &Group,
    ) -> Result<(), Self::ContentsStoreError>;

    /// Get an iterator on all cached groups
    fn groups(&self) -> Result<Self::GroupsIter, Self::ContentsStoreError>;

    /// Retrieve a single unencrypted group indexed by its `[GroupMasterKeyBytes]`
    fn group(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> Result<Option<Group>, Self::ContentsStoreError>;

    // Profiles

    /// Insert or update the profile key of a contact
    fn upsert_profile_key(
        &mut self,
        uuid: &Uuid,
        key: ProfileKey,
    ) -> Result<bool, Self::ContentsStoreError>;

    /// Get the profile key for a contact
    fn profile_key(&self, uuid: &Uuid) -> Result<Option<ProfileKey>, Self::ContentsStoreError>;

    /// Save a profile by [Uuid] and [ProfileKey].
    fn save_profile(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: Profile,
    ) -> Result<(), Self::ContentsStoreError>;

    /// Retrieve a profile by [Uuid] and [ProfileKey].
    fn profile(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> Result<Option<Profile>, Self::ContentsStoreError>;
}

/// The manager store trait combining all other stores into a single one
pub trait Store:
    StateStore<StateStoreError = Self::Error>
    + PreKeyStoreExt<PreKeyStoreExtError = Self::Error>
    + ContentsStore<ContentsStoreError = Self::Error>
    + ProtocolStore
    + SenderKeyStore
    + SessionStoreExt
    + Sync
    + Clone
{
    type Error: StoreError;

    /// Clear the entire store
    ///
    /// This can be useful when resetting an existing client.
    fn clear(&mut self) -> Result<(), <Self as StateStore>::StateStoreError>;
}

/// A thread specifies where a message was sent, either to or from a contact or in a group.
#[derive(Debug, Hash, Eq, PartialEq, Clone, Deserialize, Serialize)]
pub enum Thread {
    /// The message was sent inside a contact-chat.
    Contact(Uuid),
    // Cannot use GroupMasterKey as unable to extract the bytes.
    /// The message was sent inside a groups-chat with the [`GroupMasterKeyBytes`] (specified as bytes).
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

/// Extension trait of [`Content`]
pub trait ContentExt {
    fn timestamp(&self) -> u64;
}

impl ContentExt for Content {
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
