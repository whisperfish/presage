use std::{fmt, ops::RangeBounds};

use crate::{manager::Registered, Error, GroupMasterKeyBytes};
use libsignal_service::{
    content::ContentBody,
    groups_v2::Group,
    models::Contact,
    prelude::{
        protocol::{
            IdentityKeyStore, PreKeyStore, SenderKeyStore, SessionStoreExt, SignedPreKeyStore,
        },
        Content, ProfileKey, Uuid,
    },
    proto::{sync_message::Sent, DataMessage, GroupContextV2, SyncMessage},
    Profile,
};
use serde::{Deserialize, Serialize};

pub trait Store:
    PreKeyStore
    + SignedPreKeyStore
    + SessionStoreExt
    + IdentityKeyStore
    + StateStore<Registered>
    + ContactsStore
    + MessageStore
    + GroupsStore
    + ProfilesStore
    + SenderKeyStore
    + Sync
    + Clone
{
    type StoreError: std::error::Error + Into<Error>;

    /// Clear registration data (including keys), but keep received messages, groups and contacts.
    fn clear_registration(&mut self) -> Result<(), Self::StoreError>;

    /// Clear the entire store: this can be useful when resetting an existing client.
    fn clear(&mut self) -> Result<(), Self::StoreError>;

    fn pre_keys_offset_id(&self) -> Result<u32, Self::StoreError>;
    fn set_pre_keys_offset_id(&mut self, id: u32) -> Result<(), Self::StoreError>;

    fn next_signed_pre_key_id(&self) -> Result<u32, Self::StoreError>;
    fn set_next_signed_pre_key_id(&mut self, id: u32) -> Result<(), Self::StoreError>;
}

pub trait StateStore<S> {
    type StateStoreError: std::error::Error + Into<Error>;

    fn load_state(&self) -> Result<Option<S>, Self::StateStoreError>;
    fn save_state(&mut self, state: &S) -> Result<(), Self::StateStoreError>;
}

pub trait ContactsStore {
    type ContactsStoreError: std::error::Error + Into<Error>;
    type ContactsIter: Iterator<Item = Result<Contact, Self::ContactsStoreError>>;

    fn clear_contacts(&mut self) -> Result<(), Self::ContactsStoreError>;
    fn save_contacts(
        &mut self,
        contacts: impl Iterator<Item = Contact>,
    ) -> Result<(), Self::ContactsStoreError>;
    fn contacts(&self) -> Result<Self::ContactsIter, Self::ContactsStoreError>;
    fn contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Self::ContactsStoreError>;
}

pub trait GroupsStore {
    type GroupsStoreError: std::error::Error + Into<Error>;
    type GroupsIter: Iterator<Item = Result<(GroupMasterKeyBytes, Group), Self::GroupsStoreError>>;

    fn clear_groups(&mut self) -> Result<(), Self::GroupsStoreError>;
    fn save_group(
        &self,
        master_key: GroupMasterKeyBytes,
        group: crate::prelude::proto::Group,
    ) -> Result<(), Self::GroupsStoreError>;
    fn groups(&self) -> Result<Self::GroupsIter, Self::GroupsStoreError>;
    fn group(
        &self,
        master_key: GroupMasterKeyBytes,
    ) -> Result<Option<Group>, Self::GroupsStoreError>;
}

/// A [MessageStore] can store messages in the form [Content] and retrieve messages either by
/// [MessageIdentity], by [Thread] or completely.
pub trait MessageStore {
    type MessageStoreError: std::error::Error + Into<Error>;
    type MessagesIter: Iterator<Item = Result<Content, Self::MessageStoreError>>;

    // Clear all stored messages.
    fn clear_messages(&mut self) -> Result<(), Self::MessageStoreError>;

    /// Save a message in a [Thread] identified by a timestamp.
    fn save_message(
        &mut self,
        thread: &Thread,
        message: Content,
    ) -> Result<(), Self::MessageStoreError>;

    /// Delete a single message, identified by its received timestamp from a thread.
    #[deprecated = "message deletion is now handled internally"]
    fn delete_message(
        &mut self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<bool, Self::MessageStoreError>;

    /// Retrieve a message from a [Thread] by its timestamp.
    fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<Content>, Self::MessageStoreError>;

    /// Retrieve all messages from a [Thread] within a range in time
    fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Self::MessageStoreError>;
}

/// Cache profiles locally.
pub trait ProfilesStore {
    type ProfilesStoreError: std::error::Error + Into<Error>;

    /// Save a profile by [Uuid] and [ProfileKey].
    fn save_profile(
        &mut self,
        uuid: Uuid,
        key: ProfileKey,
        profile: Profile,
    ) -> Result<(), Self::ProfilesStoreError>;

    /// Retrieve a profile by [Uuid] and [ProfileKey].
    fn profile(
        &self,
        uuid: Uuid,
        key: ProfileKey,
    ) -> Result<Option<Profile>, Self::ProfilesStoreError>;
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
            }) => Ok(Self::Contact(Uuid::parse_str(uuid)?)),
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
                key.clone()
                    .try_into()
                    .expect("Group master key to have 32 bytes"),
            )),
            // Case 3: Received a 1-1 message
            // => The message sender is the thread.
            _ => Ok(Thread::Contact(content.metadata.sender.uuid)),
        }
    }
}
