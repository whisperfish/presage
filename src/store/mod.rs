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
        Content, Uuid,
    },
    proto::{sync_message::Sent, DataMessage, GroupContextV2, SyncMessage},
};
use serde::{Deserialize, Serialize};

#[cfg(feature = "sled-store")]
pub mod sled;

#[cfg(feature = "volatile-store")]
pub mod volatile;

#[cfg(feature = "secret-volatile-store")]
pub mod secret_volatile;

pub trait Store:
    PreKeyStore
    + SignedPreKeyStore
    + SessionStoreExt
    + IdentityKeyStore
    + StateStore<Registered>
    + ContactsStore
    + MessageStore
    + GroupsStore
    + SenderKeyStore
    + Sync
    + Clone
{
    /// Clear the entire store, this can be useful when re-initializing an existing client
    /// Note: you can implement this the way you want and only clear the database partially
    /// but should always make sure the state and all keys are gone.
    fn clear(&mut self) -> Result<(), Error>;

    fn pre_keys_offset_id(&self) -> Result<u32, Error>;
    fn set_pre_keys_offset_id(&mut self, id: u32) -> Result<(), Error>;

    fn next_signed_pre_key_id(&self) -> Result<u32, Error>;
    fn set_next_signed_pre_key_id(&mut self, id: u32) -> Result<(), Error>;
}

pub trait StateStore<S> {
    fn load_state(&self) -> Result<Registered, Error>;
    fn save_state(&mut self, state: &S) -> Result<(), Error>;
}

pub trait ContactsStore {
    type ContactsIter: Iterator<Item = Result<Contact, Error>>;

    fn clear_contacts(&mut self) -> Result<(), Error>;
    fn save_contacts(&mut self, contacts: impl Iterator<Item = Contact>) -> Result<(), Error>;
    fn contacts(&self) -> Result<Self::ContactsIter, Error>;
    fn contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Error>;
}

pub trait GroupsStore {
    type GroupsIter: Iterator<Item = Result<(GroupMasterKeyBytes, Group), Error>>;

    fn clear_groups(&mut self) -> Result<(), Error>;
    fn save_group(
        &self,
        master_key: &[u8],
        group: crate::prelude::proto::Group,
    ) -> Result<(), Error>;
    fn groups(&self) -> Result<Self::GroupsIter, Error>;
    fn group(&self, master_key: &[u8]) -> Result<Option<Group>, Error>;
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

/// A [MessageStore] can store messages in the form [Content] and retrieve messages either by
/// [MessageIdentity], by [Thread] or completely.
pub trait MessageStore {
    type MessagesIter: Iterator<Item = Result<Content, Error>>;

    // Clear all stored messages.
    fn clear_messages(&mut self) -> Result<(), Error>;

    /// Save a message in a [Thread] identified by a timestamp.
    /// TODO: deriving the thread happens from the content, so we can also ditch the first parameter
    fn save_message(&mut self, thread: &Thread, message: Content) -> Result<(), Error>;

    /// Delete a single message, identified by its received timestamp from a thread.
    fn delete_message(&mut self, thread: &Thread, timestamp: u64) -> Result<bool, Error>;

    /// Retrieve a message from a [Thread] by its timestamp.
    fn message(&self, thread: &Thread, timestamp: u64) -> Result<Option<Content>, Error>;

    /// Retrieve all messages from a [Thread] within a range in time
    fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Error>;
}
