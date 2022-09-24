use libsignal_service::{
    content::ContentBody,
    models::Contact,
    prelude::{
        protocol::{IdentityKeyStore, PreKeyStore, SessionStoreExt, SignedPreKeyStore},
        Content, Uuid,
    },
    proto::{sync_message::Sent, DataMessage, GroupContextV2, SyncMessage},
    ServiceAddress,
};

use crate::{manager::Registered, Error};

#[cfg(feature = "sled-config-store")]
pub mod sled;

#[cfg(feature = "volatile-config-store")]
pub mod volatile;

#[cfg(feature = "secret-volatile-config-store")]
pub mod secret_volatile;

pub trait ConfigStore:
    PreKeyStore
    + SignedPreKeyStore
    + SessionStoreExt
    + IdentityKeyStore
    + StateStore<Registered>
    + ContactsStore
    + Sync
    + Clone
{
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
    fn save_contacts(&mut self, contacts: impl Iterator<Item = Contact>) -> Result<(), Error>;
    fn contacts(&self) -> Result<Vec<Contact>, Error>;
    fn contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Error>;
}

/// A thread specifies where a message was sent, either to or from a contact or in a group.
#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum Thread {
    /// The message was sent inside a contact-chat.
    Contact(Uuid),
    // Cannot use GroupMasterKey as unable to extract the bytes.
    /// The message was sent inside a groups-chat with the [GroupMasterKey](crate::prelude::GroupMasterKey) (specified as bytes).
    Group([u8; 32]),
}

impl From<&Thread> for Vec<u8> {
    fn from(val: &Thread) -> Self {
        match val {
            Thread::Contact(u) => u.as_bytes().to_vec(),
            Thread::Group(g) => g.to_vec(),
        }
    }
}

impl Thread {
    pub fn from_content_receiver(
        content: &Content,
        receiver: Option<&ServiceAddress>,
    ) -> Result<Self, Error> {
        if let Some(receiver_uuid) = receiver.and_then(|s| s.uuid) {
            // Case 1: Message is beeing sent to someone
            // => The receiver is the thread.
            Ok(Self::Contact(receiver_uuid))
        } else {
            match &content.body {
                // Case 2: SyncMessage sent from other device notifying about a message sent to
                // someone else.
                // => The receiver of the message mentioned in the SyncMessage is the thread.
                ContentBody::SynchronizeMessage(SyncMessage {
                    sent:
                        Some(Sent {
                            destination_uuid: Some(uuid),
                            ..
                        }),
                    ..
                }) => Ok(Self::Contact(Uuid::parse_str(uuid)?)),
                // Case 3: The message is sent in a group.
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
                // Case 4: The message was neither sent to someone, nor happened in a group.
                // => The message sender is the thread.
                _ => Ok(Thread::Contact(
                    content
                        .metadata
                        .sender
                        .uuid
                        .ok_or(Error::ContentMissingUuid)?,
                )),
            }
        }
    }
}

/// A [MessageStore] can store messages in the form [Content] and retrieve messages either by
/// [MessageIdentity], by [Thread] or completly.
pub trait MessageStore {
    type MessagesIter: Iterator<Item = Content>;

    /// Save a message. The receiver-argument specifies the [ServiceAddress] of the receiver of
    /// that message and is needed for correct association of the message to a [Thread]. If that message was received, it should be `None`.
    fn save_message(
        &mut self,
        message: Content,
        receiver: Option<impl Into<ServiceAddress>>,
    ) -> Result<(), Error>;
    /// Retrieve a message by its a [Thread] and its timestamp.
    fn message(&self, thread: &Thread, timestamp: u64) -> Result<Option<Content>, Error>;
    /// Retrieve a message by a [Thread].
    fn messages(&self, thread: &Thread, from: Option<u64>) -> Result<Self::MessagesIter, Error>;
}
