use libsignal_service::{
    content::{ContentBody, Reaction},
    models::Contact,
    prelude::{
        protocol::{IdentityKeyStore, PreKeyStore, SessionStoreExt, SignedPreKeyStore},
        Content, Uuid,
    },
    proto::{data_message::Quote, sync_message::Sent, DataMessage, GroupContextV2, SyncMessage},
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

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub struct MessageIdentity(pub Uuid, pub u64);

impl TryFrom<&Content> for MessageIdentity {
    type Error = Error;
    fn try_from(c: &Content) -> Result<Self, <Self as TryFrom<&Content>>::Error> {
        Ok(Self(
            c.metadata.sender.uuid.ok_or(Error::ContentMissingUuid)?,
            c.metadata.timestamp,
        ))
    }
}

impl TryFrom<&Quote> for MessageIdentity {
    type Error = Error;

    fn try_from(q: &Quote) -> Result<Self, Self::Error> {
        Ok(Self(
            Uuid::parse_str(q.author_uuid.as_ref().ok_or(Error::ContentMissingUuid)?)?,
            q.id.ok_or(Error::ContentMissingUuid)?,
        ))
    }
}

impl TryFrom<&Reaction> for MessageIdentity {
    type Error = Error;

    fn try_from(r: &Reaction) -> Result<Self, Self::Error> {
        Ok(Self(
            Uuid::parse_str(
                r.target_author_uuid
                    .as_ref()
                    .ok_or(Error::ContentMissingUuid)?,
            )?,
            r.target_sent_timestamp.ok_or(Error::ContentMissingUuid)?,
        ))
    }
}

// 16 bytes for Uuid, 8 for timestamp
impl From<[u8; 24]> for MessageIdentity {
    fn from(bytes: [u8; 24]) -> Self {
        let bytes_uuid = &bytes[..16];
        let bytes_timestamp = &bytes[16..];
        Self(
            Uuid::from_bytes(bytes_uuid.try_into().unwrap()),
            u64::from_ne_bytes(bytes_timestamp.try_into().unwrap()),
        )
    }
}

impl From<MessageIdentity> for [u8; 24] {
    fn from(m: MessageIdentity) -> Self {
        [m.0.as_bytes() as &[u8], &m.1.to_ne_bytes()]
            .concat()
            .try_into()
            .unwrap()
    }
}

#[derive(Debug, Hash, Eq, PartialEq, Clone)]
pub enum Thread {
    Contact(Uuid),
    // Cannot use GroupMasterKey as unable to extract the bytes.
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
        if let Some(receiver_uuid) = receiver.and_then(|s| s.uuid.clone()) {
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

pub trait MessageStore {
    type MessagesIter: Iterator<Item = Content>;

    fn save_message(
        &mut self,
        message: Content,
        receiver: Option<impl Into<ServiceAddress>>,
    ) -> Result<(), Error>;
    fn messages(&self) -> Result<Vec<Content>, Error>;
    fn message_by_identity(&self, id: &MessageIdentity) -> Result<Option<Content>, Error>;
    fn messages_by_thread(
        &self,
        thread: &Thread,
        from: Option<u64>,
    ) -> Result<Self::MessagesIter, Error>;
}
