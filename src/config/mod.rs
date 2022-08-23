use libsignal_service::{
    models::Contact,
    prelude::{
        protocol::{IdentityKeyStore, PreKeyStore, SessionStoreExt, SignedPreKeyStore},
        Content, Uuid,
    },
    proto::GroupContextV2,
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

#[derive(Debug)]
pub struct MessageIdentity(Uuid, u64);

impl TryFrom<&Content> for MessageIdentity {
    type Error = Error;
    fn try_from(c: &Content) -> Result<Self, <Self as TryFrom<&Content>>::Error> {
        Ok(Self(
            c.metadata.sender.uuid.ok_or(Error::ContentMissingUuid)?,
            c.metadata.timestamp,
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

pub trait MessageStore {
    fn save_message(&mut self, message: Content) -> Result<(), Error>;
    fn messages(&self) -> Result<Vec<Content>, Error>;
    fn message_by_identity(&self, id: &MessageIdentity) -> Result<Option<Content>, Error>;

    fn messages_by_contact(&self, contact: &Uuid) -> Result<Vec<MessageIdentity>, Error>;
    fn messages_by_group(&self, group: &GroupContextV2) -> Result<Vec<MessageIdentity>, Error>;
}
