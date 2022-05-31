use libsignal_service::{
    models::Contact,
    prelude::{
        protocol::{IdentityKeyStore, PreKeyStore, SessionStoreExt, SignedPreKeyStore},
        Uuid,
    },
};

use crate::{manager::Registered, Error};

#[cfg(feature = "sled-store")]
pub mod sled;

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
    fn set_pre_keys_offset_id(&self, id: u32) -> Result<(), Error>;

    fn next_signed_pre_key_id(&self) -> Result<u32, Error>;
    fn set_next_signed_pre_key_id(&self, id: u32) -> Result<(), Error>;
}

pub trait StateStore<S> {
    fn load_state(&self) -> Result<Registered, Error>;
    fn save_state(&self, state: &S) -> Result<(), Error>;
}

pub trait ContactsStore {
    fn save_contacts(&mut self, contacts: impl Iterator<Item = Contact>) -> Result<(), Error>;
    fn contacts(&self) -> Result<Vec<Contact>, Error>;
    fn contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Error>;
}
