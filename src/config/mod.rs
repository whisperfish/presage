use libsignal_service::{
    models::Contact,
    prelude::protocol::{IdentityKeyStore, PreKeyStore, SessionStoreExt, SignedPreKeyStore},
};

use crate::{manager::State, Error};

#[cfg(feature = "sled-store")]
pub mod sled;

pub trait ConfigStore:
    PreKeyStore + SignedPreKeyStore + SessionStoreExt + IdentityKeyStore + ContactsStore + Clone
{
    fn state(&self) -> Result<State, Error>;

    fn save(&self, state: &State) -> Result<(), Error>;

    fn pre_keys_offset_id(&self) -> Result<u32, Error>;
    fn set_pre_keys_offset_id(&self, id: u32) -> Result<(), Error>;

    fn next_signed_pre_key_id(&self) -> Result<u32, Error>;
    fn set_next_signed_pre_key_id(&self, id: u32) -> Result<(), Error>;
}

pub trait ContactsStore {
    fn save_contacts(&mut self, contacts: impl Iterator<Item = Contact>) -> Result<(), Error>;
    fn contacts(&self) -> Result<Vec<Contact>, Error>;
}
