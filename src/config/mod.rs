use libsignal_protocol::Context;

use crate::{manager::State, Error};

mod sled;
pub use crate::config::sled::SledConfigStore;

pub trait ConfigStore {
    fn state(&self, context: &Context) -> Result<State, Error>;

    fn save(&self, state: &State) -> Result<(), Error>;

    fn pre_keys_offset_id(&self) -> Result<u32, Error>;
    fn set_pre_keys_offset_id(&self, id: u32) -> Result<(), Error>;

    fn next_signed_pre_key_id(&self) -> Result<u32, Error>;
    fn set_next_signed_pre_key_id(&self, id: u32) -> Result<(), Error>;
}