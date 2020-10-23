use ::sled::IVec;
use libsignal_protocol::Context;

use crate::{manager::State, Error};

mod sled;
pub use crate::config::sled::SledConfigStore;

pub trait ConfigStore {
    fn state(&self, context: &Context) -> Result<State, Error>;

    fn pre_key_id_offset(&self) -> Result<u32, Error>;
    fn next_signed_pre_key_id(&self) -> Result<u32, Error>;

    fn save(&self, state: &State) -> Result<(), Error>;

    fn get<K: AsRef<[u8]>>(&self, key: K) -> Result<Option<IVec>, Error>;
    fn insert<K, V>(&self, key: K, value: V) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        IVec: From<V>;

    fn incr<K: AsRef<[u8]>>(&self, key: K) -> Result<u32, Error>;
}
