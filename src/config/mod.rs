use ::sled::IVec;
use libsignal_protocol::Context;

use crate::{manager::State, Error};

mod sled;
pub use crate::config::sled::SledConfigStore;

pub trait ConfigStore {
    fn state(&self, context: &Context) -> Result<State, Error>;

    fn save(&self, state: &State) -> Result<(), Error>;

    fn get<K: AsRef<str>>(&self, key: K) -> Result<Option<IVec>, Error>;
    fn insert<K, V>(&self, key: K, value: V) -> Result<(), Error>
    where
        K: AsRef<str>,
        IVec: From<V>;

    fn get_u32<S>(&self, key: S) -> Result<Option<u32>, Error>
    where
        S: AsRef<str>;

    fn insert_u32<S>(&self, key: S, value: u32) -> Result<(), Error>
    where
        S: AsRef<str>;
}
