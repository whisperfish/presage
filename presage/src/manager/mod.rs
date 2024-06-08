//! Signal manager and its states

mod confirmation;
mod linking;
mod registered;
mod registration;

use std::fmt;

use rand::rngs::StdRng;

pub use self::confirmation::Confirmation;
pub use self::linking::Linking;
pub use self::registered::{ReceivingMode, Registered, RegistrationData, RegistrationType};
pub use self::registration::{Registration, RegistrationOptions};

/// Signal manager
///
/// The manager is parametrized over the [`crate::store::Store`] which stores the configuration, keys and
/// optionally messages; and over the type state which describes what is the current state of the
/// manager: in registration, linking, TODO
///
/// Depending on the state specific methods are available or not.
#[derive(Clone)]
pub struct Manager<Store, State> {
    /// Implementation of a metadata and messages store
    store: Store,
    /// Part of the manager which is persisted in the store.
    state: State,
    /// Random number generator
    rng: StdRng,
}

impl<Store, State: fmt::Debug> fmt::Debug for Manager<Store, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manager")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}
