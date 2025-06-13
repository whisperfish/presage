//! Signal manager and its states

mod confirmation;
mod linking;
mod registered;
mod registration;

use std::{fmt, sync::Arc};

pub use self::confirmation::Confirmation;
pub use self::linking::Linking;
pub use self::registered::{Registered, RegistrationData, RegistrationType};
pub use self::registration::{Registration, RegistrationOptions};

/// Signal manager
///
/// The manager is parametrized over the [`crate::store::Store`] which stores the configuration, keys and
/// optionally messages; and over the type state which describes what is the current state of the
/// manager: in registration, linking, TODO
///
/// Depending on the state specific methods are available or not.
pub struct Manager<Store, State> {
    /// Implementation of a metadata and messages store
    store: Store,
    /// Part of the manager which is persisted in the store.
    state: Arc<State>,
}

#[cfg(test)]
#[allow(dead_code)]
fn assert_registered_manager_is_send<S: Send>() {
    fn check_send<T: Send>() {}
    check_send::<Manager<S, Registered>>();
}

impl<Store: Clone, State> Clone for Manager<Store, State> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            state: self.state.clone(),
        }
    }
}

impl<Store, State: fmt::Debug> fmt::Debug for Manager<Store, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manager")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn managers_are_sync() {
        fn is_sync<T: Sync>() {}

        // Store trait has Send + Sync as super-trait, test States only
        is_sync::<Manager<(), Confirmation>>();
        is_sync::<Manager<(), Linking>>();
        is_sync::<Manager<(), Registration>>();
        is_sync::<Manager<(), Registered>>();
    }
}
