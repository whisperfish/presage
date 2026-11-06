//! The account's group credentials, kept for as long as the manager lives and shared by every
//! [`GroupsManager`](libsignal_service::groups_v2::GroupsManager) it makes.
//!
//! Each `GroupsManager` fetches a week of credentials when its cache has none for today
//! (`GET /v1/certificate/auth/group`). A manager made per group operation with a cache of its own
//! fetched them for every operation; with this one, once a week.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use libsignal_service::groups_v2::{CredentialsCache, CredentialsCacheError};
use libsignal_service::zkgroup::auth::AuthCredentialWithPniResponse;

/// The credentials every clone of the manager shares, by day.
#[derive(Clone)]
pub(crate) struct SharedGroupCredentials<V = AuthCredentialWithPniResponse>(
    Arc<Mutex<HashMap<u64, V>>>,
);

impl<V> Default for SharedGroupCredentials<V> {
    fn default() -> Self {
        Self(Arc::default())
    }
}

impl<V: Clone> SharedGroupCredentials<V> {
    /// A cache for one `GroupsManager`: what is known now, and what it fetches told to the rest.
    pub(crate) fn cache(&self) -> GroupCredentialsCache<V> {
        let known = self
            .0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        GroupCredentialsCache {
            known,
            shared: self.clone(),
        }
    }

    fn set(&self, credentials: HashMap<u64, V>) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = credentials;
    }
}

/// One `GroupsManager`'s view of the [`SharedGroupCredentials`]: it reads its own copy (the
/// trait lends out references), and writes through to the shared ones.
pub(crate) struct GroupCredentialsCache<V = AuthCredentialWithPniResponse> {
    known: HashMap<u64, V>,
    shared: SharedGroupCredentials<V>,
}

impl<V: Clone> GroupCredentialsCache<V> {
    fn known(&self, day: &u64) -> Option<&V> {
        self.known.get(day)
    }

    fn replace(&mut self, credentials: HashMap<u64, V>) {
        self.shared.set(credentials.clone());
        self.known = credentials;
    }

    fn empty(&mut self) {
        self.replace(HashMap::new());
    }
}

impl CredentialsCache for GroupCredentialsCache {
    fn clear(&mut self) -> Result<(), CredentialsCacheError> {
        self.empty();
        Ok(())
    }

    fn get(
        &self,
        key: &u64,
    ) -> Result<Option<&AuthCredentialWithPniResponse>, CredentialsCacheError> {
        Ok(self.known(key))
    }

    fn write(
        &mut self,
        map: HashMap<u64, AuthCredentialWithPniResponse>,
    ) -> Result<(), CredentialsCacheError> {
        self.replace(map);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::SharedGroupCredentials;

    #[test]
    fn what_one_cache_fetched_the_next_one_knows() {
        let shared = SharedGroupCredentials::<&str>::default();
        let mut first = shared.cache();
        assert_eq!(first.known(&1), None);
        first.replace(HashMap::from([(1, "today's")]));
        assert_eq!(first.known(&1), Some(&"today's"));
        let mut second = shared.cache();
        assert_eq!(second.known(&1), Some(&"today's"));
        second.empty();
        assert_eq!(shared.cache().known(&1), None);
    }
}
