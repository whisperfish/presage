use libsignal_service::libsignal_account_keys::AccountEntropyPool;
use libsignal_service::master_key::{MasterKey, StorageServiceKey};

use crate::store::StateStore;

/// What this device has of the account's keys. All of them come from the account entropy
/// pool, which a primary device makes and a linked one is given at linking or in a key sync.
/// A device linked before the pool existed has only the master key.
#[derive(Debug, PartialEq)]
pub struct AccountKeys {
    master_key: MasterKey,
}

impl AccountKeys {
    pub fn from_pool(pool: &AccountEntropyPool) -> Self {
        Self {
            // The SVR key is the account's master key.
            master_key: MasterKey {
                inner: pool.derive_svr_key(),
            },
        }
    }

    /// `None` until this device has the pool or a master key.
    pub async fn load<S: StateStore>(store: &S) -> Result<Option<Self>, S::StateStoreError> {
        Ok(match store.fetch_account_entropy_pool().await? {
            Some(pool) => Some(Self::from_pool(&pool)),
            None => store
                .fetch_master_key()
                .await?
                .map(|master_key| Self { master_key }),
        })
    }

    pub fn master_key(&self) -> &MasterKey {
        &self.master_key
    }

    /// Encrypts the account's records in the storage service.
    pub fn storage_key(&self) -> StorageServiceKey {
        StorageServiceKey::from_master_key(&self.master_key)
    }
}
