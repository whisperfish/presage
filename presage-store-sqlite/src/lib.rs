#![allow(warnings)]

use std::path::Path;

use presage::{
    libsignal_service::protocol::SignalProtocolError,
    model::identity::OnNewIdentity,
    store::{StateStore, Store},
};
use protocol::SqliteProtocolStore;
use sqlx::{migrate::MigrateDatabase, sqlite::SqliteConnectOptions, Sqlite, SqlitePool};

mod content;
mod error;
mod protocol;

pub use error::SqliteStoreError;

#[derive(Debug, Clone)]
pub struct SqliteStore {
    db: SqlitePool,
    /// Whether to trust new identities automatically (for instance, when a somebody's phone has changed)
    trust_new_identities: OnNewIdentity,
}

impl SqliteStore {
    pub async fn open(
        db_path: impl AsRef<Path>,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        let connect_options = SqliteConnectOptions::new().filename(db_path);
        let pool = SqlitePool::connect_with(connect_options).await?;

        Ok(Self {
            db: pool,
            trust_new_identities,
        })
    }
}

trait SqlxErrorExt<T> {
    fn into_protocol_error(self) -> Result<T, SignalProtocolError>;
}

impl<T> SqlxErrorExt<T> for Result<T, sqlx::Error> {
    fn into_protocol_error(self) -> Result<T, SignalProtocolError> {
        self.map_err(|error| SignalProtocolError::InvalidState("sqlite", error.to_string()))
    }
}

impl Store for SqliteStore {
    type Error = SqliteStoreError;

    type AciStore = SqliteProtocolStore;

    type PniStore = SqliteProtocolStore;

    async fn clear(&mut self) -> Result<(), SqliteStoreError> {
        todo!()
    }

    fn aci_protocol_store(&self) -> Self::AciStore {
        SqliteProtocolStore {
            store: self.clone(),
        }
    }

    fn pni_protocol_store(&self) -> Self::PniStore {
        SqliteProtocolStore {
            store: self.clone(),
        }
    }
}

impl StateStore for SqliteStore {
    type StateStoreError = SqliteStoreError;

    async fn load_registration_data(
        &self,
    ) -> Result<Option<presage::manager::RegistrationData>, Self::StateStoreError> {
        todo!()
    }

    async fn set_aci_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        todo!()
    }

    async fn set_pni_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        todo!()
    }

    async fn save_registration_data(
        &mut self,
        state: &presage::manager::RegistrationData,
    ) -> Result<(), Self::StateStoreError> {
        todo!()
    }

    async fn is_registered(&self) -> bool {
        todo!()
    }

    async fn clear_registration(&mut self) -> Result<(), Self::StateStoreError> {
        todo!()
    }
}
