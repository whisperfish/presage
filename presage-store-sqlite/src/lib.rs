#![allow(warnings)]

use std::{future::Future, path::Path, pin::Pin};

use presage::{
    libsignal_service::protocol::SignalProtocolError,
    model::identity::OnNewIdentity,
    store::{StateStore, Store},
};
use protocol::SqliteProtocolStore;
use sqlx::{
    migrate::{MigrateDatabase, Migration, MigrationSource, Migrator},
    query, query_scalar,
    sqlite::SqliteConnectOptions,
    Sqlite, SqlitePool,
};

mod content;
pub(crate) mod data;
mod error;
mod protocol;

pub use error::SqliteStoreError;
use tracing::{debug, trace};

static MIGRATOR: Migrator = sqlx::migrate!();

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
        let db_path = db_path.as_ref();
        let db_path_str = db_path.to_str().unwrap();

        // Create database if it doesn't exist
        if !Sqlite::database_exists(db_path_str).await.unwrap_or(false) {
            debug!(path = db_path_str, "creating sqlite database");
            Sqlite::create_database(db_path_str).await?;
        }

        let connect_options = SqliteConnectOptions::new().filename(db_path);
        let pool = SqlitePool::connect_with(connect_options).await?;

        debug!("applying sqlite migrations");
        MIGRATOR.run(&pool).await?;

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
        query!("DELETE FROM config").execute(&self.db).await?;
        Ok(())
    }

    fn aci_protocol_store(&self) -> Self::AciStore {
        SqliteProtocolStore {
            store: self.clone(),
            identity_type: "aci",
        }
    }

    fn pni_protocol_store(&self) -> Self::PniStore {
        SqliteProtocolStore {
            store: self.clone(),
            identity_type: "pni",
        }
    }
}

impl StateStore for SqliteStore {
    type StateStoreError = SqliteStoreError;

    #[tracing::instrument(skip(self))]
    async fn load_registration_data(
        &self,
    ) -> Result<Option<presage::manager::RegistrationData>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM config WHERE key = 'registration'")
            .fetch_optional(&self.db)
            .await?
            .map(|value: Vec<u8>| postcard::from_bytes(&value).map_err(Into::into))
            .transpose()
    }

    async fn set_aci_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        trace!("setting ACI identity key pair");
        let key_pair_bytes = key_pair.serialize();
        query!(
            "INSERT INTO config(key, value) VALUES('aci_identity_key_pair', ?)",
            key_pair_bytes
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn set_pni_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        trace!("setting PNI identity key pair");
        let key_pair_bytes = key_pair.serialize();
        query!(
            "INSERT INTO config(key, value) VALUES('pni_identity_key_pair', ?)",
            key_pair_bytes
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn save_registration_data(
        &mut self,
        state: &presage::manager::RegistrationData,
    ) -> Result<(), Self::StateStoreError> {
        trace!("saving registration data");
        let registration_data_json = postcard::to_allocvec(&state)?;
        query!(
            "INSERT INTO config(key, value) VALUES('registration', ?)",
            registration_data_json
        )
        .execute(&self.db)
        .await?;

        Ok(())
    }

    async fn is_registered(&self) -> bool {
        self.load_registration_data().await.ok().is_some()
    }

    async fn clear_registration(&mut self) -> Result<(), Self::StateStoreError> {
        query!("DELETE FROM config WHERE key = 'registration'")
            .execute(&self.db)
            .await?;
        Ok(())
    }
}
