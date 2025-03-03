use presage::{
    model::identity::OnNewIdentity,
    store::{StateStore, Store},
};
use protocol::{IdentityType, SqliteProtocolStore};
use sqlx::{query, query_scalar, sqlite::SqliteConnectOptions, SqlitePool};

mod content;
mod data;
mod error;
mod protocol;

pub use error::SqliteStoreError;

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pub(crate) db: SqlitePool,
}

impl SqliteStore {
    pub async fn open(
        url: &str,
        _trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        let options: SqliteConnectOptions = url.parse()?;
        let pool = SqlitePool::connect_with(options).await?;
        Ok(Self { db: pool })
    }
}

impl Store for SqliteStore {
    type Error = SqliteStoreError;

    type AciStore = SqliteProtocolStore;

    type PniStore = SqliteProtocolStore;

    async fn clear(&mut self) -> Result<(), SqliteStoreError> {
        query!("DELETE FROM presage_kv").execute(&self.db).await?;
        Ok(())
    }

    fn aci_protocol_store(&self) -> Self::AciStore {
        SqliteProtocolStore {
            store: self.clone(),
            identity: IdentityType::Aci,
        }
    }

    fn pni_protocol_store(&self) -> Self::PniStore {
        SqliteProtocolStore {
            store: self.clone(),
            identity: IdentityType::Pni,
        }
    }
}

impl StateStore for SqliteStore {
    type StateStoreError = SqliteStoreError;

    async fn load_registration_data(
        &self,
    ) -> Result<Option<presage::manager::RegistrationData>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM presage_kv WHERE key = 'registration'")
            .fetch_optional(&self.db)
            .await?
            .map(|value| serde_json::from_slice(&value))
            .transpose()
            .map_err(From::from)
    }

    async fn save_registration_data(
        &mut self,
        state: &presage::manager::RegistrationData,
    ) -> Result<(), Self::StateStoreError> {
        let value = serde_json::to_string(state)?;
        query!(
            "INSERT OR REPLACE INTO presage_kv (key, value) VALUES ('registration', ?)",
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn is_registered(&self) -> bool {
        self.load_registration_data().await.ok().flatten().is_some()
    }

    async fn clear_registration(&mut self) -> Result<(), Self::StateStoreError> {
        query!("DELETE FROM presage_kv WHERE key = 'registration'")
            .execute(&self.db)
            .await?;
        Ok(())
    }

    async fn set_aci_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        let key = IdentityType::Aci.identity_key_pair_key();
        let value = key_pair.serialize();
        query!(
            "INSERT OR REPLACE INTO presage_kv (key, value) VALUES (?, ?)",
            key,
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn set_pni_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        let key = IdentityType::Pni.identity_key_pair_key();
        let value = key_pair.serialize();
        query!(
            "INSERT OR REPLACE INTO presage_kv (key, value) VALUES (?, ?)",
            key,
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }
}
