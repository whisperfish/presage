use std::borrow::Cow;

use presage::{
    libsignal_service::{prelude::MasterKey, protocol::SenderCertificate},
    store::{StateStore, Store},
};
use protocol::{IdentityType, SqliteProtocolStore};
use sqlx::{
    SqlitePool,
    migrate::{Migrate, Migration, MigrationType},
    query, query_scalar,
    sqlite::{SqliteJournalMode, SqliteSynchronous},
};

mod content;
mod data;
mod error;
mod protocol;

pub use error::SqliteStoreError;
pub use presage::model::identity::OnNewIdentity;
pub use sqlx::sqlite::SqliteConnectOptions;

use crate::error::SqlxErrorExt;

#[derive(Debug, Clone)]
pub struct SqliteStore {
    pub(crate) db: SqlitePool,
    pub(crate) trust_new_identities: OnNewIdentity,
}

impl SqliteStore {
    pub async fn open(
        url: &str,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        let options: SqliteConnectOptions = url.parse()?;
        Self::open_with_options(options, trust_new_identities).await
    }

    pub async fn open_with_passphrase(
        url: &str,
        passphrase: Option<&str>,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        // Escape the passphrase.
        let passphrase = passphrase.map(|p| p.replace("'", "''"));

        let options: SqliteConnectOptions = url.parse()?;
        let options = options.create_if_missing(true).foreign_keys(true);
        let options = if let Some(passphrase) = &passphrase {
            options.pragma("key", format!("'{passphrase}'"))
        } else {
            options
        };
        match Self::open_with_options(options.clone(), trust_new_identities.clone()).await {
            Ok(s) => Ok(s),
            // The error "file is not a database" (error code 26) could mean that we provided a key for decrypting the database, but the database was actually not encrypted due to a bug in earlier versions of presage-store-sqlite.
            // If that is the case, try to migrate the database to be encrypted.
            Err(SqliteStoreError::Migrate(sqlx::migrate::MigrateError::Execute(
                sqlx::Error::Database(e),
            ))) if e.code().is_some_and(|c| c.as_ref() == "26") => {
                // Attempting migration only makes sense if a passphrase is given, otherwise just return the error.
                let Some(passphrase) = passphrase else {
                    return Err(SqliteStoreError::Migrate(
                        sqlx::migrate::MigrateError::Execute(sqlx::Error::Database(e)),
                    ));
                };

                // It does not make sense to try a migration of an in-memory database.
                // Also abort in that case.
                if url == ":memory:" {
                    return Err(SqliteStoreError::Migrate(
                        sqlx::migrate::MigrateError::Execute(sqlx::Error::Database(e)),
                    ));
                }

                Self::open_migrate_to_encrypted(url, &passphrase, trust_new_identities).await
            }
            Err(e) => Err(e),
        }
    }

    pub async fn open_with_options(
        options: SqliteConnectOptions,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        let options = options
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full);
        let db = SqlitePool::connect_with(options).await?;

        // A migration that caused errors for some users was sadly shipped.
        // Revert this migration, which got instead replaced by 20260119182700_remove_device_id_from_identities.sql.
        // This revert code should be removable once it was shipped to the affected users.
        let mut connection = db.acquire().await?;
        connection.ensure_migrations_table().await?;
        if connection
            .list_applied_migrations()
            .await?
            .iter()
            .any(|m| m.version == 20260101163100)
        {
            connection
                .revert(&Migration::new(
                    20260101163100,
                    Cow::Borrowed("revert broken identities migration"),
                    MigrationType::ReversibleDown,
                    Cow::Borrowed("ALTER TABLE identities ADD COLUMN device_id DEFAULT 1"),
                    false,
                ))
                .await?;
        }

        sqlx::migrate!().run(&db).await?;
        Ok(Self {
            db,
            trust_new_identities,
        })
    }

    /// There sadly does not seem to be a good migration strategy contained within the database we are trying to migrate.
    /// The general migration strategy is therefore creating a new encrypted database, copy the data from the unencrypted to the encrypted database, and then replace the unencrypted database with the encrypted one.
    /// The details can be found in this comment: <https://github.com/davidmartos96/sqflite_sqlcipher/issues/20#issuecomment-634167760>.
    ///
    /// This assumes that the passphrase is escaped (i.e. all `'` are already replaced by `''`).
    async fn open_migrate_to_encrypted(
        url: &str,
        passphrase: &str,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SqliteStoreError> {
        tracing::info!("Attempting to migrate an unencrypted sqlite store to an encrypted one");
        // The place where the encrypted database will be temporarily stored.
        let encrypted_url = format!("{url}.encrypted");

        // Try to open the database to migrate without any encryption.
        let no_password_options: SqliteConnectOptions = url.parse()?;
        let no_password_options = no_password_options
            .create_if_missing(true)
            .foreign_keys(true);
        let no_password_db =
            Self::open_with_options(no_password_options, trust_new_identities.clone()).await?;

        // Execute the migration.
        // This cannot be done in an sqlx macro way checking that the sql code is actually correct, as the macro does not seem to have `sqlcipher_export` available.
        // Note that `raw_sql` does not support query parameters (https://docs.rs/sqlx/latest/sqlx/fn.raw_sql.html#note-query-parameters-are-not-supported).
        // Therefore, in theory, an sql-injection could be possible.
        // But we escape the `encrypted_url`, and assume the passphrase to already be escaped, so I don't think an injection is actually possible.
        sqlx::raw_sql(&format!(
            "ATTACH DATABASE '{}' AS encrypted KEY '{passphrase}';
            SELECT sqlcipher_export('encrypted');
            DETACH DATABASE encrypted;",
            encrypted_url.replace("'", "''")
        ))
        .execute(&no_password_db.db)
        .await?;

        drop(no_password_db);

        // Replace the unencrypted database with the encrypted one.
        // TODO: Maybe zero out the unencrypted URL before?
        std::fs::rename(encrypted_url, url)?;

        // Return the now encrypted store.
        let options: SqliteConnectOptions = url.parse()?;
        let options = options.create_if_missing(true).foreign_keys(true);
        let options = options.pragma("key", format!("'{passphrase}'"));
        Self::open_with_options(options, trust_new_identities).await
    }
}

impl Store for SqliteStore {
    type Error = SqliteStoreError;

    type AciStore = SqliteProtocolStore;

    type PniStore = SqliteProtocolStore;

    async fn clear(&mut self) -> Result<(), SqliteStoreError> {
        query!("DELETE FROM kv").execute(&self.db).await?;
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
        query_scalar!("SELECT value FROM kv WHERE key = 'registration'")
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
            "INSERT OR REPLACE INTO kv (key, value) VALUES ('registration', ?)",
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
        let mut transaction = self.db.begin().await.into_protocol_error()?;
        query!("DELETE FROM kv WHERE key = 'registration'")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM sessions")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM identities")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM pre_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM signed_pre_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM kyber_pre_keys")
            .execute(&mut *transaction)
            .await?;
        query!("DELETE FROM sender_keys")
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await.into_protocol_error()?;
        Ok(())
    }

    async fn set_aci_identity_key_pair(
        &self,
        key_pair: presage::libsignal_service::protocol::IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        let key = IdentityType::Aci.identity_key_pair_key();
        let value = key_pair.serialize();
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
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
            "INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)",
            key,
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn sender_certificate(&self) -> Result<Option<SenderCertificate>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'sender_certificate' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| SenderCertificate::deserialize(&value))
            .transpose()
            .map_err(From::from)
    }

    async fn save_sender_certificate(
        &self,
        certificate: &SenderCertificate,
    ) -> Result<(), Self::StateStoreError> {
        let value = certificate.serialized()?;
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES ('sender_certificate', ?)",
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }

    async fn fetch_master_key(&self) -> Result<Option<MasterKey>, Self::StateStoreError> {
        query_scalar!("SELECT value FROM kv WHERE key = 'master_key' LIMIT 1")
            .fetch_optional(&self.db)
            .await?
            .map(|value| MasterKey::from_slice(&value))
            .transpose()
            .map_err(|_| SqliteStoreError::InvalidFormat)
    }

    async fn store_master_key(
        &self,
        master_key: Option<&MasterKey>,
    ) -> Result<(), Self::StateStoreError> {
        let value = master_key.map(|k| &k.inner[..]);
        query!(
            "INSERT OR REPLACE INTO kv (key, value) VALUES ('master_key', ?)",
            value
        )
        .execute(&self.db)
        .await?;
        Ok(())
    }
}
