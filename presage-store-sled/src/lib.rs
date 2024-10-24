use std::{
    ops::Range,
    path::Path,
    sync::{Arc, RwLock, RwLockReadGuard, RwLockWriteGuard},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::prelude::*;
use presage::{
    libsignal_service::{
        prelude::{ProfileKey, Uuid},
        protocol::{IdentityKey, IdentityKeyPair, PrivateKey},
        utils::{
            serde_identity_key, serde_optional_identity_key, serde_optional_private_key,
            serde_private_key,
        },
    },
    manager::RegistrationData,
    model::identity::OnNewIdentity,
    store::{ContentsStore, StateStore, Store},
};
use protocol::{AciSledStore, PniSledStore, SledProtocolStore, SledTrees};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, error};

mod content;
mod error;
mod protobuf;
mod protocol;

pub use error::SledStoreError;
use sled::IVec;

const SLED_TREE_STATE: &str = "state";

const SLED_KEY_REGISTRATION: &str = "registration";
const SLED_KEY_SCHEMA_VERSION: &str = "schema_version";
#[cfg(feature = "encryption")]
const SLED_KEY_STORE_CIPHER: &str = "store_cipher";

#[derive(Clone)]
pub struct SledStore {
    db: Arc<RwLock<sled::Db>>,
    #[cfg(feature = "encryption")]
    cipher: Option<Arc<presage_store_cipher::StoreCipher>>,
    /// Whether to trust new identities automatically (for instance, when a somebody's phone has changed)
    trust_new_identities: OnNewIdentity,
}

/// Sometimes Migrations can't proceed without having to drop existing
/// data. This allows you to configure, how these cases should be handled.
#[derive(Default, PartialEq, Eq, Clone, Debug)]
pub enum MigrationConflictStrategy {
    /// Just drop the data, we don't care that we have to register or link again
    Drop,
    /// Raise a `Error::MigrationConflict` error with the path to the
    /// DB in question. The caller then has to take care about what they want
    /// to do and try again after.
    #[default]
    Raise,
    /// _Default_: The _entire_ database is backed up under, before the databases are dropped.
    BackupAndDrop,
}

#[derive(PartialEq, Eq, Clone, Debug, Default, Serialize, Deserialize)]
pub enum SchemaVersion {
    /// prior to any versioning of the schema
    #[default]
    V0 = 0,
    V1 = 1,
    V2 = 2,
    V3 = 3,
    // Introduction of avatars, requires dropping all profiles from the cache
    V4 = 4,
    /// ACI and PNI identity key pairs are moved into dedicated storage keys from registration data
    V5 = 5,
    /// Reset pre-keys after fixing persistence
    V6 = 6,
}

impl SchemaVersion {
    fn current() -> SchemaVersion {
        Self::V6
    }

    /// return an iterator on all the necessary migration steps from another version
    fn steps(self) -> impl Iterator<Item = SchemaVersion> {
        Range {
            start: self as u8 + 1,
            end: Self::current() as u8 + 1,
        }
        .map(|i| match i {
            1 => SchemaVersion::V1,
            2 => SchemaVersion::V2,
            3 => SchemaVersion::V3,
            4 => SchemaVersion::V4,
            5 => SchemaVersion::V5,
            6 => SchemaVersion::V6,
            _ => unreachable!("oops, this not supposed to happen!"),
        })
    }
}

impl SledStore {
    #[allow(unused_variables)]
    fn new(
        db_path: impl AsRef<Path>,
        passphrase: Option<impl AsRef<str>>,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SledStoreError> {
        let database = sled::open(db_path)?;

        #[cfg(feature = "encryption")]
        let cipher = passphrase
            .map(|p| Self::get_or_create_store_cipher(&database, p.as_ref()))
            .transpose()?;

        #[cfg(not(feature = "encryption"))]
        if passphrase.is_some() {
            panic!("A passphrase was supplied but the encryption feature flag is not enabled")
        }

        Ok(SledStore {
            db: Arc::new(RwLock::new(database)),
            #[cfg(feature = "encryption")]
            cipher: cipher.map(Arc::new),
            trust_new_identities,
        })
    }

    pub async fn open(
        db_path: impl AsRef<Path>,
        migration_conflict_strategy: MigrationConflictStrategy,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SledStoreError> {
        Self::open_with_passphrase(
            db_path,
            None::<&str>,
            migration_conflict_strategy,
            trust_new_identities,
        )
        .await
    }

    pub async fn open_with_passphrase(
        db_path: impl AsRef<Path>,
        passphrase: Option<impl AsRef<str>>,
        migration_conflict_strategy: MigrationConflictStrategy,
        trust_new_identities: OnNewIdentity,
    ) -> Result<Self, SledStoreError> {
        let passphrase = passphrase.as_ref();

        migrate(&db_path, passphrase, migration_conflict_strategy).await?;
        Self::new(db_path, passphrase, trust_new_identities)
    }

    #[cfg(feature = "encryption")]
    fn get_or_create_store_cipher(
        database: &sled::Db,
        passphrase: &str,
    ) -> Result<presage_store_cipher::StoreCipher, SledStoreError> {
        let cipher = if let Some(key) = database.get(SLED_KEY_STORE_CIPHER)? {
            presage_store_cipher::StoreCipher::import(passphrase, &key)?
        } else {
            let cipher = presage_store_cipher::StoreCipher::new();
            #[cfg(not(test))]
            let export = cipher.export(passphrase);
            #[cfg(test)]
            let export = cipher.insecure_export_fast_for_testing(passphrase);
            database.insert(SLED_KEY_STORE_CIPHER, export?)?;
            cipher
        };

        Ok(cipher)
    }

    #[cfg(test)]
    fn temporary() -> Result<Self, SledStoreError> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Self {
            db: Arc::new(RwLock::new(db)),
            #[cfg(feature = "encryption")]
            // use store cipher with a random key
            cipher: Some(Arc::new(presage_store_cipher::StoreCipher::new())),
            trust_new_identities: OnNewIdentity::Reject
        })
    }

    fn read(&self) -> RwLockReadGuard<sled::Db> {
        self.db.read().expect("poisoned rwlock")
    }

    fn write(&self) -> RwLockWriteGuard<sled::Db> {
        self.db.write().expect("poisoned rwlock")
    }

    fn schema_version(&self) -> SchemaVersion {
        self.get(SLED_TREE_STATE, SLED_KEY_SCHEMA_VERSION)
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    #[cfg(feature = "encryption")]
    fn decrypt_value<T: DeserializeOwned>(&self, value: IVec) -> Result<T, SledStoreError> {
        if let Some(cipher) = self.cipher.as_ref() {
            Ok(cipher.decrypt_value(&value)?)
        } else {
            Ok(serde_json::from_slice(&value)?)
        }
    }

    #[cfg(not(feature = "encryption"))]
    fn decrypt_value<T: DeserializeOwned>(&self, value: IVec) -> Result<T, SledStoreError> {
        Ok(serde_json::from_slice(value)?)
    }

    #[cfg(feature = "encryption")]
    fn encrypt_value(&self, value: &impl Serialize) -> Result<Vec<u8>, SledStoreError> {
        if let Some(cipher) = self.cipher.as_ref() {
            Ok(cipher.encrypt_value(value)?)
        } else {
            Ok(serde_json::to_vec(value)?)
        }
    }

    #[cfg(not(feature = "encryption"))]
    fn encrypt_value(&self, value: &impl Serialize) -> Result<Vec<u8>, SledStoreError> {
        Ok(serde_json::to_vec(value)?)
    }

    pub fn get<K, V>(&self, tree: &str, key: K) -> Result<Option<V>, SledStoreError>
    where
        K: AsRef<[u8]>,
        V: DeserializeOwned,
    {
        self.read()
            .open_tree(tree)?
            .get(key)?
            .map(|p| self.decrypt_value(p))
            .transpose()
            .map_err(SledStoreError::from)
    }

    pub fn iter<'a, V: DeserializeOwned + 'a>(
        &'a self,
        tree: &str,
    ) -> Result<impl Iterator<Item = Result<V, SledStoreError>> + 'a, SledStoreError> {
        Ok(self
            .read()
            .open_tree(tree)?
            .iter()
            .flat_map(|res| res.map(|(_, value)| self.decrypt_value::<V>(value))))
    }

    fn insert<K, V>(&self, tree: &str, key: K, value: V) -> Result<bool, SledStoreError>
    where
        K: AsRef<[u8]>,
        V: Serialize,
    {
        let value = self.encrypt_value(&value)?;
        let db = self.write();
        let replaced = db.open_tree(tree)?.insert(key, value)?;
        db.flush()?;
        Ok(replaced.is_some())
    }

    fn remove<K>(&self, tree: &str, key: K) -> Result<bool, SledStoreError>
    where
        K: AsRef<[u8]>,
    {
        let db = self.write();
        let removed = db.open_tree(tree)?.remove(key)?;
        db.flush()?;
        Ok(removed.is_some())
    }

    fn profile_key_for_uuid(&self, uuid: Uuid, key: ProfileKey) -> String {
        let key = uuid.into_bytes().into_iter().chain(key.get_bytes());

        let mut hasher = Sha256::new();
        hasher.update(key.collect::<Vec<_>>());
        format!("{:x}", hasher.finalize())
    }

    fn get_identity_key_pair<T: SledTrees>(
        &self,
    ) -> Result<Option<IdentityKeyPair>, SledStoreError> {
        let key_base64: Option<String> = self.get(SLED_TREE_STATE, T::identity_keypair())?;
        let Some(key_base64) = key_base64 else {
            return Ok(None);
        };
        let key_bytes = BASE64_STANDARD.decode(key_base64)?;
        IdentityKeyPair::try_from(&*key_bytes)
            .map(Some)
            .map_err(|e| SledStoreError::ProtobufDecode(prost::DecodeError::new(e.to_string())))
    }

    fn set_identity_key_pair<T: SledTrees>(
        &self,
        key_pair: IdentityKeyPair,
    ) -> Result<(), SledStoreError> {
        let key_bytes = key_pair.serialize();
        let key_base64 = BASE64_STANDARD.encode(key_bytes);
        self.insert(SLED_TREE_STATE, T::identity_keypair(), key_base64)?;
        Ok(())
    }
}

async fn migrate(
    db_path: impl AsRef<Path>,
    passphrase: Option<impl AsRef<str>>,
    migration_conflict_strategy: MigrationConflictStrategy,
) -> Result<(), SledStoreError> {
    let db_path = db_path.as_ref();
    let passphrase = passphrase.as_ref();

    let run_migrations = {
        let mut store = SledStore::new(db_path, passphrase, OnNewIdentity::Reject)?;
        let schema_version = store.schema_version();
        for step in schema_version.steps() {
            match &step {
                SchemaVersion::V1 => {
                    debug!("migrating from v0, nothing to do")
                }
                SchemaVersion::V2 => {
                    debug!("migrating from schema v1 to v2: encrypting state if cipher is enabled");

                    // load registration data the old school way
                    let registration = store.read().get(SLED_KEY_REGISTRATION)?;
                    if let Some(data) = registration {
                        let state = serde_json::from_slice(&data).map_err(SledStoreError::from)?;

                        // save it the new school way
                        store.save_registration_data(&state).await?;

                        // remove old data
                        let db = store.write();
                        db.remove(SLED_KEY_REGISTRATION)?;
                        db.flush()?;
                    }
                }
                SchemaVersion::V3 => {
                    debug!("migrating from schema v2 to v3: dropping encrypted group cache");
                    store.clear_groups().await?;
                }
                SchemaVersion::V4 => {
                    debug!("migrating from schema v3 to v4: dropping profile cache");
                    store.clear_profiles().await?;
                }
                SchemaVersion::V5 => {
                    debug!("migrating from schema v4 to v5: moving identity key pairs");

                    #[derive(Deserialize)]
                    struct RegistrationDataV4Keys {
                        #[serde(with = "serde_private_key", rename = "private_key")]
                        pub(crate) aci_private_key: PrivateKey,
                        #[serde(with = "serde_identity_key", rename = "public_key")]
                        pub(crate) aci_public_key: IdentityKey,
                        #[serde(with = "serde_optional_private_key", default)]
                        pub(crate) pni_private_key: Option<PrivateKey>,
                        #[serde(with = "serde_optional_identity_key", default)]
                        pub(crate) pni_public_key: Option<IdentityKey>,
                    }

                    let run_step: Result<(), SledStoreError> = {
                        let registration_data: Option<RegistrationDataV4Keys> =
                            store.get(SLED_TREE_STATE, SLED_KEY_REGISTRATION)?;
                        if let Some(data) = registration_data {
                            store
                                .set_aci_identity_key_pair(IdentityKeyPair::new(
                                    data.aci_public_key,
                                    data.aci_private_key,
                                ))
                                .await?;
                            if let Some((public_key, private_key)) =
                                data.pni_public_key.zip(data.pni_private_key)
                            {
                                store
                                    .set_pni_identity_key_pair(IdentityKeyPair::new(
                                        public_key,
                                        private_key,
                                    ))
                                    .await?;
                            }
                        }
                        Ok(())
                    };

                    if let Err(error) = run_step {
                        error!("failed to run v4 -> v5 migration: {error}");
                    }
                }
                SchemaVersion::V6 => {
                    debug!("migrating from schema v5 to v6: new keys encoding in ACI and PNI protocol stores");
                    let db = store.db.read().expect("poisoned");

                    let trees = [
                        AciSledStore::signed_pre_keys(),
                        AciSledStore::pre_keys(),
                        AciSledStore::kyber_pre_keys(),
                        AciSledStore::kyber_pre_keys_last_resort(),
                        PniSledStore::signed_pre_keys(),
                        PniSledStore::pre_keys(),
                        PniSledStore::kyber_pre_keys(),
                        PniSledStore::kyber_pre_keys_last_resort(),
                    ];

                    for tree_name in trees {
                        let tree = db.open_tree(tree_name)?;
                        let num_keys_before = tree.len();
                        let mut data = Vec::new();
                        for (k, v) in tree.iter().filter_map(|kv| kv.ok()) {
                            if let Some(key) = std::str::from_utf8(&k)
                                .ok()
                                .and_then(|s| s.parse::<u32>().ok())
                            {
                                data.push((key, v));
                            }
                        }
                        tree.clear()?;
                        for (k, v) in data {
                            let _ = tree.insert(k.to_be_bytes(), v);
                        }
                        let num_keys_after = tree.len();
                        debug!(tree_name, num_keys_before, num_keys_after, "migrated keys");
                    }
                }
                _ => return Err(SledStoreError::MigrationConflict),
            }

            store.insert(SLED_TREE_STATE, SLED_KEY_SCHEMA_VERSION, step)?;
        }

        Ok(())
    };

    if let Err(SledStoreError::MigrationConflict) = run_migrations {
        match migration_conflict_strategy {
            MigrationConflictStrategy::BackupAndDrop => {
                let mut new_db_path = db_path.to_path_buf();
                new_db_path.set_extension(format!(
                    "{}.backup",
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .expect("time doesn't go backwards")
                        .as_secs()
                ));
                fs_extra::dir::create_all(&new_db_path, false)?;
                fs_extra::dir::copy(db_path, new_db_path, &fs_extra::dir::CopyOptions::new())?;
                fs_extra::dir::remove(db_path)?;
            }
            MigrationConflictStrategy::Drop => {
                fs_extra::dir::remove(db_path)?;
            }
            MigrationConflictStrategy::Raise => return Err(SledStoreError::MigrationConflict),
        }
    }

    Ok(())
}

impl StateStore for SledStore {
    type StateStoreError = SledStoreError;

    async fn load_registration_data(&self) -> Result<Option<RegistrationData>, SledStoreError> {
        self.get(SLED_TREE_STATE, SLED_KEY_REGISTRATION)
    }

    async fn set_aci_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        self.set_identity_key_pair::<AciSledStore>(key_pair)
    }

    async fn set_pni_identity_key_pair(
        &self,
        key_pair: IdentityKeyPair,
    ) -> Result<(), Self::StateStoreError> {
        self.set_identity_key_pair::<PniSledStore>(key_pair)
    }

    async fn save_registration_data(
        &mut self,
        state: &RegistrationData,
    ) -> Result<(), SledStoreError> {
        self.insert(SLED_TREE_STATE, SLED_KEY_REGISTRATION, state)?;
        Ok(())
    }

    async fn is_registered(&self) -> bool {
        self.load_registration_data()
            .await
            .unwrap_or_default()
            .is_some()
    }

    async fn clear_registration(&mut self) -> Result<(), SledStoreError> {
        // drop registration data (includes identity keys)
        {
            let db = self.write();
            db.remove(SLED_KEY_REGISTRATION)?;
            db.drop_tree(SLED_TREE_STATE)?;
            db.flush()?;
        }

        // drop all saved profile (+avatards) and profile keys
        self.clear_profiles().await?;

        // drop all keys
        self.aci_protocol_store().clear(true)?;
        self.pni_protocol_store().clear(true)?;

        Ok(())
    }
}

impl Store for SledStore {
    type Error = SledStoreError;
    type AciStore = SledProtocolStore<AciSledStore>;
    type PniStore = SledProtocolStore<PniSledStore>;

    async fn clear(&mut self) -> Result<(), SledStoreError> {
        self.clear_registration().await?;
        self.clear_contents().await?;

        Ok(())
    }

    fn aci_protocol_store(&self) -> Self::AciStore {
        SledProtocolStore::aci_protocol_store(self.clone())
    }

    fn pni_protocol_store(&self) -> Self::PniStore {
        SledProtocolStore::pni_protocol_store(self.clone())
    }
}

#[cfg(test)]
mod tests {
    use presage::libsignal_service::{
        content::{ContentBody, Metadata},
        prelude::Uuid,
        proto::DataMessage,
        protocol::PreKeyId,
        ServiceAddress, ServiceIdType,
    };
    use presage::store::ContentsStore;
    use protocol::SledPreKeyId;
    use quickcheck::{Arbitrary, Gen};
    use quickcheck_macros::quickcheck;

    use crate::SchemaVersion;

    use super::*;

    #[test]
    fn test_migration_steps() {
        let steps: Vec<_> = SchemaVersion::steps(SchemaVersion::V0).collect();
        assert_eq!(
            steps,
            [
                SchemaVersion::V1,
                SchemaVersion::V2,
                SchemaVersion::V3,
                SchemaVersion::V4,
                SchemaVersion::V5,
                SchemaVersion::V6,
            ]
        )
    }
    #[derive(Debug, Clone)]
    struct Thread(presage::store::Thread);

    #[derive(Debug, Clone)]
    struct Content(presage::libsignal_service::content::Content);

    impl Arbitrary for Content {
        fn arbitrary(g: &mut Gen) -> Self {
            let timestamp: u64 = Arbitrary::arbitrary(g);
            let contacts = [
                Uuid::from_u128(Arbitrary::arbitrary(g)),
                Uuid::from_u128(Arbitrary::arbitrary(g)),
                Uuid::from_u128(Arbitrary::arbitrary(g)),
            ];
            let metadata = Metadata {
                sender: ServiceAddress {
                    uuid: *g.choose(&contacts).unwrap(),
                    identity: ServiceIdType::AccountIdentity,
                },
                destination: ServiceAddress {
                    uuid: *g.choose(&contacts).unwrap(),
                    identity: ServiceIdType::AccountIdentity,
                },
                sender_device: Arbitrary::arbitrary(g),
                server_guid: None,
                timestamp,
                needs_receipt: Arbitrary::arbitrary(g),
                unidentified_sender: Arbitrary::arbitrary(g),
            };
            let content_body = ContentBody::DataMessage(DataMessage {
                body: Arbitrary::arbitrary(g),
                timestamp: Some(timestamp),
                ..Default::default()
            });
            Self(presage::libsignal_service::content::Content::from_body(
                content_body,
                metadata,
            ))
        }
    }

    impl Arbitrary for Thread {
        fn arbitrary(g: &mut Gen) -> Self {
            Self(presage::store::Thread::Contact(Uuid::from_u128(
                Arbitrary::arbitrary(g),
            )))
        }
    }

    fn content_with_timestamp(
        content: &Content,
        ts: u64,
    ) -> presage::libsignal_service::content::Content {
        presage::libsignal_service::content::Content {
            metadata: Metadata {
                timestamp: ts,
                ..content.0.metadata.clone()
            },
            body: content.0.body.clone(),
        }
    }

    #[quickcheck]
    fn compare_pre_keys(mut pre_key_id: u32, mut next_pre_key_id: u32) {
        if pre_key_id > next_pre_key_id {
            std::mem::swap(&mut pre_key_id, &mut next_pre_key_id);
        }
        assert!(PreKeyId::from(pre_key_id).sled_key() <= PreKeyId::from(next_pre_key_id).sled_key())
    }

    #[quickcheck_async::tokio]
    async fn test_store_messages(thread: Thread, content: Content) -> anyhow::Result<()> {
        let db = SledStore::temporary()?;
        let thread = thread.0;
        db.save_message(&thread, content_with_timestamp(&content, 1678295210))
            .await?;
        db.save_message(&thread, content_with_timestamp(&content, 1678295220))
            .await?;
        db.save_message(&thread, content_with_timestamp(&content, 1678295230))
            .await?;
        db.save_message(&thread, content_with_timestamp(&content, 1678295240))
            .await?;
        db.save_message(&thread, content_with_timestamp(&content, 1678280000))
            .await?;

        assert_eq!(db.messages(&thread, ..).await.unwrap().count(), 5);
        assert_eq!(db.messages(&thread, 0..).await.unwrap().count(), 5);
        assert_eq!(db.messages(&thread, 1678280000..).await.unwrap().count(), 5);

        assert_eq!(db.messages(&thread, 0..1678280000).await?.count(), 0);
        assert_eq!(db.messages(&thread, 0..1678295210).await?.count(), 1);
        assert_eq!(
            db.messages(&thread, 1678295210..1678295240).await?.count(),
            3
        );
        assert_eq!(
            db.messages(&thread, 1678295210..=1678295240).await?.count(),
            4
        );

        assert_eq!(
            db.messages(&thread, 0..=1678295240)
                .await?
                .next()
                .unwrap()?
                .metadata
                .timestamp,
            1678280000
        );
        assert_eq!(
            db.messages(&thread, 0..=1678295240)
                .await?
                .next_back()
                .unwrap()?
                .metadata
                .timestamp,
            1678295240
        );

        Ok(())
    }
}
