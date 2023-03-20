use std::{
    ops::{Bound, Range, RangeBounds, RangeFull},
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use async_trait::async_trait;
use libsignal_service::{
    groups_v2::{decrypt_group, Group},
    models::Contact,
    prelude::{
        protocol::{
            Context, Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore, PreKeyId,
            PreKeyRecord, PreKeyStore, ProtocolAddress, SenderKeyRecord, SenderKeyStore,
            SessionRecord, SessionStore, SessionStoreExt, SignalProtocolError, SignedPreKeyId,
            SignedPreKeyRecord, SignedPreKeyStore,
        },
        Content, ProfileKey, Uuid,
    },
    proto,
    push_service::DEFAULT_DEVICE_ID,
    Profile, ServiceAddress,
};
use log::{debug, error, trace, warn};
use matrix_sdk_store_encryption::StoreCipher;
use prost::Message;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sled::{Batch, IVec};

use super::{ContactsStore, GroupsStore, MessageStore, ProfilesStore, StateStore};
use crate::{
    manager::Registered, proto::ContentProto, store::Thread, Error, GroupMasterKeyBytes, Store,
};

const SLED_TREE_CONTACTS: &str = "contacts";
const SLED_TREE_GROUPS: &str = "groups";
const SLED_TREE_IDENTITIES: &str = "identities";
const SLED_TREE_PRE_KEYS: &str = "pre_keys";
const SLED_TREE_SENDER_KEYS: &str = "sender_keys";
const SLED_TREE_SESSIONS: &str = "sessions";
const SLED_TREE_SIGNED_PRE_KEYS: &str = "signed_pre_keys";
const SLED_TREE_STATE: &str = "state";
const SLED_TREE_THREADS_PREFIX: &str = "threads";
const SLED_TREE_PROFILES: &str = "profiles";

const SLED_KEY_NEXT_SIGNED_PRE_KEY_ID: &str = "next_signed_pre_key_id";
const SLED_KEY_PRE_KEYS_OFFSET_ID: &str = "pre_keys_offset_id";
const SLED_KEY_REGISTRATION: &str = "registration";
const SLED_KEY_SCHEMA_VERSION: &str = "schema_version";
const SLED_KEY_STORE_CIPHER: &str = "store_cipher";

#[derive(Clone)]
pub struct SledStore {
    db: Arc<sled::Db>,
    cipher: Option<Arc<StoreCipher>>,
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
    /// the current version
    V2 = 2,
}

impl SchemaVersion {
    fn current() -> SchemaVersion {
        Self::V2
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
            _ => unreachable!("oops, this not supposed to happen!"),
        })
    }
}

impl SledStore {
    fn new(db_path: impl AsRef<Path>, passphrase: Option<impl AsRef<str>>) -> Result<Self, Error> {
        let database = sled::open(db_path)?;
        let cipher = passphrase
            .map(|p| Self::get_or_create_store_cipher(&database, p.as_ref()))
            .transpose()?;

        Ok(SledStore {
            db: Arc::new(database),
            cipher: cipher.map(Arc::new),
        })
    }

    pub fn open(
        db_path: impl AsRef<Path>,
        migration_conflict_strategy: MigrationConflictStrategy,
    ) -> Result<Self, Error> {
        Self::open_with_passphrase(db_path, None::<&str>, migration_conflict_strategy)
    }

    pub fn open_with_passphrase(
        db_path: impl AsRef<Path>,
        passphrase: Option<impl AsRef<str>>,
        migration_conflict_strategy: MigrationConflictStrategy,
    ) -> Result<Self, Error> {
        let passphrase = passphrase.as_ref();

        migrate(&db_path, passphrase, migration_conflict_strategy)?;
        Self::new(db_path, passphrase)
    }

    fn get_or_create_store_cipher(
        database: &sled::Db,
        passphrase: &str,
    ) -> Result<StoreCipher, Error> {
        let cipher = if let Some(key) = database.get(SLED_KEY_STORE_CIPHER)? {
            StoreCipher::import(passphrase, &key)?
        } else {
            let cipher = StoreCipher::new()?;
            #[cfg(not(test))]
            let export = cipher.export(passphrase);
            #[cfg(test)]
            let export = cipher._insecure_export_fast_for_testing(passphrase);
            database.insert(SLED_KEY_STORE_CIPHER, export?)?;
            cipher
        };

        Ok(cipher)
    }

    #[cfg(test)]
    fn temporary() -> Result<Self, Error> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Self {
            db: Arc::new(db),
            cipher: None,
        })
    }

    fn schema_version(&self) -> SchemaVersion {
        self.get(SLED_TREE_STATE, SLED_KEY_SCHEMA_VERSION)
            .ok()
            .flatten()
            .unwrap_or_default()
    }

    fn tree<T>(&self, tree: T) -> Result<sled::Tree, Error>
    where
        T: AsRef<[u8]>,
    {
        self.db.open_tree(tree).map_err(Error::DbError)
    }

    pub fn get<K, V>(&self, tree: &str, key: K) -> Result<Option<V>, Error>
    where
        K: AsRef<[u8]>,
        V: DeserializeOwned,
    {
        self.tree(tree)?
            .get(key)?
            .map(|p| {
                self.cipher.as_ref().map_or_else(
                    || serde_json::from_slice(&p).map_err(Error::from),
                    |c| c.decrypt_value(&p).map_err(Error::from),
                )
            })
            .transpose()
            .map_err(Error::from)
    }

    fn insert<K, V>(&self, tree: &str, key: K, value: V) -> Result<bool, Error>
    where
        K: AsRef<[u8]>,
        V: Serialize,
    {
        let value = self.cipher.as_ref().map_or_else(
            || serde_json::to_vec(&value).map_err(Error::from),
            |c| c.encrypt_value(&value).map_err(Error::from),
        )?;
        let last_value = self.tree(tree)?.insert(key, value)?;
        self.db.flush()?;
        Ok(last_value.is_some())
    }

    fn remove<K>(&self, tree: &str, key: K) -> Result<bool, Error>
    where
        K: AsRef<[u8]>,
    {
        Ok(self.tree(tree)?.remove(key)?.is_some())
    }

    /// build a hashed messages thread key
    fn messages_thread_tree_name(&self, t: &Thread) -> String {
        let key = match t {
            Thread::Contact(uuid) => format!("{SLED_TREE_THREADS_PREFIX}:contact:{uuid}"),
            Thread::Group(group_id) => format!(
                "{SLED_TREE_THREADS_PREFIX}:group:{}",
                base64::encode(group_id)
            ),
        };
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        format!("{SLED_TREE_THREADS_PREFIX}:{:x}", hasher.finalize())
    }

    fn profile_key(&self, uuid: Uuid, key: ProfileKey) -> String {
        let key = uuid
            .into_bytes()
            .into_iter()
            .chain(key.get_bytes().into_iter());

        let mut hasher = Sha256::new();
        hasher.update(key.collect::<Vec<_>>());
        format!("{:x}", hasher.finalize())
    }
}

fn migrate(
    db_path: impl AsRef<Path>,
    passphrase: Option<impl AsRef<str>>,
    migration_conflict_strategy: MigrationConflictStrategy,
) -> Result<(), Error> {
    let db_path = db_path.as_ref();
    let passphrase = passphrase.as_ref();

    let run_migrations = move || {
        let mut store = SledStore::new(db_path, passphrase)?;
        let schema_version = store.schema_version();
        for step in schema_version.steps() {
            match &step {
                SchemaVersion::V1 => {
                    debug!("migrating from v0, nothing to do")
                }
                SchemaVersion::V2 => {
                    debug!("migrating from schema v1 to v2: encrypting state if cipher is enabled");

                    // load registration data the old school way
                    if let Some(data) = store.db.get(SLED_KEY_REGISTRATION)? {
                        let state = serde_json::from_slice(&data).map_err(Error::from)?;

                        // save it the new school way
                        store.save_state(&state)?;

                        // remove old data
                        store.db.remove(SLED_KEY_REGISTRATION)?;
                    }
                }
                _ => return Err(Error::MigrationConflict),
            }

            store.insert(SLED_TREE_STATE, SLED_KEY_SCHEMA_VERSION, step)?;
            store.db.flush()?;
        }

        Ok(())
    };

    if let Err(error) = run_migrations() {
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
            MigrationConflictStrategy::Raise => return Err(error),
        }
    }

    Ok(())
}

impl StateStore<Registered> for SledStore {
    fn load_state(&self) -> Result<Registered, Error> {
        self.get(SLED_TREE_STATE, SLED_KEY_REGISTRATION)?
            .ok_or(Error::NotYetRegisteredError)
    }

    fn save_state(&mut self, state: &Registered) -> Result<(), Error> {
        self.insert(SLED_TREE_STATE, SLED_KEY_REGISTRATION, state)?;
        Ok(())
    }
}

impl Store for SledStore {
    fn clear_registration(&mut self) -> Result<(), Error> {
        self.db.remove(SLED_KEY_REGISTRATION)?;

        self.db.drop_tree(SLED_TREE_IDENTITIES)?;
        self.db.drop_tree(SLED_TREE_PRE_KEYS)?;
        self.db.drop_tree(SLED_TREE_SENDER_KEYS)?;
        self.db.drop_tree(SLED_TREE_SESSIONS)?;
        self.db.drop_tree(SLED_TREE_SIGNED_PRE_KEYS)?;
        self.db.drop_tree(SLED_TREE_STATE)?;

        self.db.flush()?;

        Ok(())
    }

    fn clear(&mut self) -> Result<(), Error> {
        self.clear_registration()?;

        self.db.drop_tree(SLED_TREE_CONTACTS)?;
        self.db.drop_tree(SLED_TREE_GROUPS)?;

        for tree in self
            .db
            .tree_names()
            .into_iter()
            .filter(|n| n.starts_with(SLED_TREE_THREADS_PREFIX.as_bytes()))
        {
            self.db.drop_tree(tree)?;
        }

        self.db.flush()?;

        Ok(())
    }

    fn pre_keys_offset_id(&self) -> Result<u32, Error> {
        Ok(self
            .get(SLED_TREE_STATE, SLED_KEY_PRE_KEYS_OFFSET_ID)?
            .unwrap_or(0))
    }

    fn set_pre_keys_offset_id(&mut self, id: u32) -> Result<(), Error> {
        self.insert(SLED_TREE_STATE, SLED_KEY_PRE_KEYS_OFFSET_ID, id)?;
        Ok(())
    }

    fn next_signed_pre_key_id(&self) -> Result<u32, Error> {
        Ok(self
            .get(SLED_TREE_STATE, SLED_KEY_NEXT_SIGNED_PRE_KEY_ID)?
            .unwrap_or(0))
    }

    fn set_next_signed_pre_key_id(&mut self, id: u32) -> Result<(), Error> {
        self.insert(SLED_TREE_STATE, SLED_KEY_NEXT_SIGNED_PRE_KEY_ID, id)?;
        Ok(())
    }
}

impl ContactsStore for SledStore {
    type ContactsIter = SledContactsIter;

    fn clear_contacts(&mut self) -> Result<(), Error> {
        self.db.drop_tree(SLED_TREE_CONTACTS)?;
        Ok(())
    }

    fn save_contacts(&mut self, contacts: impl Iterator<Item = Contact>) -> Result<(), Error> {
        for contact in contacts {
            self.insert(SLED_TREE_CONTACTS, contact.uuid, contact)?;
        }
        debug!("saved contacts");
        Ok(())
    }

    fn contacts(&self) -> Result<Self::ContactsIter, Error> {
        Ok(SledContactsIter {
            iter: self.tree(SLED_TREE_CONTACTS)?.iter(),
            cipher: self.cipher.clone(),
        })
    }

    fn contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Error> {
        self.get(SLED_TREE_CONTACTS, id)
    }
}

impl GroupsStore for SledStore {
    type GroupsIter = SledGroupsIter;

    fn clear_groups(&mut self) -> Result<(), Error> {
        self.db.drop_tree(SLED_TREE_GROUPS)?;
        Ok(())
    }

    fn groups(&self) -> Result<Self::GroupsIter, Error> {
        Ok(SledGroupsIter {
            iter: self.tree(SLED_TREE_GROUPS)?.iter(),
            cipher: self.cipher.clone(),
        })
    }

    fn group(&self, master_key: &[u8]) -> Result<Option<Group>, Error> {
        let key: GroupMasterKeyBytes = master_key.try_into()?;
        let val: Option<Vec<u8>> = self.get(SLED_TREE_GROUPS, key)?;
        match val {
            Some(ref v) => {
                let encrypted_group = proto::Group::decode(v.as_slice())?;
                let group = decrypt_group(&key, encrypted_group)?;
                Ok(Some(group))
            }
            None => Ok(None),
        }
    }

    fn save_group(&self, master_key: &[u8], group: proto::Group) -> Result<(), Error> {
        let key: GroupMasterKeyBytes = master_key.try_into()?;
        self.insert(SLED_TREE_GROUPS, key, group.encode_to_vec())?;
        Ok(())
    }
}

pub struct SledContactsIter {
    cipher: Option<Arc<StoreCipher>>,
    iter: sled::Iter,
}

impl Iterator for SledContactsIter {
    type Item = Result<Contact, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()?
            .map_err(Error::from)
            .and_then(|(_key, value)| {
                self.cipher.as_ref().map_or_else(
                    || serde_json::from_slice(&value).map_err(Error::from),
                    |c| c.decrypt_value(&value).map_err(Error::from),
                )
            })
            .into()
    }
}

pub struct SledGroupsIter {
    cipher: Option<Arc<StoreCipher>>,
    iter: sled::Iter,
}

impl Iterator for SledGroupsIter {
    type Item = Result<(GroupMasterKeyBytes, Group), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter
            .next()?
            .map_err(Error::from)
            .and_then(|(master_key_bytes, value)| {
                let decrypted_data: Vec<u8> = self.cipher.as_ref().map_or_else(
                    || serde_json::from_slice(&value).map_err(Error::from),
                    |c| c.decrypt_value(&value).map_err(Error::from),
                )?;
                Ok((master_key_bytes, decrypted_data))
            })
            .and_then(|(master_key_bytes, encrypted_group_data)| {
                let encrypted_group = proto::Group::decode(encrypted_group_data.as_slice())?;
                let master_key: GroupMasterKeyBytes = master_key_bytes[..]
                    .try_into()
                    .expect("wrong group master key length");
                let decrypted_group =
                    decrypt_group(&master_key, encrypted_group).map_err(Error::from)?;
                Ok((master_key, decrypted_group))
            })
            .into()
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SledStore {
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
        _ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        let buf: Vec<u8> = self
            .get(SLED_TREE_PRE_KEYS, prekey_id.to_string())
            .ok()
            .flatten()
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;

        PreKeyRecord::deserialize(&buf)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.insert(
            SLED_TREE_PRE_KEYS,
            prekey_id.to_string(),
            record.serialize()?,
        )
        .expect("failed to store pre-key");
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.remove(SLED_TREE_PRE_KEYS, prekey_id.to_string())
            .expect("failed to remove pre-key");
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SledStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let buf: Vec<u8> = self
            .get(SLED_TREE_SIGNED_PRE_KEYS, signed_prekey_id.to_string())
            .ok()
            .flatten()
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(&buf)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.insert(
            SLED_TREE_SIGNED_PRE_KEYS,
            signed_prekey_id.to_string(),
            record.serialize()?,
        )
        .map_err(|e| {
            log::error!("sled error: {}", e);
            SignalProtocolError::InvalidState("save_signed_pre_key", "sled error".into())
        })?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for SledStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let session = self
            .get(SLED_TREE_SESSIONS, address.to_string())
            .map_err(Error::into_signal_error)?;
        trace!("loading session {} / exists={}", address, session.is_some());
        session
            .map(|b: Vec<u8>| SessionRecord::deserialize(&b))
            .transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        trace!("storing session {}", address);
        self.insert(SLED_TREE_SESSIONS, address.to_string(), record.serialize()?)
            .map_err(Error::into_signal_error)?;
        Ok(())
    }
}

#[async_trait]
impl SessionStoreExt for SledStore {
    async fn get_sub_device_sessions(
        &self,
        address: &ServiceAddress,
    ) -> Result<Vec<u32>, SignalProtocolError> {
        let session_prefix = format!("{}.", address.uuid);
        trace!("get_sub_device_sessions {}", session_prefix);
        let session_ids: Vec<u32> = self
            .tree(SLED_TREE_SESSIONS)
            .map_err(Error::into_signal_error)?
            .scan_prefix(&session_prefix)
            .filter_map(|r| {
                let (key, _) = r.ok()?;
                let key_str = String::from_utf8_lossy(&key);
                let device_id = key_str.strip_prefix(&session_prefix)?;
                device_id.parse().ok()
            })
            .filter(|d| *d != DEFAULT_DEVICE_ID)
            .collect();
        Ok(session_ids)
    }

    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), SignalProtocolError> {
        trace!("deleting session {}", address);
        self.tree(SLED_TREE_SESSIONS)
            .map_err(Error::into_signal_error)?
            .remove(address.to_string())
            .map_err(|_e| SignalProtocolError::SessionNotFound(address.clone()))?;
        Ok(())
    }

    async fn delete_all_sessions(
        &self,
        address: &ServiceAddress,
    ) -> Result<usize, SignalProtocolError> {
        let tree = self
            .tree(SLED_TREE_SESSIONS)
            .map_err(Error::into_signal_error)?;

        let mut batch = Batch::default();

        self.tree(SLED_TREE_SESSIONS)
            .map_err(Error::into_signal_error)?
            .scan_prefix(address.uuid.to_string())
            .filter_map(|r| {
                let (key, _) = r.ok()?;
                Some(key)
            })
            .for_each(|k| batch.remove(k));

        self.db
            .apply_batch(batch)
            .map_err(Error::DbError)
            .map_err(Error::into_signal_error)?;

        let len = tree.len();
        tree.clear().map_err(|_e| {
            SignalProtocolError::InvalidSessionStructure("failed to delete all sessions")
        })?;
        Ok(len)
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for SledStore {
    async fn get_identity_key_pair(
        &self,
        _ctx: Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        trace!("getting identity_key_pair");
        let state = self.load_state().map_err(|e| {
            SignalProtocolError::InvalidState("failed to load presage state", e.to_string())
        })?;
        Ok(IdentityKeyPair::new(
            IdentityKey::new(state.public_key),
            state.private_key,
        ))
    }

    async fn get_local_registration_id(&self, _ctx: Context) -> Result<u32, SignalProtocolError> {
        let state = self.load_state().map_err(|e| {
            SignalProtocolError::InvalidState("failed to load presage state", e.to_string())
        })?;
        Ok(state.registration_id)
    }

    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        trace!("saving identity");
        self.insert(
            SLED_TREE_IDENTITIES,
            address.to_string(),
            identity_key.serialize(),
        )
        .map_err(|e| {
            error!("error saving identity for {:?}: {}", address, e);
            SignalProtocolError::InvalidState("save_identity", "failed to save identity".into())
        })?;

        Ok(false)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        right_identity_key: &IdentityKey,
        _direction: Direction,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        match self
            .get(SLED_TREE_IDENTITIES, address.to_string())
            .map_err(Error::into_signal_error)?
            .map(|b: Vec<u8>| IdentityKey::decode(&b))
            .transpose()?
        {
            None => {
                // when we encounter a new identity, we trust it by default
                warn!("trusting new identity {:?}", address);
                Ok(true)
            }
            Some(left_identity_key) => Ok(left_identity_key == *right_identity_key),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        self.get(SLED_TREE_IDENTITIES, address.to_string())
            .map_err(Error::into_signal_error)?
            .map(|b: Vec<u8>| IdentityKey::decode(&b))
            .transpose()
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for SledStore {
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let key = format!(
            "{}.{}/{}",
            sender.name(),
            sender.device_id(),
            distribution_id
        );
        self.insert(SLED_TREE_SENDER_KEYS, key, record.serialize()?)
            .map_err(Error::into_signal_error)?;
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let key = format!(
            "{}.{}/{}",
            sender.name(),
            sender.device_id(),
            distribution_id
        );
        self.get(SLED_TREE_SENDER_KEYS, key)
            .map_err(Error::into_signal_error)?
            .map(|b: Vec<u8>| SenderKeyRecord::deserialize(&b))
            .transpose()
    }
}

impl MessageStore for SledStore {
    type MessagesIter = SledMessagesIter;

    fn clear_messages(&mut self) -> Result<(), Error> {
        for name in self.db.tree_names() {
            if name
                .as_ref()
                .starts_with(SLED_TREE_THREADS_PREFIX.as_bytes())
            {
                self.db.drop_tree(&name)?;
            }
        }
        self.db.flush()?;
        Ok(())
    }

    fn save_message(&mut self, thread: &Thread, message: Content) -> Result<(), Error> {
        log::trace!(
            "storing a message with thread: {thread}, timestamp: {}",
            message.metadata.timestamp,
        );

        let tree = self.messages_thread_tree_name(thread);
        let key = message.metadata.timestamp.to_be_bytes();

        let proto: ContentProto = message.into();
        let value = proto.encode_to_vec();

        self.insert(&tree, key, value)?;

        Ok(())
    }

    fn delete_message(&mut self, thread: &Thread, timestamp: u64) -> Result<bool, Error> {
        let tree = self.messages_thread_tree_name(thread);
        self.remove(&tree, timestamp.to_be_bytes())
    }

    fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<libsignal_service::prelude::Content>, Error> {
        // Big-Endian needed, otherwise wrong ordering in sled.
        let val: Option<Vec<u8>> = self.get(
            &self.messages_thread_tree_name(thread),
            timestamp.to_be_bytes(),
        )?;
        match val {
            Some(ref v) => {
                let proto = ContentProto::decode(v.as_slice())?;
                let content = proto.try_into()?;
                Ok(Some(content))
            }
            None => Ok(None),
        }
    }

    fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Error> {
        let tree_thread = self.tree(self.messages_thread_tree_name(thread))?;
        debug!("{} messages in this tree", tree_thread.len());

        let iter = match (range.start_bound(), range.end_bound()) {
            (Bound::Included(start), Bound::Unbounded) => tree_thread.range(start.to_be_bytes()..),
            (Bound::Included(start), Bound::Excluded(end)) => {
                tree_thread.range(start.to_be_bytes()..end.to_be_bytes())
            }
            (Bound::Included(start), Bound::Included(end)) => {
                tree_thread.range(start.to_be_bytes()..=end.to_be_bytes())
            }
            (Bound::Unbounded, Bound::Included(end)) => tree_thread.range(..=end.to_be_bytes()),
            (Bound::Unbounded, Bound::Excluded(end)) => tree_thread.range(..end.to_be_bytes()),
            (Bound::Unbounded, Bound::Unbounded) => tree_thread.range::<[u8; 8], RangeFull>(..),
            (Bound::Excluded(_), _) => unreachable!("range that excludes the initial value"),
        };

        Ok(SledMessagesIter {
            cipher: self.cipher.clone(),
            iter,
        })
    }
}

pub struct SledMessagesIter {
    cipher: Option<Arc<StoreCipher>>,
    iter: sled::Iter,
}

impl SledMessagesIter {
    fn decode(&self, elem: Result<(IVec, IVec), sled::Error>) -> Option<Result<Content, Error>> {
        elem.map_err(Error::from)
            .and_then(|(_, value)| {
                self.cipher.as_ref().map_or_else(
                    || serde_json::from_slice(&value).map_err(Error::from),
                    |c| c.decrypt_value(&value).map_err(Error::from),
                )
            })
            .and_then(|data: Vec<u8>| ContentProto::decode(&data[..]).map_err(Error::from))
            .map_or_else(|e| Some(Err(e)), |p| Some(p.try_into()))
    }
}

impl Iterator for SledMessagesIter {
    type Item = Result<Content, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let elem = self.iter.next()?;
        self.decode(elem)
    }
}

impl DoubleEndedIterator for SledMessagesIter {
    fn next_back(&mut self) -> Option<Self::Item> {
        let elem = self.iter.next_back()?;
        self.decode(elem)
    }
}

impl ProfilesStore for SledStore {
    fn save_profile(&mut self, uuid: Uuid, key: ProfileKey, profile: Profile) -> Result<(), Error> {
        let key = self.profile_key(uuid, key);
        self.insert(SLED_TREE_PROFILES, &key, profile)?;
        Ok(())
    }

    fn profile(&self, uuid: Uuid, key: ProfileKey) -> Result<Option<Profile>, Error> {
        let key = self.profile_key(uuid, key);
        self.get(SLED_TREE_PROFILES, key)
    }
}

#[cfg(test)]
mod tests {
    use core::fmt;

    use libsignal_service::{
        content::{ContentBody, Metadata},
        prelude::{
            protocol::{
                self, Direction, IdentityKeyStore, PreKeyRecord, PreKeyStore, SessionRecord,
                SessionStore, SignedPreKeyRecord, SignedPreKeyStore,
            },
            Uuid,
        },
        proto::DataMessage,
        ServiceAddress,
    };
    use quickcheck::{Arbitrary, Gen};

    use crate::{MessageStore, Thread};

    use super::SledStore;

    #[derive(Debug, Clone)]
    struct ProtocolAddress(protocol::ProtocolAddress);

    #[derive(Clone)]
    struct KeyPair(protocol::KeyPair);

    #[derive(Debug, Clone)]
    struct Content(libsignal_service::prelude::Content);

    impl fmt::Debug for KeyPair {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "{}", base64::encode(self.0.public_key.serialize()))
        }
    }

    impl Arbitrary for ProtocolAddress {
        fn arbitrary(g: &mut Gen) -> Self {
            let name: String = Arbitrary::arbitrary(g);
            let device_id: u32 = Arbitrary::arbitrary(g);
            ProtocolAddress(protocol::ProtocolAddress::new(name, device_id.into()))
        }
    }

    impl Arbitrary for KeyPair {
        fn arbitrary(_g: &mut Gen) -> Self {
            // Gen is not rand::CryptoRng here, see https://github.com/BurntSushi/quickcheck/issues/241
            KeyPair(protocol::KeyPair::generate(&mut rand::thread_rng()))
        }
    }

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
                },
                sender_device: Arbitrary::arbitrary(g),
                timestamp,
                needs_receipt: Arbitrary::arbitrary(g),
                unidentified_sender: Arbitrary::arbitrary(g),
            };
            let content_body = ContentBody::DataMessage(DataMessage {
                body: Arbitrary::arbitrary(g),
                timestamp: Some(timestamp),
                ..Default::default()
            });
            Self(libsignal_service::prelude::Content::from_body(
                content_body,
                metadata,
            ))
        }
    }

    impl Arbitrary for Thread {
        fn arbitrary(g: &mut Gen) -> Self {
            Self::Contact(Uuid::from_u128(Arbitrary::arbitrary(g)))
        }
    }

    #[quickcheck_async::tokio]
    async fn test_save_get_trust_identity(addr: ProtocolAddress, key_pair: KeyPair) -> bool {
        let mut db = SledStore::temporary().unwrap();
        let identity_key = protocol::IdentityKey::new(key_pair.0.public_key);
        db.save_identity(&addr.0, &identity_key, None)
            .await
            .unwrap();
        let id = db.get_identity(&addr.0, None).await.unwrap().unwrap();
        if id != identity_key {
            return false;
        }
        db.is_trusted_identity(&addr.0, &id, Direction::Receiving, None)
            .await
            .unwrap()
    }

    #[quickcheck_async::tokio]
    async fn test_store_load_session(addr: ProtocolAddress) -> bool {
        let session = SessionRecord::new_fresh();

        let mut db = SledStore::temporary().unwrap();
        db.store_session(&addr.0, &session, None).await.unwrap();
        if db.load_session(&addr.0, None).await.unwrap().is_none() {
            return false;
        }
        let loaded_session = db.load_session(&addr.0, None).await.unwrap().unwrap();
        session.serialize().unwrap() == loaded_session.serialize().unwrap()
    }

    #[quickcheck_async::tokio]
    async fn test_prekey_store(id: u32, key_pair: KeyPair) -> bool {
        let id = id.into();
        let mut db = SledStore::temporary().unwrap();
        let pre_key_record = PreKeyRecord::new(id, &key_pair.0);
        db.save_pre_key(id, &pre_key_record, None).await.unwrap();
        if db.get_pre_key(id, None).await.unwrap().serialize().unwrap()
            != pre_key_record.serialize().unwrap()
        {
            return false;
        }

        db.remove_pre_key(id, None).await.unwrap();
        db.get_pre_key(id, None).await.is_err()
    }

    #[quickcheck_async::tokio]
    async fn test_signed_prekey_store(
        id: u32,
        timestamp: u64,
        key_pair: KeyPair,
        signature: Vec<u8>,
    ) -> bool {
        let mut db = SledStore::temporary().unwrap();
        let id = id.into();
        let signed_pre_key_record = SignedPreKeyRecord::new(id, timestamp, &key_pair.0, &signature);
        db.save_signed_pre_key(id, &signed_pre_key_record, None)
            .await
            .unwrap();

        db.get_signed_pre_key(id, None)
            .await
            .unwrap()
            .serialize()
            .unwrap()
            == signed_pre_key_record.serialize().unwrap()
    }

    fn content_with_timestamp(content: &Content, ts: u64) -> libsignal_service::prelude::Content {
        libsignal_service::prelude::Content {
            metadata: Metadata {
                timestamp: ts,
                ..content.0.metadata.clone()
            },
            body: content.0.body.clone(),
        }
    }

    #[quickcheck_async::tokio]
    async fn test_store_messages(thread: Thread, content: Content) -> anyhow::Result<()> {
        let mut db = SledStore::temporary()?;
        db.save_message(&thread, content_with_timestamp(&content, 1678295210))?;
        db.save_message(&thread, content_with_timestamp(&content, 1678295220))?;
        db.save_message(&thread, content_with_timestamp(&content, 1678295230))?;
        db.save_message(&thread, content_with_timestamp(&content, 1678295240))?;
        db.save_message(&thread, content_with_timestamp(&content, 1678280000))?;

        assert_eq!(db.messages(&thread, ..).unwrap().count(), 5);
        assert_eq!(db.messages(&thread, 0..).unwrap().count(), 5);
        assert_eq!(db.messages(&thread, 1678280000..).unwrap().count(), 5);

        assert_eq!(db.messages(&thread, 0..1678280000)?.count(), 0);
        assert_eq!(db.messages(&thread, 0..1678295210)?.count(), 1);
        assert_eq!(db.messages(&thread, 1678295210..1678295240)?.count(), 3);
        assert_eq!(db.messages(&thread, 1678295210..=1678295240)?.count(), 4);

        assert_eq!(
            db.messages(&thread, 0..=1678295240)?
                .next()
                .unwrap()?
                .metadata
                .timestamp,
            1678280000
        );
        assert_eq!(
            db.messages(&thread, 0..=1678295240)?
                .next_back()
                .unwrap()?
                .metadata
                .timestamp,
            1678295240
        );

        Ok(())
    }
}
