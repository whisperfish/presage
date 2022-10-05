use std::{path::PathBuf, sync::Arc};

use async_trait::async_trait;
use libsignal_service::{
    models::Contact,
    prelude::{
        protocol::{
            Context, Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore, PreKeyId,
            PreKeyRecord, PreKeyStore, ProtocolAddress, SessionRecord, SessionStore,
            SessionStoreExt, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
            SignedPreKeyStore,
        },
        Content, Uuid,
    },
    push_service::DEFAULT_DEVICE_ID,
};
use log::{debug, trace, warn};
use matrix_sdk_store_encryption::StoreCipher;
use prost::Message;
use serde::{de::DeserializeOwned, Serialize};
use sled::Batch;

use super::{ContactsStore, MessageStore, StateStore};
use crate::{manager::Registered, proto::ContentProto, store::Thread, Error, Store};

const SLED_KEY_CONTACTS: &str = "contacts";
const SLED_KEY_PRE_KEYS_OFFSET_ID: &str = "pre_keys_offset_id";
const SLED_KEY_NEXT_SIGNED_PRE_KEY_ID: &str = "next_signed_pre_key_id";
const SLED_KEY_REGISTRATION: &str = "registration";
const SLED_KEY_STORE_CIPHER: &str = "store_cipher";

const SLED_TREE_DEFAULT: &str = "state";
const SLED_TREE_PRE_KEYS: &str = "pre_keys";
const SLED_TREE_SIGNED_PRE_KEYS: &str = "signed_pre_keys";
const SLED_TREE_IDENTITIES: &str = "identities";
const SLED_TREE_SESSIONS: &str = "sessions";
const SLED_TREE_THREAD_PREFIX: &str = "threads";

#[derive(Clone)]
pub struct SledStore {
    db: Arc<sled::Db>,
    cipher: Option<Arc<StoreCipher>>,
}

impl SledStore {
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, Error> {
        Self::open_with_passphrase(path, None)
    }

    pub fn open_with_passphrase(
        path: impl Into<PathBuf>,
        passphrase: Option<&str>,
    ) -> Result<Self, Error> {
        let database = sled::open(path.into())?;
        let cipher = passphrase
            .map(|p| Self::get_or_create_store_cipher(&database, p))
            .transpose()?;
        Ok(SledStore {
            db: Arc::new(database),
            cipher: cipher.map(Arc::new),
        })
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

    fn tree(&self, tree: &str) -> Result<sled::Tree, Error> {
        self.db.open_tree(tree).map_err(Error::DbError)
    }

    pub fn get<K, V>(&self, tree: &str, key: K) -> Result<Option<V>, Error>
    where
        K: AsRef<[u8]>,
        V: DeserializeOwned,
    {
        self.tree(tree)?
            .get(key.as_ref())?
            .map(|p| {
                self.cipher.as_ref().map_or_else(
                    || serde_json::from_slice(&p).map_err(Error::from),
                    |c| c.decrypt_value(&p).map_err(Error::from),
                )
            })
            .transpose()
            .map_err(Error::from)
    }

    fn insert<K, V>(&self, tree: &str, key: K, value: V) -> Result<(), Error>
    where
        K: AsRef<str>,
        V: Serialize,
    {
        trace!("inserting {}", key.as_ref());
        let encrypted_value = self.cipher.as_ref().map_or_else(
            || serde_json::to_vec(&value).map_err(Error::from),
            |c| c.encrypt_value(&value).map_err(Error::from),
        )?;
        let _ = self.tree(tree)?.insert(key.as_ref(), encrypted_value)?;
        Ok(())
    }

    fn remove<S>(&self, tree: &str, key: S) -> Result<(), Error>
    where
        S: AsRef<str>,
    {
        trace!("removing {} from db", key.as_ref());
        self.tree(tree)?.remove(key.as_ref())?;
        Ok(())
    }
}

impl StateStore<Registered> for SledStore {
    fn load_state(&self) -> Result<Registered, Error> {
        let data = self
            .db
            .get(SLED_KEY_REGISTRATION)?
            .ok_or(Error::NotYetRegisteredError)?;
        serde_json::from_slice(&data).map_err(Error::from)
    }

    fn save_state(&mut self, state: &Registered) -> Result<(), Error> {
        self.db
            .insert(SLED_KEY_REGISTRATION, serde_json::to_vec(state)?)?;
        Ok(())
    }
}

impl Store for SledStore {
    fn clear(&mut self) -> Result<(), Error> {
        self.db.drop_tree(SLED_TREE_DEFAULT)?;
        self.db.drop_tree(SLED_TREE_IDENTITIES)?;
        self.db.drop_tree(SLED_TREE_PRE_KEYS)?;
        self.db.drop_tree(SLED_TREE_SESSIONS)?;
        self.db.drop_tree(SLED_TREE_SIGNED_PRE_KEYS)?;
        self.db.drop_tree(SLED_TREE_PRE_KEYS)?;

        Ok(())
    }

    fn pre_keys_offset_id(&self) -> Result<u32, Error> {
        Ok(self
            .get(SLED_TREE_DEFAULT, SLED_KEY_PRE_KEYS_OFFSET_ID)?
            .unwrap_or(0))
    }

    fn set_pre_keys_offset_id(&mut self, id: u32) -> Result<(), Error> {
        self.insert(SLED_TREE_DEFAULT, SLED_KEY_PRE_KEYS_OFFSET_ID, id)
    }

    fn next_signed_pre_key_id(&self) -> Result<u32, Error> {
        Ok(self
            .get(SLED_TREE_DEFAULT, SLED_KEY_NEXT_SIGNED_PRE_KEY_ID)?
            .unwrap_or(0))
    }

    fn set_next_signed_pre_key_id(&mut self, id: u32) -> Result<(), Error> {
        self.insert(SLED_TREE_DEFAULT, SLED_KEY_NEXT_SIGNED_PRE_KEY_ID, id)
    }
}

impl ContactsStore for SledStore {
    fn save_contacts(&mut self, contacts: impl Iterator<Item = Contact>) -> Result<(), Error> {
        let tree = self.db.open_tree(SLED_KEY_CONTACTS)?;
        for contact in contacts {
            if let Some(uuid) = contact.address.uuid {
                tree.insert(uuid.to_string(), serde_json::to_vec(&contact)?)?;
            } else {
                warn!("skipping contact {:?} without uuid", contact);
            }
        }
        debug!("saved contacts");
        Ok(())
    }

    fn contacts(&self) -> Result<Vec<Contact>, Error> {
        Ok(self
            .db
            .open_tree(SLED_KEY_CONTACTS)?
            .iter()
            .filter_map(Result::ok)
            .filter_map(|(_key, buf)| serde_json::from_slice(&buf).ok())
            .collect())
    }

    fn contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Error> {
        Ok(
            if let Some(buf) = self.db.open_tree(SLED_KEY_CONTACTS)?.get(id.to_string())? {
                let contact = serde_json::from_slice(&buf)?;
                Some(contact)
            } else {
                None
            },
        )
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
        })
    }
}

#[async_trait(?Send)]
impl SessionStore for SledStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        trace!("loading session {}", address);
        self.get(SLED_TREE_SESSIONS, address.to_string())
            .map_err(Error::into_signal_error)?
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
            .map_err(Error::into_signal_error)
    }
}

#[async_trait]
impl SessionStoreExt for SledStore {
    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, SignalProtocolError> {
        let session_prefix = format!("{name}.");
        log::info!("get_sub_device_sessions {}", session_prefix);
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

    async fn delete_all_sessions(&self, name: &str) -> Result<usize, SignalProtocolError> {
        let tree = self
            .tree(SLED_TREE_SESSIONS)
            .map_err(Error::into_signal_error)?;

        let mut batch = Batch::default();

        self.tree(SLED_TREE_SESSIONS)
            .map_err(Error::into_signal_error)?
            .scan_prefix(name)
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
            log::error!("error saving identity for {:?}: {}", address, e);
            SignalProtocolError::InvalidState("save_identity", "failed to save identity".into())
        })?;
        trace!("saved identity");
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

fn thread_key(t: &Thread) -> Vec<u8> {
    let mut bytes = SLED_TREE_THREAD_PREFIX.as_bytes().to_owned();
    bytes.append(&mut t.into());
    bytes
}

impl MessageStore for SledStore {
    type MessagesIter = SledMessagesIter;

    fn save_message(&mut self, thread: &Thread, message: Content) -> Result<(), Error> {
        log::trace!(
            "Storing a message with thread: {:?}, timestamp: {}",
            thread,
            message.metadata.timestamp,
        );

        let tree_thread = self.db.open_tree(thread_key(thread))?;

        let timestamp_bytes = message.metadata.timestamp.to_be_bytes();
        let proto: ContentProto = message.into();
        tree_thread.insert(timestamp_bytes, proto.encode_to_vec())?;
        Ok(())
    }

    fn delete_message(&mut self, thread: &Thread, timestamp: u64) -> Result<bool, Error> {
        Ok(self
            .db
            .open_tree(thread_key(thread))?
            .remove(timestamp.to_be_bytes())?
            .is_some())
    }

    fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<libsignal_service::prelude::Content>, Error> {
        let tree_thread = self.db.open_tree(thread_key(thread))?;
        // Big-Endian needed, otherwise wrong ordering in sled.
        let val = tree_thread.get(timestamp.to_be_bytes())?;
        if let Some(val) = val {
            let proto = ContentProto::decode(&val[..])?;
            let content = proto.try_into()?;
            Ok(Some(content))
        } else {
            Ok(None)
        }
    }

    fn messages(&self, thread: &Thread, from: Option<u64>) -> Result<Self::MessagesIter, Error> {
        let tree_thread = self.db.open_tree(thread_key(thread))?;
        let iter = if let Some(from) = from {
            tree_thread.range(..from.to_be_bytes())
        } else {
            tree_thread.range::<&[u8], std::ops::RangeFull>(..)
        };
        Ok(SledMessagesIter(iter.rev()))
    }
}

pub struct SledMessagesIter(std::iter::Rev<sled::Iter>);

impl Iterator for SledMessagesIter {
    // TODO: If error, throw away the rest. Maybe return Result<Content, Error>?
    type Item = Content;

    fn next(&mut self) -> Option<Self::Item> {
        let ivec = self.0.next()?.ok()?.1;
        let proto = ContentProto::decode(&*ivec).ok()?;
        proto.try_into().ok()
    }
}

#[cfg(test)]
mod tests {
    use core::fmt;

    use libsignal_service::prelude::protocol::{
        self, Direction, IdentityKeyStore, PreKeyRecord, PreKeyStore, SessionRecord, SessionStore,
        SignedPreKeyRecord, SignedPreKeyStore,
    };
    use quickcheck::{Arbitrary, Gen};

    use super::SledStore;

    #[derive(Debug, Clone)]
    struct ProtocolAddress(protocol::ProtocolAddress);

    #[derive(Clone)]
    struct KeyPair(protocol::KeyPair);

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
}
