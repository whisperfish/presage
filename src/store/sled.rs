use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

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
use prost::Message;
use sled::IVec;

use super::{ContactsStore, MessageStore, StateStore};
use crate::{manager::Registered, proto::ContentProto, store::Thread, Error, Store};

const SLED_KEY_REGISTRATION: &str = "registration";
const SLED_KEY_CONTACTS: &str = "contacts";

const SLED_TREE_SESSIONS: &str = "sessions";
const SLED_TREE_THREAD_PREFIX: &str = "thread";

#[derive(Debug, Clone)]
pub struct SledStore {
    db: Arc<RwLock<sled::Db>>,
}

impl SledStore {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, Error> {
        Ok(SledStore {
            db: Arc::new(RwLock::new(sled::open(path.into())?)),
        })
    }

    #[cfg(test)]
    fn temporary() -> Result<Self, Error> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Self {
            db: Arc::new(RwLock::new(db)),
        })
    }

    pub fn get<K>(&self, key: K) -> Result<Option<IVec>, Error>
    where
        K: AsRef<str>,
    {
        trace!("get {}", key.as_ref());
        Ok(self.db.read().expect("poisoned mutex").get(key.as_ref())?)
    }

    fn get_u32<S>(&self, key: S) -> Result<Option<u32>, Error>
    where
        S: AsRef<str>,
    {
        trace!("getting u32 {}", key.as_ref());
        Ok(self.get(key.as_ref())?.map(|data| {
            let mut a: [u8; 4] = Default::default();
            a.copy_from_slice(&data);
            u32::from_le_bytes(a)
        }))
    }

    fn insert<K, V>(&self, key: K, value: V) -> Result<(), Error>
    where
        K: AsRef<str>,
        IVec: From<V>,
    {
        trace!("inserting {}", key.as_ref());
        let _ = self
            .db
            .try_write()
            .expect("poisoned mutex")
            .insert(key.as_ref(), value)?;
        Ok(())
    }

    fn insert_u32<S>(&self, key: S, value: u32) -> Result<(), Error>
    where
        S: AsRef<str>,
    {
        trace!("inserting u32 {}", key.as_ref());
        self.db
            .try_write()
            .expect("poisoned mutex")
            .insert(key.as_ref(), &value.to_le_bytes())?;
        Ok(())
    }

    fn remove<S>(&self, key: S) -> Result<(), Error>
    where
        S: AsRef<str>,
    {
        trace!("removing {} from db", key.as_ref());
        self.db
            .try_write()
            .expect("poisoned mutex")
            .remove(key.as_ref())?;
        Ok(())
    }

    fn prekey_key(&self, id: PreKeyId) -> String {
        format!("prekey-{:09}", id)
    }

    fn signed_prekey_key(&self, id: SignedPreKeyId) -> String {
        format!("signed-prekey-{:09}", id)
    }

    fn session_key(&self, addr: &ProtocolAddress) -> String {
        format!("session-{}", addr)
    }

    fn session_prefix(&self, name: &str) -> String {
        format!("session-{}.", name)
    }

    fn identity_key(&self, addr: &ProtocolAddress) -> String {
        format!("identity-remote-{}", addr)
    }

    pub fn keys(&self) -> Result<(Vec<String>, Vec<String>), SignalProtocolError> {
        let db = self.db.read().expect("poisoned mutex");
        let global_keys = db
            .iter()
            .filter_map(|r| {
                let (k, _) = r.ok()?;
                Some(String::from_utf8_lossy(&k).to_string())
            })
            .collect();
        let session_keys = db
            .open_tree(SLED_TREE_SESSIONS)
            .unwrap_or_else(|e| {
                panic!("failed to open sessions tree: {}", e);
            })
            .iter()
            .filter_map(|r| {
                let (k, _) = r.ok()?;
                Some(String::from_utf8_lossy(&k).to_string())
            })
            .collect();
        Ok((global_keys, session_keys))
    }
}

impl StateStore<Registered> for SledStore {
    fn load_state(&self) -> Result<Registered, Error> {
        let db = self.db.read().expect("poisoned mutex");
        let data = db
            .get(SLED_KEY_REGISTRATION)?
            .ok_or(Error::NotYetRegisteredError)?;
        serde_json::from_slice(&data).map_err(Error::from)
    }

    fn save_state(&mut self, state: &Registered) -> Result<(), Error> {
        let db = self.db.try_write().expect("poisoned mutex");
        db.clear()?;
        db.insert(SLED_KEY_REGISTRATION, serde_json::to_vec(state)?)?;
        Ok(())
    }
}

impl Store for SledStore {
    fn pre_keys_offset_id(&self) -> Result<u32, Error> {
        Ok(self.get_u32("pre_keys_offset_id")?.unwrap_or(0))
    }

    fn set_pre_keys_offset_id(&mut self, id: u32) -> Result<(), Error> {
        self.insert_u32("pre_keys_offset_id", id)
    }

    fn next_signed_pre_key_id(&self) -> Result<u32, Error> {
        Ok(self.get_u32("next_signed_pre_key_id")?.unwrap_or(0))
    }

    fn set_next_signed_pre_key_id(&mut self, id: u32) -> Result<(), Error> {
        self.insert_u32("next_signed_pre_key_id", id)
    }
}

impl ContactsStore for SledStore {
    fn save_contacts(&mut self, contacts: impl Iterator<Item = Contact>) -> Result<(), Error> {
        let tree = self
            .db
            .write()
            .expect("poisoned mutex")
            .open_tree(SLED_KEY_CONTACTS)?;
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
            .read()
            .expect("poisoned mutex")
            .open_tree(SLED_KEY_CONTACTS)?
            .iter()
            .filter_map(Result::ok)
            .filter_map(|(_key, buf)| serde_json::from_slice(&buf).ok())
            .collect())
    }

    fn contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Error> {
        let db = self.db.read().expect("poisoned mutex");
        Ok(
            if let Some(buf) = db.open_tree(SLED_KEY_CONTACTS)?.get(id.to_string())? {
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
        let buf = self
            .get(self.prekey_key(prekey_id))
            .unwrap()
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(&buf)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.insert(self.prekey_key(prekey_id), record.serialize()?)
            .expect("failed to store pre-key");
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.remove(self.prekey_key(prekey_id))
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
        let buf = self
            .get(self.signed_prekey_key(signed_prekey_id))
            .unwrap()
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
            self.signed_prekey_key(signed_prekey_id),
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
        let key = self.session_key(address);
        trace!("loading session from {}", key);

        let buf = self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_SESSIONS)
            .unwrap()
            .get(key)
            .unwrap();

        buf.map(|buf| SessionRecord::deserialize(&buf)).transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let key = self.session_key(address);
        trace!("storing session for {:?} at {:?}", address, key);
        self.db
            .try_write()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_SESSIONS)
            .unwrap()
            .insert(key, record.serialize()?)
            .unwrap();
        Ok(())
    }
}

#[async_trait]
impl SessionStoreExt for SledStore {
    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, SignalProtocolError> {
        let session_prefix = self.session_prefix(name);
        log::info!("get_sub_device_sessions: session_prefix={}", session_prefix);
        let session_ids: Vec<u32> = self
            .db
            .read()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_SESSIONS)
            .unwrap()
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
        let key = self.session_key(address);
        trace!("deleting session with key: {}", key);
        self.db
            .try_write()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_SESSIONS)
            .unwrap()
            .remove(key)
            .map_err(|_e| SignalProtocolError::SessionNotFound(address.clone()))?;
        Ok(())
    }

    async fn delete_all_sessions(&self, _name: &str) -> Result<usize, SignalProtocolError> {
        let tree = self
            .db
            .try_write()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_SESSIONS)
            .unwrap();
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
        self.insert(self.identity_key(address), identity_key.serialize())
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
        identity_key: &IdentityKey,
        _direction: Direction,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        match self.get(self.identity_key(address)).map_err(|_| {
            SignalProtocolError::InvalidState(
                "is_trusted_identity",
                "failed to check if identity is trusted".into(),
            )
        })? {
            None => {
                // when we encounter a new identity, we trust it by default
                warn!("trusting new identity {:?}", address);
                Ok(true)
            }
            Some(contents) => Ok(&IdentityKey::decode(&contents)? == identity_key),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let buf = self.get(self.identity_key(address)).map_err(|e| {
            log::error!("error getting identity of {:?}: {}", address, e);
            SignalProtocolError::InvalidState("get_identity", "failed to read identity".into())
        })?;
        Ok(buf.map(|ref b| IdentityKey::decode(b).unwrap()))
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

        let tree_thread = self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree(thread_key(&thread))?;

        let timestamp_bytes = message.metadata.timestamp.to_be_bytes();
        let proto: ContentProto = message.into();
        tree_thread.insert(timestamp_bytes, proto.encode_to_vec())?;
        Ok(())
    }

    fn delete_message(&mut self, thread: &Thread, timestamp: u64) -> Result<bool, Error> {
        Ok(self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree(thread_key(thread))?
            .remove(timestamp.to_be_bytes())?
            .is_some())
    }

    fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<libsignal_service::prelude::Content>, Error> {
        let tree_thread = self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree(thread_key(thread))?;
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
        let tree_thread = self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree(thread_key(thread))?;
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
