use std::{
    path::PathBuf,
    sync::{Arc, RwLock},
};

use async_trait::async_trait;
use libsignal_service::{
    content::ContentBody,
    models::Contact,
    prelude::{
        protocol::{
            Context, Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore, PreKeyRecord,
            PreKeyStore, ProtocolAddress, SessionRecord, SessionStore, SessionStoreExt,
            SignalProtocolError, SignedPreKeyRecord, SignedPreKeyStore,
        },
        Uuid,
    },
    proto::{sync_message::Sent, GroupContextV2, SyncMessage},
    ServiceAddress,
};
use log::{debug, trace, warn};
use prost::Message;
use sled::IVec;

use super::{ConfigStore, ContactsStore, MessageIdentity, MessageStore, StateStore};
use crate::{manager::Registered, proto::ContentProto, Error};

const SLED_KEY_REGISTRATION: &str = "registration";
const SLED_KEY_CONTACTS: &str = "contacts";

const SLED_TREE_SESSIONS: &str = "sessions";
const SLED_TREE_MESSAGES: &str = "messages";
const SLED_TREE_CONTACTS_TO_MESSAGES: &str = "contacts-to-messages";
const SLED_TREE_GROUPS_TO_MESSAGES: &str = "groups-to-messages";

#[derive(Debug, Clone)]
pub struct SledConfigStore {
    db: Arc<RwLock<sled::Db>>,
}

impl SledConfigStore {
    pub fn new(path: impl Into<PathBuf>) -> Result<Self, Error> {
        Ok(SledConfigStore {
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

    fn prekey_key(&self, id: u32) -> String {
        format!("prekey-{:09}", id)
    }

    fn signed_prekey_key(&self, id: u32) -> String {
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

impl StateStore<Registered> for SledConfigStore {
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

impl ConfigStore for SledConfigStore {
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

impl ContactsStore for SledConfigStore {
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
impl PreKeyStore for SledConfigStore {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
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
        prekey_id: u32,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.insert(self.prekey_key(prekey_id), record.serialize()?)
            .expect("failed to store pre-key");
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.remove(self.prekey_key(prekey_id))
            .expect("failed to remove pre-key");
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SledConfigStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: u32,
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
        signed_prekey_id: u32,
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
impl SessionStore for SledConfigStore {
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
impl SessionStoreExt for SledConfigStore {
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
impl IdentityKeyStore for SledConfigStore {
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

fn prefix_merge(_key: &[u8], old_value: Option<&[u8]>, merged_bytes: &[u8]) -> Option<Vec<u8>> {
    let mut ret = merged_bytes.to_vec();

    ret.extend_from_slice(old_value.unwrap_or_default());

    Some(ret)
}

impl MessageStore for SledConfigStore {
    fn save_message(
        &mut self,
        message: libsignal_service::prelude::Content,
        receiver: Option<impl Into<ServiceAddress>>,
    ) -> Result<(), Error> {
        let id = MessageIdentity::try_from(&message)?;
        let store_uuid = if let Some(uuid) = receiver.map(|s| s.into()).and_then(|s| s.uuid) {
            uuid
        } else {
            id.0
        };
        let timestamp = id.1;

        log::trace!("Storing a message with id: {:?}", id);

        let group_master_key = match message.body {
            ContentBody::DataMessage(ref msg)
            | ContentBody::SynchronizeMessage(SyncMessage {
                sent:
                    Some(Sent {
                        message: Some(ref msg),
                        ..
                    }),
                ..
            }) => msg.group_v2.clone().and_then(|g| g.master_key),
            _ => None,
        };

        let tree_messages = self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_MESSAGES)?;
        let tree_contacts_to_messages = self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_CONTACTS_TO_MESSAGES)?;
        let tree_groups_to_messages = self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_GROUPS_TO_MESSAGES)?;
        tree_contacts_to_messages.set_merge_operator(prefix_merge);
        tree_groups_to_messages.set_merge_operator(prefix_merge);

        let key_uuid = store_uuid.as_bytes();
        let key_timestamp = timestamp.to_ne_bytes();
        let key = [&key_uuid[..], &key_timestamp[..]].concat();
        let value = ContentProto::from_content(message);

        tree_messages.insert(key.clone(), value.encode_to_vec())?;
        if let Some(group) = group_master_key {
            log::trace!("Storing message to group: {:?}", group);
            tree_groups_to_messages.merge(group, key)?;
        } else {
            log::trace!("Storing message to contact: {:?}", store_uuid);
            tree_contacts_to_messages.merge(store_uuid.as_bytes(), key)?;
        }
        Ok(())
    }

    fn messages(&self) -> Result<Vec<libsignal_service::prelude::Content>, Error> {
        Ok(self
            .db
            .read()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_MESSAGES)?
            .iter()
            .filter_map(Result::ok)
            .filter_map(|(_key, buf)| ContentProto::decode(&*buf).ok())
            .map(|c| c.into_content())
            .collect())
    }

    fn message_by_identity(
        &self,
        id: &MessageIdentity,
    ) -> Result<Option<libsignal_service::prelude::Content>, Error> {
        let sender = id.0;
        let timestamp = id.1;

        let tree = self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_MESSAGES)?;
        let key_sender = sender.as_bytes();
        let key_timestamp = timestamp.to_ne_bytes();
        let key = [&key_sender[..], &key_timestamp[..]].concat();
        let val = tree.get(key)?;
        if let Some(val) = val {
            let proto = ContentProto::decode(&*val)?;
            Ok(Some(proto.into_content()))
        } else {
            Ok(None)
        }
    }

    fn messages_by_contact(&self, contact: &Uuid) -> Result<Vec<MessageIdentity>, Error> {
        log::trace!("Query messages by contact: {:?}", contact);
        Ok(self
            .db
            .read()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_CONTACTS_TO_MESSAGES)?
            .get(contact.as_bytes())?
            .unwrap_or_default()
            .chunks_exact(24)
            .map(|c| MessageIdentity::from(<[u8; 24]>::try_from(c).unwrap()))
            .collect())
    }

    fn messages_by_group(&self, group: &GroupContextV2) -> Result<Vec<MessageIdentity>, Error> {
        log::trace!("Query messages by group: {:?}", group.master_key());
        Ok(self
            .db
            .read()
            .expect("poisoned mutex")
            .open_tree(SLED_TREE_GROUPS_TO_MESSAGES)?
            .get(group.master_key())?
            .unwrap_or_default()
            .chunks_exact(24)
            .map(|c| MessageIdentity::from(<[u8; 24]>::try_from(c).unwrap()))
            .collect())
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

    use super::SledConfigStore;

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
            let device_id: u8 = Arbitrary::arbitrary(g);
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
        let mut db = SledConfigStore::temporary().unwrap();
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

        let mut db = SledConfigStore::temporary().unwrap();
        db.store_session(&addr.0, &session, None).await.unwrap();
        if db.load_session(&addr.0, None).await.unwrap().is_none() {
            return false;
        }
        let loaded_session = db.load_session(&addr.0, None).await.unwrap().unwrap();
        session.serialize().unwrap() == loaded_session.serialize().unwrap()
    }

    #[quickcheck_async::tokio]
    async fn test_prekey_store(id: u32, key_pair: KeyPair) -> bool {
        let mut db = SledConfigStore::temporary().unwrap();
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
        let mut db = SledConfigStore::temporary().unwrap();
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
