use std::{
    collections::HashMap,
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
use log::{trace, warn};

use super::{StateStore, Store};
use crate::{manager::Registered, ContactsStore, Error, MessageStore, Thread};

#[derive(Default, Debug, Clone)]
pub struct VolatileStore {
    pre_keys_offset_id: u32,
    next_signed_pre_key_id: u32,

    pre_keys: HashMap<PreKeyId, Vec<u8>>,
    signed_pre_keys: HashMap<SignedPreKeyId, Vec<u8>>,

    // XXX: we need interior mutability + Sync until we fix the trait definition to use &mut self in libsignal-service
    sessions: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    identities: HashMap<ProtocolAddress, Vec<u8>>,

    registration: Option<Vec<u8>>,
}

impl VolatileStore {
    fn session_key(&self, addr: &ProtocolAddress) -> String {
        format!("session-{}", addr)
    }

    fn session_prefix(&self, name: &str) -> String {
        format!("session-{}.", name)
    }
}

impl StateStore<Registered> for VolatileStore {
    fn load_state(&self) -> Result<Registered, Error> {
        let data = self
            .registration
            .as_ref()
            .ok_or(Error::NotYetRegisteredError)?;
        serde_json::from_slice(data).map_err(Error::from)
    }

    fn save_state(&mut self, state: &Registered) -> Result<(), Error> {
        let data = serde_json::to_vec(state)?;
        self.registration = Some(data);
        Ok(())
    }
}

impl Store for VolatileStore {
    fn clear(&mut self) -> Result<(), Error> {
        let mut new_store: VolatileStore = Default::default();
        std::mem::swap(self, &mut new_store);
        Ok(())
    }

    fn pre_keys_offset_id(&self) -> Result<u32, Error> {
        Ok(self.pre_keys_offset_id)
    }

    fn set_pre_keys_offset_id(&mut self, id: u32) -> Result<(), Error> {
        self.pre_keys_offset_id = id;
        Ok(())
    }

    fn next_signed_pre_key_id(&self) -> Result<u32, Error> {
        Ok(self.next_signed_pre_key_id)
    }

    fn set_next_signed_pre_key_id(&mut self, id: u32) -> Result<(), Error> {
        self.next_signed_pre_key_id = id;
        Ok(())
    }
}

impl ContactsStore for VolatileStore {
    fn clear_contacts(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn save_contacts(&mut self, _: impl Iterator<Item = Contact>) -> Result<(), Error> {
        warn!("contacts are not saved when using volatile storage.");
        Ok(())
    }

    fn contacts(&self) -> Result<Vec<Contact>, Error> {
        warn!("contacts are not saved when using volatile storage.");
        Ok(vec![])
    }

    fn contact_by_id(&self, _: Uuid) -> Result<Option<Contact>, Error> {
        warn!("contacts are not saved when using volatile storage.");
        Ok(None)
    }
}

#[async_trait(?Send)]
impl PreKeyStore for VolatileStore {
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
        _ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        let buf = self
            .pre_keys
            .get(&prekey_id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        PreKeyRecord::deserialize(buf)
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.pre_keys.insert(prekey_id, record.serialize()?);
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.pre_keys.remove(&prekey_id);
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for VolatileStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let buf = self
            .signed_pre_keys
            .get(&signed_prekey_id)
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        SignedPreKeyRecord::deserialize(buf)
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.signed_pre_keys
            .insert(signed_prekey_id, record.serialize()?);
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for VolatileStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let db = self.sessions.try_read().expect("poisoned mutex");
        let key = self.session_key(address);
        let buf = db.get(&key);

        buf.map(|buf| SessionRecord::deserialize(buf)).transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let key = self.session_key(address);
        self.sessions
            .try_write()
            .expect("poisoned mutex")
            .insert(key, record.serialize()?);
        Ok(())
    }
}

#[async_trait]
impl SessionStoreExt for VolatileStore {
    async fn get_sub_device_sessions(
        &self,
        name: &ServiceAddress,
    ) -> Result<Vec<u32>, SignalProtocolError> {
        let session_prefix = self.session_prefix(name);
        log::info!("get_sub_device_sessions: session_prefix={}", session_prefix);
        let session_ids: Vec<u32> = self
            .sessions
            .read()
            .expect("poisoned mutex")
            .keys()
            .filter_map(|key| {
                let device_id = key.strip_prefix(&session_prefix)?;
                device_id.parse().ok()
            })
            .filter(|d| *d != DEFAULT_DEVICE_ID)
            .collect();
        Ok(session_ids)
    }

    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), SignalProtocolError> {
        let key = self.session_key(address);
        trace!("deleting session with key: {}", key);
        self.sessions
            .try_write()
            .expect("poisoned mutex")
            .remove(&key);
        Ok(())
    }

    async fn delete_all_sessions(&self, _name: &str) -> Result<usize, SignalProtocolError> {
        let mut sessions = self.sessions.try_write().expect("poisoned mutex");
        let len = sessions.len();
        sessions.clear();
        Ok(len)
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for VolatileStore {
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
        self.identities
            .insert(address.clone(), identity_key.serialize().to_vec());
        Ok(false)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
        _direction: Direction,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        match self.identities.get(address) {
            None => {
                // when we encounter a new identity, we trust it by default
                warn!("trusting new identity {:?}", address);
                Ok(true)
            }
            Some(contents) => Ok(&IdentityKey::decode(contents)? == identity_key),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let buf = self.identities.get(address);
        Ok(buf.map(|b| IdentityKey::decode(b).unwrap()))
    }
}

impl MessageStore for VolatileStore {
    type MessagesIter = std::iter::Empty<Content>;

    fn save_message(&mut self, _thread: &Thread, _message: Content) -> Result<(), Error> {
        todo!()
    }

    fn delete_message(&mut self, _thread: &Thread, _timestamp: u64) -> Result<bool, Error> {
        todo!()
    }

    fn message(&self, _thread: &Thread, _timestamp: u64) -> Result<Option<Content>, Error> {
        todo!()
    }

    fn messages(&self, _thread: &Thread, _from: Option<u64>) -> Result<Self::MessagesIter, Error> {
        todo!()
    }
}
