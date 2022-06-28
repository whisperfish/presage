use std::{
    collections::HashMap,
    sync::{Arc, RwLock, Mutex},
};

use async_trait::async_trait;
use libsignal_service::{
    models::Contact,
    prelude::{
        protocol::{
            Context, Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore, PreKeyRecord,
            PreKeyStore, ProtocolAddress, SessionRecord, SessionStore, SessionStoreExt,
            SignalProtocolError, SignedPreKeyRecord, SignedPreKeyStore,
        },
        Uuid,
    },
};
use log::{trace, warn};
use secrets::{SecretBox, SecretVec};

use super::{ConfigStore, ContactsStore, StateStore};
use crate::{manager::Registered, Error};

#[derive(Default, Debug, Clone)]
pub struct SecretVolatileConfigStore {
    // `Cell<u8>` cannot be shared between threads safely (part of SecretBox/SecretVec)
    // - therefore wrapped within a Mutex
    // - to be able to derive the Clone trait Arc is needed
    // - Option enum to derive derive the Default trait
    pre_keys_offset_id: Arc<Mutex<Option<SecretBox<u32>>>>,
    next_signed_pre_key_id: Arc<Mutex<Option<SecretBox<u32>>>>,

    pre_keys: Arc<RwLock<HashMap<u32, Mutex<SecretVec<u8>>>>>,
    signed_pre_keys: Arc<RwLock<HashMap<u32, Mutex<SecretVec<u8>>>>>,

    // XXX: we need interior mutability + Sync until we fix the trait definition to use &mut self in libsignal-service
    sessions: Arc<RwLock<HashMap<String, Mutex<SecretVec<u8>>>>>,

    identities: Arc<RwLock<HashMap<ProtocolAddress, Mutex<SecretVec<u8>>>>>,
    registration: Arc<RwLock<Option<Mutex<SecretVec<u8>>>>>,
}
// todo: to erase or zero out secrets passed into the secret store upstream refactoring is necessary,
// parameters for example `id` for `set_pre_keys_offset_id` must be passed as &mut for the secrets crate to zero out the value.

impl SecretVolatileConfigStore {
    fn session_key(&self, addr: &ProtocolAddress) -> String {
        format!("session-{}", addr)
    }

    fn session_prefix(&self, name: &str) -> String {
        format!("session-{}.", name)
    }
}

impl StateStore<Registered> for SecretVolatileConfigStore {
    fn load_state(&self) -> Result<Registered, Error> {
        let d = self
            .registration
            .try_read()
            .expect("poisoned mutex");
        let data = d.as_ref()
            .ok_or(Error::NotYetRegisteredError)?;
        let x = serde_json::from_slice(&(*data.try_lock().unwrap()).borrow()).map_err(Error::from); x
    }

    fn save_state(&mut self, state: &Registered) -> Result<(), Error> {
        let mut data = serde_json::to_vec(state)?;
        self.registration = Arc::new(RwLock::new(Some(Mutex::new(SecretVec::from(&mut data[..])))));
        Ok(())
    }
}

impl ConfigStore for SecretVolatileConfigStore {
    fn pre_keys_offset_id(&self) -> Result<u32, Error> {
        let d = self.pre_keys_offset_id
            .try_lock()
            .expect("poisoned mutex");
        match d.as_ref() {
            None => Ok(0u32),
            Some(s) => Ok(*s.borrow()),
        }
    }

    fn set_pre_keys_offset_id(&mut self, id: u32) -> Result<(), Error> {
        self.pre_keys_offset_id = Arc::new(Mutex::new(Some(SecretBox::<u32>::new(|s| *s=id))));
        Ok(())
    }

    fn next_signed_pre_key_id(&self) -> Result<u32, Error> {
        let d = self.next_signed_pre_key_id
            .try_lock()
            .expect("poisoned mutex");
        match d.as_ref() {
            None => Ok(0u32),
            Some(s) => Ok(*s.borrow()),
        }
    }

    fn set_next_signed_pre_key_id(&mut self, id: u32) -> Result<(), Error> {
        self.next_signed_pre_key_id = Arc::new(Mutex::new(Some(SecretBox::<u32>::new(|s| *s=id))));
        Ok(())
    }
}

impl ContactsStore for SecretVolatileConfigStore {
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
impl PreKeyStore for SecretVolatileConfigStore {
    async fn get_pre_key(
        &self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        let buf = self
            .pre_keys
            .try_read()
            .expect("poisoned mutex");
        let b = buf
            .get(&prekey_id)
            .ok_or(SignalProtocolError::InvalidPreKeyId)?;
        let x = PreKeyRecord::deserialize(&(*b.try_lock().unwrap()).borrow()); x
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: u32,
        record: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.pre_keys
            .try_write()
            .expect("poisoned mutex")
            .insert(prekey_id, Mutex::new(SecretVec::from(&mut record.serialize()?[..])));
        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: u32,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.pre_keys
            .try_write()
            .expect("poisoned mutex")
            .remove(&prekey_id);
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SecretVolatileConfigStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: u32,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let buf = self
            .signed_pre_keys
            .try_write()
            .expect("poisoned mutex");
        let b = buf
            .get(&signed_prekey_id)
            .ok_or(SignalProtocolError::InvalidSignedPreKeyId)?;
        let x = SignedPreKeyRecord::deserialize(&(*b.try_lock().unwrap()).borrow()); x
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: u32,
        record: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        self.signed_pre_keys
            .try_write()
            .expect("poisoned mutex")
            .insert(signed_prekey_id, Mutex::new(SecretVec::from(&mut record.serialize()?[..])));
        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for SecretVolatileConfigStore {
    async fn load_session(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let db = self.sessions.try_read().expect("poisoned mutex");
        let key = self.session_key(address);
        let buf = db.get(&key);

        buf.map(|buf| SessionRecord::deserialize(&(*buf.try_lock().unwrap()).borrow())).transpose()
    }

    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        let key = self.session_key(address);
        let mut data =  record.serialize()?;
        self.sessions
            .try_write()
            .expect("poisoned mutex")
            .insert(key, Mutex::new(SecretVec::from(&mut data[..])));
        Ok(())
    }
}

#[async_trait]
impl SessionStoreExt for SecretVolatileConfigStore {
    async fn get_sub_device_sessions(&self, name: &str) -> Result<Vec<u32>, SignalProtocolError> {
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
impl IdentityKeyStore for SecretVolatileConfigStore {
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
            .try_write()
            .expect("poisoned mutex")
            .insert(address.clone(), Mutex::new(SecretVec::from(&mut identity_key.serialize().to_vec()[..])));
        Ok(false)
    }

    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity_key: &IdentityKey,
        _direction: Direction,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        match self.identities
            .try_read()
            .expect("poisoned mutex").get(address) {
            None => {
                // when we encounter a new identity, we trust it by default
                warn!("trusting new identity {:?}", address);
                Ok(true)
            }
            Some(contents) => Ok(&IdentityKey::decode(&(*contents.try_lock().unwrap()).borrow())? == identity_key),
        }
    }

    async fn get_identity(
        &self,
        address: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let identities = self.identities
            .try_write()
            .expect("poisoned mutex");
        let buf = identities
            .get(address);
        Ok(buf.map(|ref b| IdentityKey::decode(&(*b.try_lock().unwrap()).borrow()).unwrap()))
    }
}
