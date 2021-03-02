use std::{
    collections::HashMap,
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock},
};

use libsignal_protocol::{
    keys::{PrivateKey, PublicKey},
    stores::IdentityKeyStore,
    stores::SessionStore,
    stores::{PreKeyStore, SerializedSession, SignedPreKeyStore},
    Address, Buffer, Context, Serializable,
};
use libsignal_service::{
    configuration::{SignalServers, SignalingKey},
    gv2::{AuthCredentialResponse, CredentialsCache, CredentialsCacheError},
};
use log::{trace, warn};
use sled::IVec;

use crate::{manager::State, Error};

use super::ConfigStore;

#[derive(Debug, Clone)]
pub struct SledConfigStore {
    db: Arc<RwLock<sled::Db>>,
}

impl SledConfigStore {
    pub fn new(path: PathBuf) -> Result<Self, Error> {
        Ok(SledConfigStore {
            db: Arc::new(RwLock::new(sled::open(path)?)),
        })
    }

    #[cfg(test)]
    fn temporary() -> Result<Self, Error> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Self {
            db: Arc::new(RwLock::new(db)),
        })
    }

    fn get_string(db: &sled::Tree, key: &str) -> Result<String, Error> {
        trace!("getting string {} from config", key);
        Ok(String::from_utf8_lossy(
            &db.get(key)?
                .ok_or_else(|| Error::MissingKeyError(key.to_string().into()))?,
        )
        .to_string())
    }

    pub fn get<K>(&self, key: K) -> Result<Option<IVec>, Error>
    where
        K: AsRef<str>,
    {
        trace!("get {}", key.as_ref());
        Ok(self.db.read().expect("poisoned mutex").get(key.as_ref())?)
    }

    fn get_i32<S>(&self, key: S) -> Result<Option<i32>, Error>
    where
        S: AsRef<str>,
    {
        trace!("getting i32 {}", key.as_ref());
        Ok(self.get(key.as_ref())?.map(|data| {
            let mut a: [u8; 4] = Default::default();
            a.copy_from_slice(&data);
            i32::from_le_bytes(a)
        }))
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

    fn contains<S>(&self, key: S) -> Result<bool, Error>
    where
        S: AsRef<str>,
    {
        trace!("checking if config contains {}", key.as_ref());
        Ok(self
            .db
            .read()
            .expect("poisoned mutex")
            .contains_key(key.as_ref())?)
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

    fn session_key(&self, addr: &Address) -> String {
        format!("session-{}-{}", addr.as_str().unwrap(), addr.device_id())
    }

    fn session_prefix(&self, name: &[u8]) -> String {
        format!("session-{}-", String::from_utf8_lossy(name))
    }

    fn identity_key(&self, addr: &Address) -> String {
        format!("identity-remote-{}", addr.as_str().unwrap(),)
    }

    pub fn keys(&self) -> (Vec<String>, Vec<String>) {
        let db = self.db.read().unwrap();
        let global_keys = db
            .iter()
            .map(|r| {
                let (k, _) = r.unwrap();
                String::from_utf8_lossy(&k).to_string()
            })
            .collect();
        let session_keys = db
            .open_tree("sessions")
            .unwrap()
            .iter()
            .map(|r| {
                let (k, _) = r.unwrap();
                String::from_utf8_lossy(&k).to_string()
            })
            .collect();
        (global_keys, session_keys)
    }
}

impl ConfigStore for SledConfigStore {
    fn state(&self, context: &Context) -> Result<State, Error> {
        let db = self.db.read().expect("poisoned mutex");
        if db.contains_key("uuid")? {
            trace!("Loading registered state");
            Ok(State::Registered {
                signal_servers: SignalServers::from_str(&Self::get_string(&db, "signal_servers")?)
                    .expect("unknown signal servers"),
                phone_number: Self::get_string(&db, "phone_number")?.parse()?,
                uuid: Self::get_string(&db, "uuid")?.parse()?,
                password: Self::get_string(&db, "password")?,
                signaling_key: {
                    let mut key: SignalingKey = [0; 52];
                    key.copy_from_slice(
                        &db.get("signaling_key")?
                            .ok_or_else(|| Error::MissingKeyError("signaling_key".into()))?,
                    );
                    key
                },
                device_id: self.get_i32("device_id")?,
                registration_id: self
                    .get_u32("registration_id")?
                    .ok_or_else(|| Error::MissingKeyError("registration_id".into()))?
                    as u32,
                private_key: PrivateKey::decode_point(
                    context,
                    &db.get("private_key")?
                        .ok_or_else(|| Error::MissingKeyError("private_key".into()))?,
                )?,
                public_key: PublicKey::decode_point(
                    context,
                    &db.get("public_key")?
                        .ok_or_else(|| Error::MissingKeyError("public_key".into()))?,
                )?,
                profile_key: db
                    .get("profile_key")?
                    .ok_or_else(|| Error::MissingKeyError("profile_key".into()))?
                    .to_vec(),
            })
        } else if db.contains_key("phone_number")? {
            trace!("Loading registration state");
            Ok(State::Registration {
                signal_servers: SignalServers::from_str(&Self::get_string(&db, "signal_servers")?)
                    .expect("unknown signal servers"),
                phone_number: Self::get_string(&db, "phone_number")?.parse()?,
                password: Self::get_string(&db, "password")?,
            })
        } else {
            Ok(State::New)
        }
    }

    fn save(&self, state: &State) -> Result<(), Error> {
        let db = self.db.try_write().expect("poisoned mutex");
        db.clear()?;
        match state {
            State::New => (),
            State::Registration {
                signal_servers,
                phone_number,
                password,
            } => {
                trace!("saving registration data");
                db.insert("signal_servers", signal_servers.to_string().as_bytes())?;
                db.insert("phone_number", phone_number.to_string().as_bytes())?;
                db.insert("password", password.as_bytes())?;
            }
            State::Registered {
                signal_servers,
                phone_number,
                uuid,
                password,
                signaling_key,
                device_id,
                registration_id,
                private_key,
                public_key,
                profile_key,
            } => {
                db.insert("signal_servers", signal_servers.to_string().as_bytes())?;
                db.insert("phone_number", phone_number.to_string().as_bytes())?;
                db.insert("uuid", uuid.to_string().as_bytes())?;
                db.insert("password", password.as_bytes())?;
                db.insert("signaling_key", signaling_key.to_vec())?;
                if let Some(device_id) = device_id {
                    db.insert("device_id", &device_id.to_le_bytes())?;
                }
                db.insert("registration_id", &registration_id.to_le_bytes())?;
                db.insert("private_key", private_key.serialize()?.as_slice())?;
                db.insert("public_key", public_key.serialize()?.as_slice())?;
                db.insert("profile_key", profile_key.as_slice())?;
            }
        };
        Ok(())
    }

    fn pre_keys_offset_id(&self) -> Result<u32, Error> {
        Ok(self.get_u32("pre_keys_offset_id")?.unwrap_or(0))
    }

    fn set_pre_keys_offset_id(&self, id: u32) -> Result<(), Error> {
        self.insert_u32("pre_keys_offset_id", id)
    }

    fn next_signed_pre_key_id(&self) -> Result<u32, Error> {
        Ok(self.get_u32("next_signed_pre_key_id")?.unwrap_or(0))
    }

    fn set_next_signed_pre_key_id(&self, id: u32) -> Result<(), Error> {
        self.insert_u32("next_signed_pre_key_id", id)
    }
}

impl PreKeyStore for SledConfigStore {
    fn load(&self, id: u32, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
        trace!("loading pre-key {}", id);
        writer.write_all(
            &self
                .get(self.prekey_key(id))
                .expect("sled error")
                .expect("no pre key with this id"),
        )
    }

    fn store(&self, id: u32, body: &[u8]) -> Result<(), libsignal_protocol::Error> {
        trace!("storing pre-key {}", id);
        self.insert(self.prekey_key(id), body)
            .expect("failed to store pre-key");
        Ok(())
    }

    fn contains(&self, id: u32) -> bool {
        trace!("checking if pre-key {} exists", id);
        self.contains(self.prekey_key(id)).unwrap()
    }

    fn remove(&self, id: u32) -> Result<(), libsignal_protocol::Error> {
        self.remove(self.prekey_key(id)).unwrap();
        Ok(())
    }
}

impl SignedPreKeyStore for SledConfigStore {
    fn load(&self, id: u32, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
        trace!("loading signed-pre key {}", id);
        writer.write_all(&self.get(self.signed_prekey_key(id)).unwrap().unwrap())
    }

    fn store(&self, id: u32, body: &[u8]) -> Result<(), libsignal_protocol::Error> {
        trace!("storing signed pre-key {}", id);
        self.insert(self.signed_prekey_key(id), body).unwrap();
        Ok(())
    }

    fn contains(&self, id: u32) -> bool {
        trace!("checking is signed pre-key {} exists", id);
        self.contains(self.signed_prekey_key(id)).unwrap()
    }

    fn remove(&self, id: u32) -> Result<(), libsignal_protocol::Error> {
        trace!("removing signed pre-key {}", id);
        self.remove(self.signed_prekey_key(id)).unwrap();
        Ok(())
    }
}

impl SessionStore for SledConfigStore {
    fn load_session(
        &self,
        address: libsignal_protocol::Address,
    ) -> Result<Option<libsignal_protocol::stores::SerializedSession>, libsignal_protocol::Error>
    {
        let key = self.session_key(&address);
        trace!("loading session from {}", key);

        let buf = if let Ok(Some(buf)) = self
            .db
            .try_read()
            .expect("poisoned mutex")
            .open_tree("sessions")
            .unwrap()
            .get(key)
        {
            buf
        } else {
            return Ok(None);
        };

        trace!("session loaded!");
        Ok(Some(SerializedSession {
            session: Buffer::from(&buf[..]),
            extra_data: None,
        }))
    }

    fn get_sub_device_sessions(
        &self,
        addr: &[u8],
    ) -> Result<Vec<i32>, libsignal_protocol::InternalError> {
        trace!("getting sub device sessions");

        let session_prefix = self.session_prefix(addr);
        let ids = self
            .db
            .read()
            .expect("poisoned mutex")
            .open_tree("sessions")
            .unwrap()
            .scan_prefix(&session_prefix)
            .filter_map(|r| {
                let (key, _) = r.unwrap();
                let key_str = String::from_utf8_lossy(&key);
                let device_id = key_str.strip_prefix(&session_prefix)?;
                device_id.parse().ok()
            })
            .collect();

        Ok(ids)
    }

    fn contains_session(
        &self,
        addr: libsignal_protocol::Address,
    ) -> Result<bool, libsignal_protocol::Error> {
        trace!("contains session for {:?}", addr);
        self.db
            .read()
            .expect("poisoned mutex")
            .open_tree("sessions")
            .unwrap()
            .contains_key(self.session_key(&addr))
            .map_err(|e| libsignal_protocol::Error::Unknown {
                reason: e.to_string(),
            })
    }

    fn store_session(
        &self,
        addr: libsignal_protocol::Address,
        session: libsignal_protocol::stores::SerializedSession,
    ) -> Result<(), libsignal_protocol::InternalError> {
        let key = self.session_key(&addr);
        trace!("storing session for {:?} at {:?}", addr, key);
        self.db
            .try_write()
            .expect("poisoned mutex")
            .open_tree("sessions")
            .unwrap()
            .insert(key, session.session.as_slice())
            .unwrap();
        trace!("stored session");
        Ok(())
    }

    fn delete_session(
        &self,
        addr: libsignal_protocol::Address,
    ) -> Result<(), libsignal_protocol::Error> {
        let key = self.session_key(&addr);
        trace!("deleting session with key: {}", key);
        self.db
            .try_write()
            .expect("poisoned mutex")
            .open_tree("sessions")
            .unwrap()
            .remove(key)
            .unwrap();
        Ok(())
    }

    fn delete_all_sessions(&self, _name: &[u8]) -> Result<usize, libsignal_protocol::Error> {
        trace!("deleting all sessions");
        let tree = self
            .db
            .try_write()
            .expect("poisoned mutex")
            .open_tree("sessions")
            .unwrap();
        let s = tree.len();
        tree.clear().unwrap();
        Ok(s)
    }
}

impl IdentityKeyStore for SledConfigStore {
    fn identity_key_pair(
        &self,
    ) -> Result<(libsignal_protocol::Buffer, libsignal_protocol::Buffer), libsignal_protocol::Error>
    {
        trace!("getting identity_key_pair");
        let public_key: &[u8] = &self.get("public_key").unwrap().unwrap();
        let private_key: &[u8] = &self.get("private_key").unwrap().unwrap();
        Ok((public_key.into(), private_key.into()))
    }

    fn local_registration_id(&self) -> Result<u32, libsignal_protocol::Error> {
        trace!("getting local_registration_id");
        Ok(self.get_u32("registration_id").unwrap().unwrap())
    }

    fn is_trusted_identity(
        &self,
        address: libsignal_protocol::Address,
        identity_key: &[u8],
    ) -> Result<bool, libsignal_protocol::Error> {
        match self.get(self.identity_key(&address)).map_err(|e| {
            log::error!("failed to read identity for {:?}: {}", address, e);
            libsignal_protocol::InternalError::Unknown
        })? {
            None => {
                // when we encounter a new identity, we trust it by default
                warn!("trusting new identity {:?}", address);
                Ok(true)
            }
            Some(contents) => Ok(contents == identity_key),
        }
    }

    fn save_identity(
        &self,
        address: libsignal_protocol::Address,
        identity_key: &[u8],
    ) -> Result<(), libsignal_protocol::Error> {
        trace!("saving identity");
        self.insert(self.identity_key(&address), identity_key)
            .map_err(|e| {
                log::error!("error saving identity for {:?}: {}", address, e);
                libsignal_protocol::InternalError::Unknown
            })?;
        trace!("saved identity");
        Ok(())
    }

    fn get_identity(&self, address: Address) -> Result<Option<Buffer>, libsignal_protocol::Error> {
        trace!("getting identity of {:?}", &address);
        Ok(self
            .get(self.identity_key(&address))
            .map_err(|e| {
                log::error!("error getting identity of {:?}: {}", address, e);
                libsignal_protocol::InternalError::Unknown
            })?
            .map(|v| Buffer::from(&v[..])))
    }
}

impl CredentialsCache for SledConfigStore {
    fn clear(&self) -> Result<(), CredentialsCacheError> {
        let db = self.db.read().expect("poisoned mutex");
        db.remove("gv2-credentials-cache")
            .map_err(|e| CredentialsCacheError::WriteError(e.to_string()))?;
        Ok(())
    }

    fn read(&self) -> Result<HashMap<i64, AuthCredentialResponse>, CredentialsCacheError> {
        let db = self.db.read().expect("poisoned mutex");
        if let Some(buf) = db.get("gv2-credentials-cache").map_err(|e| {
            CredentialsCacheError::ReadError(format!("failed to read credentials cache: {}", e))
        })? {
            serde_json::from_slice(&buf).map_err(|e| {
                CredentialsCacheError::ReadError(format!("failed to deserialize JSON: {}", e))
            })
        } else {
            Ok(HashMap::new())
        }
    }

    fn write(
        &self,
        value: &HashMap<i64, AuthCredentialResponse>,
    ) -> Result<(), CredentialsCacheError> {
        let db = self.db.read().expect("poisoned mutex");
        let buf = serde_json::to_vec(value).map_err(|e| {
            CredentialsCacheError::WriteError(format!("failed to serialize JSON: {}", e))
        })?;
        db.insert("gv2-credentials-cache", buf).map_err(|e| {
            CredentialsCacheError::WriteError(format!("failed to write credentials cache: {}", e))
        })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use quickcheck::{quickcheck, Arbitrary, Gen};

    use std::collections::HashSet;

    #[derive(Debug, Clone)]
    struct Address(libsignal_protocol::Address);

    impl Arbitrary for Address {
        fn arbitrary(g: &mut Gen) -> Address {
            let name: String = Arbitrary::arbitrary(g);
            let device_id: u8 = Arbitrary::arbitrary(g);
            Address(libsignal_protocol::Address::new(name, device_id.into()))
        }
    }

    quickcheck! {
        fn test_save_get_trust_identity(addr: Address, identity_key: Vec<u8>) -> bool {
            let db = SledConfigStore::temporary().unwrap();
            db.save_identity(addr.clone().0, &identity_key).unwrap();
            let id = db.get_identity(addr.clone().0).unwrap().unwrap();
            if id.as_slice() != identity_key {
                return false;
            }
            db.is_trusted_identity(addr.0, id.as_slice()).unwrap()
        }
    }

    quickcheck! {
        fn test_store_load_session(addr: Address, session: Vec<u8>) -> bool {
            let session = libsignal_protocol::stores::SerializedSession {
                session: session.into(),
                extra_data: None,
            };

            let db = SledConfigStore::temporary().unwrap();
            db.store_session(addr.clone().0, session.clone()).unwrap();
            if !db.contains_session(addr.clone().0).unwrap() {
                return false;
            }
            let loaded_session = db.load_session(addr.clone().0).unwrap().unwrap();

            session == loaded_session
        }
    }

    quickcheck! {
        fn test_get_sub_device_sessions(name: String, device_ids: HashSet<u8>) -> bool {
            let db = SledConfigStore::temporary().unwrap();

            for device_id in &device_ids {
                let session = libsignal_protocol::stores::SerializedSession {
                    session: vec![0; 10].into(),
                    extra_data: None,
                };
                let addr = libsignal_protocol::Address::new(name.clone(), (*device_id).into());
                db.store_session(addr, session.clone()).unwrap();
            }

            let stored_devices_ids = db
                .get_sub_device_sessions(name.as_bytes())
                .unwrap()
                .into_iter()
                .map(|id| id as u8)
                .collect();
            device_ids == stored_devices_ids
        }
    }

    quickcheck! {
        fn test_prekey_store(id: u32, body: Vec<u8>) -> bool {
            let db = SledConfigStore::temporary().unwrap();

            PreKeyStore::store(&db, id, &body).unwrap();
            if !PreKeyStore::contains(&db, id) {
                return false;
            }

            let mut loaded_body = Vec::new();
            PreKeyStore::load(&db, id, &mut loaded_body).unwrap();
            if body != loaded_body {
                return false;
            }

            PreKeyStore::remove(&db, id).unwrap();
            !PreKeyStore::contains(&db, id)
        }
    }

    quickcheck! {
        fn test_signed_prekey_store(id: u32, body: Vec<u8>) -> bool {
            let db = SledConfigStore::temporary().unwrap();

            SignedPreKeyStore::store(&db, id, &body).unwrap();
            if !SignedPreKeyStore::contains(&db, id) {
                return false;
            }

            let mut loaded_body = Vec::new();
            SignedPreKeyStore::load(&db, id, &mut loaded_body).unwrap();
            if body != loaded_body {
                return false;
            }

            SignedPreKeyStore::remove(&db, id).unwrap();
            !SignedPreKeyStore::contains(&db, id)
        }
    }
}
