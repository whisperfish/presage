use std::{
    path::PathBuf,
    str::FromStr,
    sync::{Arc, RwLock},
};

use directories::ProjectDirs;
use libsignal_protocol::{
    keys::{PrivateKey, PublicKey},
    stores::IdentityKeyStore,
    stores::SessionStore,
    stores::{PreKeyStore, SerializedSession, SignedPreKeyStore},
    Address, Buffer, Context, Serializable,
};
use libsignal_service::configuration::{SignalServers, SignalingKey};
use log::{trace, warn};
use sled::IVec;

use crate::{manager::State, Error};

use super::ConfigStore;

#[derive(Debug, Clone)]
pub struct SledConfigStore {
    db: Arc<RwLock<sled::Db>>,
}

impl SledConfigStore {
    pub fn new() -> Result<Self, Error> {
        let dir: PathBuf = ProjectDirs::from("org", "libsignal-service-rs", "signal-bot-rs")
            .unwrap()
            .config_dir()
            .into();
        std::fs::create_dir_all(&dir).unwrap();
        Ok(SledConfigStore {
            db: Arc::new(RwLock::new(sled::open(dir.join("db.sled"))?)),
        })
    }

    fn get_string(db: &sled::Tree, key: &str) -> Result<String, Error> {
        trace!("getting string {} from config", key);
        Ok(
            String::from_utf8_lossy(&db.get(key)?.ok_or(Error::MissingKeyError(key.into()))?)
                .to_string(),
        )
    }

    fn get<K>(&self, key: K) -> Result<Option<IVec>, Error>
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
        Ok(self.get(key.as_ref())?.and_then(|ref data| {
            let mut a: [u8; 4] = Default::default();
            a.copy_from_slice(data);
            Some(i32::from_le_bytes(a))
        }))
    }

    fn get_u32<S>(&self, key: S) -> Result<Option<u32>, Error>
    where
        S: AsRef<str>,
    {
        trace!("getting u32 {}", key.as_ref());
        Ok(self.get(key.as_ref())?.and_then(|ref data| {
            let mut a: [u8; 4] = Default::default();
            a.copy_from_slice(data);
            Some(u32::from_le_bytes(a))
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

    fn identity_key(&self, addr: &Address) -> String {
        format!("identity-remote-{}", addr.as_str().unwrap())
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
                phone_number: Self::get_string(&db, "phone_number")?,
                uuid: Self::get_string(&db, "uuid")?,
                password: Self::get_string(&db, "password")?,
                signaling_key: {
                    let mut key: SignalingKey = [0; 52];
                    key.copy_from_slice(
                        &db.get("signaling_key")?
                            .ok_or(Error::MissingKeyError("signaling_key".into()))?,
                    );
                    key
                },
                device_id: self.get_i32("device_id")?,
                registration_id: self
                    .get_u32("registration_id")?
                    .ok_or(Error::MissingKeyError("registration_id".into()))?
                    as u32,
                private_key: PrivateKey::decode_point(
                    context,
                    &db.get("private_key")?
                        .ok_or(Error::MissingKeyError("private_key".into()))?,
                )?,
                public_key: PublicKey::decode_point(
                    context,
                    &db.get("public_key")?
                        .ok_or(Error::MissingKeyError("public_key".into()))?,
                )?,
                profile_key: db
                    .get("profile_key")?
                    .ok_or(Error::MissingKeyError("profile_key".into()))?
                    .to_vec(),
            })
        } else if db.contains_key("phone_number")? {
            trace!("Loading registration state");
            Ok(State::Registration {
                signal_servers: SignalServers::from_str(&Self::get_string(&db, "signal_servers")?)
                    .expect("unknown signal servers"),
                phone_number: Self::get_string(&db, "phone_number")?,
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
                db.insert("phone_number", phone_number.as_bytes())?;
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
                db.insert("phone_number", phone_number.as_bytes())?;
                db.insert("uuid", uuid.as_bytes())?;
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
        let ids = self
            .db
            .read()
            .expect("poisoned mutex")
            .open_tree("sessions")
            .unwrap()
            .iter()
            .filter_map(|r| {
                let (key, _) = r.unwrap();
                if key.len() < addr.len() + 2 {
                    return None;
                }

                if &key[..addr.len()] == addr {
                    if key[addr.len()] != '_' as u8 {
                        log::warn!("Weird session directory entry: {:?}. Skipping", key);
                        return None;
                    }
                    // skip underscore
                    let id = std::str::from_utf8(&key[(addr.len() + 1)..]).ok()?;
                    id.parse().ok()
                } else {
                    None
                }
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
}
