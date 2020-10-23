use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use directories::ProjectDirs;
use libsignal_protocol::{
    keys::{PrivateKey, PublicKey},
    stores::SessionStore,
    stores::{PreKeyStore, SerializedSession, SignedPreKeyStore},
    Address, Buffer, Context, Serializable,
};
use libsignal_service::configuration::SignalingKey;
use log::{debug, trace};
use sled::IVec;

use crate::{manager::State, Error};

use super::ConfigStore;

#[derive(Clone)]
pub struct SledConfigStore {
    db: Arc<Mutex<sled::Db>>,
}

impl SledConfigStore {
    pub fn new() -> Result<Self, Error> {
        let dir: PathBuf = ProjectDirs::from("org", "libsignal-service-rs", "signal-bot-rs")
            .ok_or(Error::MissingKeyError)?
            .config_dir()
            .into();
        std::fs::create_dir_all(&dir).unwrap();
        Ok(SledConfigStore {
            db: Arc::new(Mutex::new(sled::open(dir.join("db.sled"))?)),
        })
    }

    fn db(&self) -> MutexGuard<sled::Db> {
        trace!("[mutex] locking sled DB");
        self.db.lock().expect("poisoned mutex")
    }

    fn get_string<K>(db: &sled::Tree, key: K) -> Result<String, Error>
    where
        K: AsRef<[u8]>,
    {
        Ok(String::from_utf8_lossy(&db.get(key)?.ok_or(Error::MissingKeyError)?).to_string())
    }

    fn get_u32<K>(db: &sled::Tree, key: K) -> Result<Option<u32>, Error>
    where
        K: AsRef<[u8]>,
    {
        Ok(db.get(&key)?.and_then(|ref data| {
            let mut a: [u8; 4] = Default::default();
            a.copy_from_slice(data);
            Some(u32::from_le_bytes(a))
        }))
    }

    fn contains<K>(&self, key: K) -> Result<bool, Error>
    where
        K: AsRef<[u8]>,
    {
        Ok(self.db().contains_key(key)?)
    }

    fn remove<K>(&self, key: K) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
    {
        self.db().remove(key)?;
        Ok(())
    }

    fn prekey_key(&self, id: u32) -> String {
        format!("prekey-{:09}", id)
    }

    fn signed_prekey_key(&self, id: u32) -> String {
        format!("signed-prekey-{:09}", id)
    }

    fn session_key(&self, addr: &Address) -> Option<String> {
        let addr_str = addr.as_str().unwrap();
        let recipient_id = if addr_str.starts_with('+') {
            // strip the prefix + from e164, as is done in Go (cfr. the `func recID`).
            &addr_str[1..]
        } else {
            return None;
            // addr_str
        };

        Some(format!("session-{}-{}", recipient_id, addr.device_id()))
    }
}

impl ConfigStore for SledConfigStore {
    fn state(&self, context: &Context) -> Result<State, Error> {
        let db = self.db();
        if db.contains_key("uuid")? {
            trace!("Loading registered state");
            Ok(State::Registered {
                phone_number: Self::get_string(&db, "phone_number")?,
                uuid: Self::get_string(&db, "uuid")?,
                password: Self::get_string(&db, "password")?,
                signaling_key: {
                    let mut key: SignalingKey = [0; 52];
                    key.copy_from_slice(&db.get("signaling_key")?.ok_or(Error::MissingKeyError)?);
                    key
                },
                device_id: Self::get_u32(&db, "device_id")?,
                private_key: PrivateKey::decode_point(
                    context,
                    &db.get("private_key")?.ok_or(Error::MissingKeyError)?,
                )?,
                public_key: PublicKey::decode_point(
                    context,
                    &db.get("public_key")?.ok_or(Error::MissingKeyError)?,
                )?,
                profile_key: db
                    .get("profile_key")?
                    .ok_or(Error::MissingKeyError)?
                    .to_vec(),
            })
        } else if db.contains_key("phone_number")? {
            trace!("Loading registration state");
            Ok(State::Registration {
                phone_number: Self::get_string(&db, "phone_number")?,
                password: Self::get_string(&db, "password")?,
            })
        } else {
            Err(Error::NotYetRegisteredError)
        }
    }

    fn pre_key_id_offset(&self) -> Result<u32, Error> {
        let db = self.db();
        Ok(Self::get_u32(&db, "pre_key_id_offset")?.ok_or(Error::MissingKeyError)?)
    }

    fn next_signed_pre_key_id(&self) -> Result<u32, Error> {
        let db = self.db();
        Ok(Self::get_u32(&db, "next_signed_pre_key_id")?.ok_or(Error::MissingKeyError)?)
    }

    fn save(&self, state: &State) -> Result<(), Error> {
        let db = self.db();
        match state {
            State::Registration {
                phone_number,
                password,
            } => {
                db.insert("phone_number", phone_number.as_bytes())?;
                db.insert("password", password.as_bytes())?;
            }
            State::Registered {
                phone_number,
                uuid,
                password,
                signaling_key,
                device_id,
                private_key,
                public_key,
                profile_key,
            } => {
                db.insert("phone_number", phone_number.as_bytes())?;
                db.insert("uuid", uuid.as_bytes())?;
                db.insert("password", password.as_bytes())?;
                db.insert("signaling_key", signaling_key.to_vec())?;
                if let Some(device_id) = device_id {
                    db.insert("device_id", &device_id.to_le_bytes())?;
                }
                db.insert("private_key", private_key.serialize()?.as_slice())?;
                db.insert("public_key", public_key.serialize()?.as_slice())?;
                db.insert("profile_key", profile_key.as_slice())?;
            }
        };
        Ok(())
    }

    fn get<K>(&self, key: K) -> Result<Option<IVec>, Error>
    where
        K: AsRef<[u8]>,
    {
        Ok(self.db().get(key)?)
    }

    fn insert<K, V>(&self, key: K, value: V) -> Result<(), Error>
    where
        K: AsRef<[u8]>,
        IVec: From<V>,
    {
        let _ = self.db().insert(key, value)?;
        Ok(())
    }

    fn incr<K>(&self, key: K) -> Result<u32, Error>
    where
        K: AsRef<[u8]>,
    {
        let value = Self::get_u32(&self.db(), &key)?.unwrap_or(0);
        self.db().insert(key, &value.to_le_bytes())?;
        Ok(value)
    }
}

impl PreKeyStore for SledConfigStore {
    fn load(&self, id: u32, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
        writer.write_all(&self.get(self.prekey_key(id)).unwrap().unwrap())
    }

    fn store(&self, id: u32, body: &[u8]) -> Result<(), libsignal_protocol::Error> {
        self.insert(self.prekey_key(id), body).unwrap();
        Ok(())
    }

    fn contains(&self, id: u32) -> bool {
        self.contains(self.prekey_key(id)).unwrap()
    }

    fn remove(&self, id: u32) -> Result<(), libsignal_protocol::Error> {
        self.remove(self.prekey_key(id)).unwrap();
        Ok(())
    }
}

impl SignedPreKeyStore for SledConfigStore {
    fn load(&self, id: u32, writer: &mut dyn std::io::Write) -> std::io::Result<()> {
        writer.write_all(&self.get(self.signed_prekey_key(id)).unwrap().unwrap())
    }

    fn store(&self, id: u32, body: &[u8]) -> Result<(), libsignal_protocol::Error> {
        self.insert(self.signed_prekey_key(id), body).unwrap();
        Ok(())
    }

    fn contains(&self, id: u32) -> bool {
        self.contains(self.signed_prekey_key(id)).unwrap()
    }

    fn remove(&self, id: u32) -> Result<(), libsignal_protocol::Error> {
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
        let key = if let Some(key) = self.session_key(&address) {
            key
        } else {
            return Ok(None);
        };

        trace!("Loading session for {:?} from {:?}", address, key);

        let buf = if let Ok(buf) = self.get(key) {
            buf
        } else {
            return Ok(None);
        };

        Ok(Some(SerializedSession {
            session: Buffer::from(&buf.unwrap()[..]),
            extra_data: None,
        }))
    }

    fn get_sub_device_sessions(
        &self,
        addr: &[u8],
    ) -> Result<Vec<i32>, libsignal_protocol::InternalError> {
        trace!("Getting sub device sessions");
        let ids = self
            .db()
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
        if let Some(key) = self.session_key(&addr) {
            self.db()
                .open_tree("sessions")
                .unwrap()
                .contains_key(key)
                .map_err(|e| libsignal_protocol::Error::Unknown {
                    reason: e.to_string(),
                })
        } else {
            Ok(false)
        }
    }

    fn store_session(
        &self,
        addr: libsignal_protocol::Address,
        session: libsignal_protocol::stores::SerializedSession,
    ) -> Result<(), libsignal_protocol::InternalError> {
        let key = self.session_key(&addr).expect("path for session FIXME");
        trace!("Storing session for {:?} at {:?}", addr, key);
        self.db()
            .open_tree("sessions")
            .unwrap()
            .insert(key, session.session.as_slice())
            .unwrap();
        Ok(())
    }

    fn delete_session(
        &self,
        addr: libsignal_protocol::Address,
    ) -> Result<(), libsignal_protocol::Error> {
        if let Some(key) = self.session_key(&addr) {
            trace!("Deleting session with key: {}", key);
            self.db()
                .open_tree("sessions")
                .unwrap()
                .remove(key)
                .unwrap();
        }
        Ok(())
    }

    fn delete_all_sessions(&self, _name: &[u8]) -> Result<usize, libsignal_protocol::Error> {
        trace!("Deleting all sessions");
        let tree = self.db().open_tree("sessions").unwrap();
        let s = tree.len();
        tree.clear().unwrap();
        Ok(s)
    }
}
