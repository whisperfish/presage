use std::fs::File;

use libsignal_protocol::keys::{PrivateKey, PublicKey};
use serde::Deserialize;

use crate::{Error, manager::State};

use super::ConfigStore;

#[derive(Debug, Deserialize)]
#[serde(rename = "camelCase")]
struct SignalCliConfig {
    username: String,
    uuid: String,
    device_id: Option<i32>,
    is_multi_device: bool,
    password: String,
    registration_lock_pin: Option<bool>,
    signaling_key: String,
    preKey_id_offset: u32,
    next_signed_pre_key_id: u32,
    profile_key: String,
    registered: bool,
    axolotl_store: StoreConfig
}

#[derive(Debug, Deserialize)]
#[serde(rename = "camelCase")]
struct StoreConfig {
    pre_keys: Vec<PreKey>,
    session_store: Vec<Session>,
    identity_key_store: IdentityKeyStore,
}

#[derive(Debug, Deserialize)]
struct PreKey {
    id: u32,
    record: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "camelCase")]
struct Session {
    name: String,
    device_id: Option<u32>,
    record: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename = "camelCase")]
struct IdentityKeyStore {
    registration_id: u32,
    identity_key: String,
    // trusted keys
}

impl SignalCliConfig {
    pub fn new() -> Result<Self, Error> {
        // load the signal-cli configuration file!
        let config: Self = serde_json::from_reader(File::open("/home/gabriel/.local/share/signal-cli/data/+4915172831232").unwrap()).unwrap();
        Ok(config)
    }
}

impl ConfigStore for SignalCliConfig {
    fn state(&self, context: &libsignal_protocol::Context) -> Result<crate::manager::State, crate::Error> {
        let state = if self.registered {
            let mut signaling_key = [0u8; 52];
            signaling_key.copy_from_slice(self.signaling_key.as_bytes());
            // let identity_key = IdentityKey::from_proto();
            State::Registered {
                phone_number: self.username,
                device_id: self.device_id,
                uuid: self.uuid,
                password: self.password,
                signaling_key,
                registration_id: self.axolotl_store.identity_key_store.registration_id,
                // private_key: PrivateKey::decode_point(&context, &self.axolotl_store.identity_key_store.identity_key.as_bytes()[0..32])?,
                // public_key: PublicKey::decode_point(&context, &self.axolotl_store.identity_key_store.identity_key.as_bytes()[32..])?,
                profile_key: base64::decode(self.profile_key).unwrap(),
            }
        } else {
            State::Registration {
            }
        };
        Ok(state)
    }

    fn save(&self, state: &crate::manager::State) -> Result<(), crate::Error> {
        todo!()
    }

    fn pre_keys_offset_id(&self) -> Result<u32, crate::Error> {
        todo!()
    }

    fn set_pre_keys_offset_id(&self, id: u32) -> Result<(), crate::Error> {
        todo!()
    }

    fn next_signed_pre_key_id(&self) -> Result<u32, crate::Error> {
        todo!()
    }

    fn set_next_signed_pre_key_id(&self, id: u32) -> Result<(), crate::Error> {
        todo!()
    }
}