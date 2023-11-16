//! Signal manager and its states

mod confirmation;
mod linking;
mod registered;
mod registration;

use std::fmt;

use rand::rngs::StdRng;

pub use self::confirmation::Confirmation;
pub use self::linking::Linking;
pub use self::registered::{ReceivingMode, Registered};
pub use self::registration::{Registration, RegistrationOptions};

/// Signal manager
///
/// The manager is parametrized over the [`crate::store::Store`] which stores the configuration, keys and
/// optionally messages; and over the type state which describes what is the current state of the
/// manager: in registration, linking, TODO
///
/// Depending on the state specific methods are available or not.
#[derive(Clone)]
pub struct Manager<Store, State> {
    /// Implementation of a metadata and messages store
    store: Store,
    /// Part of the manager which is persisted in the store.
    state: State,
    /// Random number generator
    rng: StdRng,
}

impl<Store, State: fmt::Debug> fmt::Debug for Manager<Store, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manager")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose;
    use base64::Engine;
    use libsignal_service::prelude::ProfileKey;
    use libsignal_service::protocol::KeyPair;
    use rand::RngCore;
    use serde_json::json;

    use crate::manager::Registered;

    #[test]
    fn test_state_before_pni() {
        let mut rng = rand::thread_rng();
        let key_pair = KeyPair::generate(&mut rng);
        let mut profile_key = [0u8; 32];
        rng.fill_bytes(&mut profile_key);
        let profile_key = ProfileKey::generate(profile_key);
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        // this is before public_key and private_key were renamed to aci_public_key and aci_private_key
        // and pni_public_key + pni_private_key were added
        let previous_state = json!({
          "signal_servers": "Production",
          "device_name": "Test",
          "phone_number": {
            "code": {
              "value": 1,
              "source": "plus"
            },
            "national": {
              "value": 5550199,
              "zeros": 0
            },
            "extension": null,
            "carrier": null
          },
          "uuid": "ff9a89d9-8052-4af0-a91d-2a0dfa0c6b95",
          "password": "HelloWorldOfPasswords",
          "signaling_key": general_purpose::STANDARD.encode(signaling_key),
          "device_id": 42,
          "registration_id": 64,
          "private_key": general_purpose::STANDARD.encode(key_pair.private_key.serialize()),
          "public_key": general_purpose::STANDARD.encode(key_pair.public_key.serialize()),
          "profile_key": general_purpose::STANDARD.encode(profile_key.get_bytes()),
        });

        let state: Registered = serde_json::from_value(previous_state).expect("should deserialize");
        assert_eq!(state.aci_public_key, key_pair.public_key);
        assert!(state.aci_private_key == key_pair.private_key);
        assert!(state.pni_public_key.is_none());
    }
}
