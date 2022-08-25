mod cache;
mod config;
mod errors;
mod manager;
mod proto;

#[cfg(feature = "sled-config-store")]
pub use config::sled::SledConfigStore;

#[cfg(feature = "secret-volatile-config-store")]
pub use config::secret_volatile::SecretVolatileConfigStore;
#[cfg(feature = "volatile-config-store")]
pub use config::volatile::VolatileConfigStore;

pub use config::{ConfigStore, ContactsStore, MessageIdentity, MessageStore, StateStore};
pub use errors::Error;
pub use manager::{Confirmation, Linking, Manager, Registered, Registration, RegistrationOptions};
pub use proto::ContentProto;

#[deprecated(note = "Please help use improve the prelude module instead")]
pub use libsignal_service;

pub mod prelude {
    pub use libsignal_service::{
        configuration::SignalServers,
        content::{
            self, Content, ContentBody, DataMessage, GroupContext, GroupContextV2, GroupType,
            Metadata, SyncMessage,
        },
        models::Contact,
        prelude::{
            phonenumber::{self, PhoneNumber},
            GroupMasterKey, GroupSecretParams, Uuid,
        },
        proto,
        sender::AttachmentSpec,
        ServiceAddress,
    };
}

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));
