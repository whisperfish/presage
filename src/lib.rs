mod cache;
mod config;
mod errors;
mod manager;

#[cfg(feature = "sled-store")]
pub use config::sled::SledConfigStore;

pub use config::ConfigStore;
pub use errors::Error;
pub use manager::{Manager, State};

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
