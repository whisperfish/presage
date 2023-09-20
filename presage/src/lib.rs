mod cache;
mod errors;
mod manager;
mod serializers;
use serde::{Deserialize, Serialize};
mod store;

pub use errors::Error;
pub use manager::{Confirmation, Linking, Manager, Registered, Registration, RegistrationOptions};
pub use store::{Store, StoreError, Thread};

#[deprecated(note = "Please help use improve the prelude module instead")]
pub use libsignal_service;

pub mod prelude {
    pub use libsignal_service::{
        configuration::SignalServers,
        content::{
            self, Content, ContentBody, DataMessage, GroupContext, GroupContextV2, GroupType,
            Metadata, SyncMessage,
        },
        groups_v2::{AccessControl, Group, GroupChange, PendingMember, RequestingMember, Timer},
        models::Contact,
        prelude::{
            phonenumber::{self, PhoneNumber},
            GroupMasterKey, GroupSecretParams, Uuid,
        },
        proto,
        sender::AttachmentSpec,
        ParseServiceAddressError, ServiceAddress,
    };
}

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

// TODO: open a PR in libsignal and make sure the bytes can be read from `GroupMasterKey` instead of using this type
pub type GroupMasterKeyBytes = [u8; 32];

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ThreadMetadata {
    pub thread: Thread,
    pub last_message: Option<ThreadMetadataMessageContent>,
    pub unread_messages_count: usize,
    pub title: Option<String>,
    pub archived: bool,
    pub muted: bool,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct ThreadMetadataMessageContent {
    pub sender: prelude::Uuid,
    pub timestamp: u64,
    pub message: Option<String>,

}