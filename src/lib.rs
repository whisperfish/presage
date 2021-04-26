pub mod config;
mod errors;
mod manager;

pub use crate::errors::Error;
pub use crate::manager::Manager;

pub mod prelude {
    pub use libsignal_service::content::{
        self, sync_message, AttachmentPointer, ContentBody, DataMessage, GroupContextV2, Metadata,
        SyncMessage,
    };
    pub use libsignal_service::prelude::Uuid;
    pub use libsignal_service::ServiceAddress;
}

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));
