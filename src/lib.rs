pub mod config;
mod errors;
mod manager;

pub use crate::errors::Error;
pub use crate::manager::Manager;

pub use libsignal_protocol::Context as ProtocolContext;

pub mod prelude {
    pub use libsignal_protocol::{crypto::DefaultCrypto, Context};
    pub use libsignal_service::content::{
        sync_message, AttachmentPointer, ContentBody, DataMessage, GroupContextV2, Metadata,
        SyncMessage,
    };
}
