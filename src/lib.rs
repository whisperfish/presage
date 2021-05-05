#![deny(clippy::dbg_macro)]

mod cache;
pub mod config;
mod errors;
mod manager;

pub use crate::errors::Error;
pub use crate::manager::{Manager, State};

/// Re-export of `libsignal-service` crate
pub use libsignal_service;

/// Re-export of Signal protobufs
pub use libsignal_service::proto;

pub mod prelude {
    pub mod service {
        pub use libsignal_service::{
            configuration::SignalServers,
            content::{self, Content, ContentBody, Metadata},
            prelude::{phonenumber, GroupMasterKey, Uuid},
            proto, ServiceAddress,
        };
    }
}

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));
