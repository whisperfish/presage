pub mod config;
mod errors;
mod manager;

pub use crate::errors::Error;
pub use crate::manager::{Manager, State};

pub mod prelude {
    pub mod service {
        pub use libsignal_service::{
            content::{self, Content, ContentBody, Metadata},
            prelude::{phonenumber, Uuid},
            proto, ServiceAddress,
        };
    }
}

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));
