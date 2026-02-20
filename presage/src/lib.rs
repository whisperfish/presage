#![warn(clippy::large_futures)]

mod errors;
pub mod manager;
pub mod model;
mod serde;
pub mod store;

pub use libsignal_service;
/// Protobufs used in Signal protocol and service communication
pub use libsignal_service::proto;

pub use errors::Error;
pub use manager::Manager;

const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "-rs-", env!("CARGO_PKG_VERSION"));

pub type AvatarBytes = Vec<u8>;
