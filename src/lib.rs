pub mod config;
mod errors;
mod manager;

pub use crate::errors::Error;
pub use crate::manager::Manager;

pub use libsignal_protocol::Context as ProtocolContext;