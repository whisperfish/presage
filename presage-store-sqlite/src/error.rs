use presage::{libsignal_service::prelude::phonenumber, store::StoreError};
use sqlx::types::uuid;

#[derive(Debug, thiserror::Error)]
pub enum SqliteStoreError {
    #[error("database migration is not supported")]
    MigrationConflict,
    #[error("data store error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("error parsing phonenumber: {0}")]
    PhoneNumber(#[from] phonenumber::ParseError),
    #[error("error parsing UUID: {0}")]
    Uuid(#[from] uuid::Error),

    #[error("failed to convert int: {0}")]
    TryFromInt(#[from] std::num::TryFromIntError),

    #[error("invalid format")]
    InvalidFormat,

    #[error(transparent)]
    Postcard(#[from] postcard::Error),
}

impl StoreError for SqliteStoreError {}
