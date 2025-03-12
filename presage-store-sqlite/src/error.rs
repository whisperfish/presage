use presage::{
    libsignal_service::{prelude::phonenumber, protocol::SignalProtocolError},
    store::StoreError,
};
use tracing::error;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SqliteStoreError {
    #[error(transparent)]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Migrate(#[from] sqlx::migrate::MigrateError),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    Uuid(#[from] uuid::Error),
    #[error(transparent)]
    PhoneNumber(#[from] phonenumber::ParseError),
    #[error("conversation error")]
    InvalidFormat,
}

impl StoreError for SqliteStoreError {}

impl From<SqliteStoreError> for presage::libsignal_service::protocol::SignalProtocolError {
    fn from(error: SqliteStoreError) -> Self {
        error!(%error, "presage sqlite store error");
        Self::InvalidState("presage sqlite store error", error.to_string())
    }
}

pub(crate) trait SqlxErrorExt<T> {
    fn into_protocol_error(self) -> Result<T, SignalProtocolError>;
}

impl<T> SqlxErrorExt<T> for Result<T, sqlx::Error> {
    fn into_protocol_error(self) -> Result<T, SignalProtocolError> {
        self.map_err(|error| SignalProtocolError::InvalidState("sqlite", error.to_string()))
    }
}
