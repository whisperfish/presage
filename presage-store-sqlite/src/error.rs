use presage::store::StoreError;
use tracing::error;

#[derive(Debug, thiserror::Error)]
pub enum SqliteStoreError {
    #[error("database migration is not supported")]
    MigrationConflict,
    #[error("data store error: {0}")]
    Db(#[from] sqlx::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl StoreError for SqliteStoreError {}

impl From<SqliteStoreError> for presage::libsignal_service::protocol::SignalProtocolError {
    fn from(error: SqliteStoreError) -> Self {
        error!(%error, "presage sqlite store error");
        Self::InvalidState("presage sqlite store error", error.to_string())
    }
}
