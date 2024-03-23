use presage::{libsignal_service::protocol::SignalProtocolError, store::StoreError};

#[derive(Debug, thiserror::Error)]
pub enum SledStoreError {
    #[error("database migration is not supported")]
    MigrationConflict,
    #[error("data store error: {0}")]
    Db(#[from] sled::Error),
    #[error("data store error: {0}")]
    DbTransaction(#[from] sled::transaction::TransactionError),
    #[cfg(feature = "encryption")]
    #[error("store cipher error: {0}")]
    StoreCipher(#[from] presage_store_cipher::StoreCipherError),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Prost error: {0}")]
    ProtobufDecode(#[from] prost::DecodeError),
    #[error("I/O error: {0}")]
    FsExtra(#[from] fs_extra::error::Error),
    #[error("group decryption error")]
    GroupDecryption,
    #[error("No UUID")]
    NoUuid,
    #[error("Unsupported message content")]
    UnsupportedContent,
}

impl StoreError for SledStoreError {}

impl From<SledStoreError> for SignalProtocolError {
    fn from(error: SledStoreError) -> Self {
        log::error!("presage store error: {error}");
        Self::InvalidState("presage store error", error.to_string())
    }
}
