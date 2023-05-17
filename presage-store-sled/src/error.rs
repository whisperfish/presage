use presage::{libsignal_service::prelude::protocol::SignalProtocolError, StoreError};

#[derive(Debug, thiserror::Error)]
pub enum SledStoreError {
    #[error("database migration is not supported")]
    MigrationConflict,
    #[error("data store error: {0}")]
    Db(#[from] sled::Error),
    #[error("data store error: {0}")]
    DbTransaction(#[from] sled::transaction::TransactionError),
    #[error("store cipher error: {0}")]
    StoreCipher(#[from] matrix_sdk_store_encryption::Error),
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

impl SledStoreError {
    pub(crate) fn into_signal_error(self) -> SignalProtocolError {
        SignalProtocolError::InvalidState("presage error", self.to_string())
    }
}
