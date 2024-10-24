use presage::store::StoreError;

#[derive(Debug, thiserror::Error)]
pub enum SqliteStoreError {
    #[error("database migration is not supported")]
    MigrationConflict,
    #[error("data store error: {0}")]
    Db(#[from] sqlx::Error),
}

impl StoreError for SqliteStoreError {}
