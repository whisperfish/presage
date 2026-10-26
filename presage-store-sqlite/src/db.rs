//! Where a query runs: on the pool, or in a transaction that the store's clones share.

use std::{
    fmt,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use futures::{
    StreamExt, TryStreamExt,
    future::BoxFuture,
    lock::{Mutex, OwnedMutexGuard},
    stream::{self, BoxStream},
};
use sqlx::{
    Describe, Either, Execute, Executor, SqlStr, Sqlite, SqliteConnection, SqlitePool, Transaction,
    sqlite::{SqliteQueryResult, SqliteRow, SqliteStatement, SqliteTypeInfo},
};

#[derive(Clone)]
pub(crate) enum Db {
    Pool(SqlitePool),
    /// Every query in one transaction, until it is taken out to be committed.
    Transaction(SharedTransaction),
}

pub(crate) type SharedTransaction = Arc<Mutex<Option<Transaction<'static, Sqlite>>>>;

impl fmt::Debug for Db {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pool(pool) => f.debug_tuple("Pool").field(pool).finish(),
            Self::Transaction(_) => f.write_str("Transaction"),
        }
    }
}

impl Db {
    /// Begins a transaction that writes, taking the write lock at once. A deferred transaction
    /// that reads before it writes fails with `SQLITE_BUSY`, which no busy timeout waits out,
    /// when another connection to the database writes in between.
    pub(crate) async fn begin_write(&self) -> Result<Write, sqlx::Error> {
        match self {
            Self::Pool(pool) => Ok(Write::Own(pool.begin_with("BEGIN IMMEDIATE").await?)),
            // The writes join the shared transaction, which already holds the write lock.
            Self::Transaction(transaction) => Ok(Write::Shared(locked(transaction).await?)),
        }
    }
}

/// The shared transaction, while nobody else uses it.
async fn locked(
    transaction: &SharedTransaction,
) -> Result<OwnedMutexGuard<Option<Transaction<'static, Sqlite>>>, sqlx::Error> {
    let guard = transaction.clone().lock_owned().await;
    if guard.is_none() {
        return Err(sqlx::Error::Protocol(
            "a clone of the store outlived its committed transaction".into(),
        ));
    }
    Ok(guard)
}

/// The transaction of [`Db::begin_write`]: its own, or a part of the shared one, which
/// [`Write::commit`] leaves to the shared one's commit.
pub(crate) enum Write {
    Own(Transaction<'static, Sqlite>),
    Shared(OwnedMutexGuard<Option<Transaction<'static, Sqlite>>>),
}

impl Write {
    pub(crate) async fn commit(self) -> Result<(), sqlx::Error> {
        match self {
            Self::Own(transaction) => transaction.commit().await,
            Self::Shared(_) => Ok(()),
        }
    }
}

impl Deref for Write {
    type Target = SqliteConnection;

    fn deref(&self) -> &SqliteConnection {
        match self {
            Self::Own(transaction) => transaction,
            Self::Shared(guard) => guard.as_ref().expect("checked when locked"),
        }
    }
}

impl DerefMut for Write {
    fn deref_mut(&mut self) -> &mut SqliteConnection {
        match self {
            Self::Own(transaction) => transaction,
            Self::Shared(guard) => guard.as_mut().expect("checked when locked"),
        }
    }
}

impl<'c> Executor<'c> for &'c Db {
    type Database = Sqlite;

    fn fetch_many<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxStream<'e, Result<Either<SqliteQueryResult, SqliteRow>, sqlx::Error>>
    where
        'c: 'e,
        E: 'q + Execute<'q, Sqlite>,
    {
        match self {
            Db::Pool(pool) => pool.fetch_many(query),
            // All at once, so that the transaction isn't held between two items.
            Db::Transaction(transaction) => stream::once(async move {
                let mut guard = locked(transaction).await?;
                let connection: &mut SqliteConnection = guard.as_mut().expect("checked");
                connection.fetch_many(query).try_collect::<Vec<_>>().await
            })
            .map_ok(|results| stream::iter(results.into_iter().map(Ok)))
            .try_flatten()
            .boxed(),
        }
    }

    fn fetch_optional<'e, 'q: 'e, E>(
        self,
        query: E,
    ) -> BoxFuture<'e, Result<Option<SqliteRow>, sqlx::Error>>
    where
        'c: 'e,
        E: 'q + Execute<'q, Sqlite>,
    {
        match self {
            Db::Pool(pool) => pool.fetch_optional(query),
            Db::Transaction(transaction) => Box::pin(async move {
                let mut guard = locked(transaction).await?;
                let connection: &mut SqliteConnection = guard.as_mut().expect("checked");
                connection.fetch_optional(query).await
            }),
        }
    }

    fn prepare_with<'e>(
        self,
        sql: SqlStr,
        parameters: &'e [SqliteTypeInfo],
    ) -> BoxFuture<'e, Result<SqliteStatement, sqlx::Error>>
    where
        'c: 'e,
    {
        match self {
            Db::Pool(pool) => pool.prepare_with(sql, parameters),
            Db::Transaction(transaction) => Box::pin(async move {
                let mut guard = locked(transaction).await?;
                let connection: &mut SqliteConnection = guard.as_mut().expect("checked");
                connection.prepare_with(sql, parameters).await
            }),
        }
    }

    fn describe<'e>(self, sql: SqlStr) -> BoxFuture<'e, Result<Describe<Sqlite>, sqlx::Error>>
    where
        'c: 'e,
    {
        match self {
            Db::Pool(pool) => pool.describe(sql),
            Db::Transaction(transaction) => Box::pin(async move {
                let mut guard = locked(transaction).await?;
                let connection: &mut SqliteConnection = guard.as_mut().expect("checked");
                connection.describe(sql).await
            }),
        }
    }
}
