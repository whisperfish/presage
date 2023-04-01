#![recursion_limit = "512"]

use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use diesel::connection::SimpleConnection;
use diesel::migration::{Migration, MigrationSource};
use diesel::sql_types::{Integer, Text};
use diesel::sqlite::Sqlite;
use diesel::{Connection, Queryable, QueryableByName, SqliteConnection};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};

pub mod error;
mod imp;
mod orm;
pub mod schema;

pub use imp::*;

pub use error::Error;

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!();

// TODO: Encryption
#[derive(Clone)]
pub struct SqliteStore {
    db: Arc<AssertUnwindSafe<Mutex<SqliteConnection>>>,
    path: PathBuf,
}

impl SqliteStore {
    // TODO: Encryption
    pub fn new<P: AsRef<Path>>(path: P) -> Result<SqliteStore, Error> {
        let path = path.as_ref();
        let connection = open_db(path)?;
        Ok(Self {
            db: Arc::new(AssertUnwindSafe(Mutex::new(connection))),
            path: path.to_owned(),
        })
    }

    // TODO: In-Memory Store?
    // TODO: Apply pending migrations.

    pub(crate) fn db(&self) -> MutexGuard<'_, SqliteConnection> {
        self.db.lock().expect("storage is alive")
    }
}

fn open_db<P: AsRef<Path>>(path: P) -> Result<SqliteConnection, Error> {
    let path = path.as_ref();
    let mut db = SqliteConnection::establish(path.join("db").to_str().ok_or(Error::PathNoUTF8)?)?;
    db.batch_execute("PRAGMA foreign_keys = OFF;").unwrap();
    db.transaction::<_, Error, _>(|db| {
        log::trace!("Running pending migrations.",);
        db.run_pending_migrations(MIGRATIONS)
            .map_err(|e| Error::MigrationFailure(e))?;
        crate::check_foreign_keys(db)?;
        Ok(())
    })?;
    db.batch_execute("PRAGMA foreign_keys = ON;").unwrap();
    Ok(db)
}

/// Checks if the db contains foreign key violations.
pub fn check_foreign_keys(db: &mut diesel::SqliteConnection) -> Result<(), Error> {
    use diesel::prelude::*;
    use diesel::sql_types::*;

    log::trace!("Checking foreign keys");

    db.batch_execute("PRAGMA foreign_keys = ON;").unwrap();
    let violations: Vec<ForeignKeyViolation> = diesel::sql_query("PRAGMA main.foreign_key_check;")
        .load(db)
        .unwrap();

    if !violations.is_empty() {
        log::error!("Found foreign key violations: {:#?}", violations);
        Err(Error::ForeignKeyViolations(violations))
    } else {
        Ok(())
    }
}

#[derive(Queryable, QueryableByName, Debug)]
#[allow(dead_code)]
pub struct ForeignKeyViolation {
    #[diesel(sql_type = Text)]
    table: String,
    #[diesel(sql_type = Integer)]
    rowid: i32,
    #[diesel(sql_type = Text)]
    parent: String,
    #[diesel(sql_type = Integer)]
    fkid: i32,
}
