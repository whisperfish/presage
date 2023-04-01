use std::fmt::{Display, Formatter};

use diesel::ConnectionError;

use crate::ForeignKeyViolation;

#[derive(Debug)]
pub enum Error {
    SqliteConnection(ConnectionError),
    PathNoUTF8,
    ForeignKeyViolations(Vec<ForeignKeyViolation>),
    MigrationFailure(Box<dyn std::error::Error + Send + Sync>),
    Diesel(diesel::result::Error),
}

impl Display for Error {
    fn fmt(&self, fmt: &mut Formatter<'_>) -> Result<(), std::fmt::Error> {
        // TODO: More detailed error.
        write!(fmt, "An error occured")
    }
}

impl From<ConnectionError> for Error {
    fn from(e: ConnectionError) -> Error {
        Self::SqliteConnection(e)
    }
}

impl From<diesel::result::Error> for Error {
    fn from(e: diesel::result::Error) -> Error {
        Self::Diesel(e)
    }
}
