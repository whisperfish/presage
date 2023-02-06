use std::borrow::Cow;

use libsignal_service::{
    models::ParseContactError,
    prelude::{protocol::SignalProtocolError, Uuid},
};

#[derive(thiserror::Error, Debug)]
#[non_exhaustive]
pub enum Error {
    #[error("captcha from https://signalcaptchas.org/registration/generate.html required")]
    CaptchaRequired,
    #[error("input/output error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Prost error: {0}")]
    ProstError(#[from] prost::DecodeError),
    #[error("data store error: {0}")]
    DbError(#[from] sled::Error),
    #[error("data store error: {0}")]
    DbTransactionError(#[from] sled::transaction::TransactionError),
    #[error("store cipher error: {0}")]
    StoreCipherError(#[from] matrix_sdk_store_encryption::Error),
    #[error("error decoding base64 data: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("wrong slice size: {0}")]
    TryFromSliceError(#[from] std::array::TryFromSliceError),
    #[error("phone number parsing error: {0}")]
    PhoneNumberError(#[from] libsignal_service::prelude::phonenumber::ParseError),
    #[error("UUID decoding error: {0}")]
    UuidError(#[from] libsignal_service::prelude::UuidError),
    #[error("libsignal-protocol error: {0}")]
    ProtocolError(#[from] SignalProtocolError),
    #[error("libsignal-service error: {0}")]
    ServiceError(#[from] libsignal_service::prelude::ServiceError),
    #[error("libsignal-service error: {0}")]
    ProfileManagerError(#[from] libsignal_service::ProfileManagerError),
    #[error("libsignal-service sending error: {0}")]
    MessageSenderError(#[from] libsignal_service::prelude::MessageSenderError),
    #[error("libsignal-service error: {0}")]
    MessageReceiverError(#[from] libsignal_service::receiver::MessageReceiverError),
    #[error("this client is already registered with Signal")]
    AlreadyRegisteredError,
    #[error("this client is not yet registered, please register or link as a secondary device")]
    NotYetRegisteredError,
    #[error("failed to provision device: {0}")]
    ProvisioningError(#[from] libsignal_service::provisioning::ProvisioningError),
    #[error("no provisioning message received")]
    NoProvisioningMessageReceived,
    #[error("qr code error")]
    LinkError,
    #[error("missing key {0} in config DB")]
    MissingKeyError(Cow<'static, str>),
    #[error("message pipe not started, you need to start receiving messages before you can send anything back")]
    MessagePipeNotStarted,
    #[error("receiving pipe was interrupted")]
    MessagePipeInterruptedError,
    #[error("failed to parse contact information: {0}")]
    ParseContactError(#[from] ParseContactError),
    #[error("failed to decrypt attachment: {0}")]
    AttachmentCipherError(#[from] libsignal_service::attachment_cipher::AttachmentCipherError),
    #[error("message is missing a uuid")]
    ContentMissingUuid,
    #[error("unknown group")]
    UnknownGroup,
    #[error("database migration is not supported")]
    MigrationConflict,
    #[error("I/O error: {0}")]
    FsError(#[from] fs_extra::error::Error),
    #[error("timeout: {0}")]
    Timeout(#[from] tokio::time::error::Elapsed),
}

impl Error {
    pub(crate) fn into_signal_error(self) -> SignalProtocolError {
        SignalProtocolError::InvalidState("presage error", self.to_string())
    }
}
