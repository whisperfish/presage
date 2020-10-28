#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("data store error: {0}")]
    DbError(#[from] sled::Error),
    #[error("libsignal-protocol error: {0}")]
    ProtocolError(#[from] libsignal_protocol::Error),
    #[error("libsignal-service error: {0}")]
    ServiceError(#[from] libsignal_service::prelude::ServiceError),
    #[error("libsignal-service sending error: {0}")]
    MessageSenderError(#[from] libsignal_service::prelude::MessageSenderError),
    #[error("this client is already registered with Signal")]
    AlreadyRegisteredError,
    #[error("this client is not yet registered, please register or link as a secondary device")]
    NotYetRegisteredError,
    #[error("failed to provision device: {0}")]
    ProvisioningError(#[from] libsignal_service::provisioning::ProvisioningError),
    #[error("no provisioning message received")]
    NoProvisioningMessageReceived,
    #[error("qr code error")]
    QrCodeError,
    #[error("missing key {0} in config DB")]
    MissingKeyError(String),
    #[error("receiving pipe was interrupted")]
    MessagePipeInterruptedError,
}
