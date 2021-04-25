use std::borrow::Cow;

use libsignal_service::models::ParseContactError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("captcha from https://signalcaptchas.org required")]
    CaptchaRequired,
    #[error("input/output error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("data store error: {0}")]
    DbError(#[from] sled::Error),
    #[error("error decoding base64 data: {0}")]
    Base64Error(#[from] base64::DecodeError),
    #[error("phone number parsing error: {0}")]
    PhoneNumberError(#[from] libsignal_service::prelude::phonenumber::ParseError),
    #[error("UUID decoding error: {0}")]
    UuidError(#[from] libsignal_service::prelude::UuidError),
    #[error("libsignal-protocol error: {0}")]
    ProtocolError(#[from] libsignal_protocol::Error),
    #[error("libsignal-service error: {0}")]
    ServiceError(#[from] libsignal_service::prelude::ServiceError),
    #[error("libsignal-service error: {0}")]
    ProfileManagerError(#[from] libsignal_service::ProfileManagerError),
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
    MissingKeyError(Cow<'static, str>),
    #[error("receiving pipe was interrupted")]
    MessagePipeInterruptedError,
    #[error("failed to parse contact information: {0}")]
    ParseContactError(#[from] ParseContactError),
}
