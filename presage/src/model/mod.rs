use serde::{Deserialize, Serialize};

pub mod contacts;
pub mod groups;

#[derive(Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub enum ServiceIdType {
    /// Account Identity (ACI)
    ///
    /// An account UUID without an associated phone number, probably in the future to a username
    #[default]
    AccountIdentity,
    /// Phone number identity (PNI)
    ///
    /// A UUID associated with a phone number
    PhoneNumberIdentity,
}

impl Into<ServiceIdType> for libsignal_service::ServiceIdType {
    fn into(self) -> ServiceIdType {
        match self {
            libsignal_service::ServiceIdType::AccountIdentity => ServiceIdType::AccountIdentity,
            libsignal_service::ServiceIdType::PhoneNumberIdentity => {
                ServiceIdType::PhoneNumberIdentity
            }
        }
    }
}
