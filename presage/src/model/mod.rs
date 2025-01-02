use libsignal_service::protocol::ServiceIdKind;
use serde::{Deserialize, Serialize};

pub mod contacts;
pub mod groups;
pub mod identity;
pub mod messages;

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

impl From<ServiceIdKind> for ServiceIdType {
    fn from(val: ServiceIdKind) -> Self {
        match val {
            ServiceIdKind::Aci => ServiceIdType::AccountIdentity,
            ServiceIdKind::Pni => ServiceIdType::PhoneNumberIdentity,
        }
    }
}
