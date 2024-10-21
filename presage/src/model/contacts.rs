use bytes::Bytes;
use libsignal_service::{
    models::Attachment,
    prelude::{phonenumber::PhoneNumber, Uuid},
    proto::Verified,
};
use serde::{Deserialize, Serialize};

const fn default_expire_timer_version() -> u32 {
    2
}

/// Mirror of the protobuf ContactDetails message
/// but with stronger types (e.g. `ServiceAddress` instead of optional uuid and string phone numbers)
/// and some helper functions
#[derive(Debug, Serialize, Deserialize)]
pub struct Contact {
    pub uuid: Uuid,
    pub phone_number: Option<PhoneNumber>,
    pub name: String,
    pub color: Option<String>,
    #[serde(skip)]
    pub verified: Verified,
    pub profile_key: Vec<u8>,
    pub expire_timer: u32,
    #[serde(default = "default_expire_timer_version")]
    pub expire_timer_version: u32,
    pub inbox_position: u32,
    pub archived: bool,
    #[serde(skip)]
    pub avatar: Option<Attachment<Bytes>>,
}

impl From<libsignal_service::models::Contact> for Contact {
    fn from(c: libsignal_service::models::Contact) -> Self {
        Self {
            uuid: c.uuid,
            phone_number: c.phone_number,
            name: c.name,
            color: c.color,
            verified: c.verified,
            profile_key: c.profile_key,
            expire_timer: c.expire_timer,
            expire_timer_version: c.expire_timer_version,
            inbox_position: c.inbox_position,
            archived: c.archived,
            avatar: c.avatar,
        }
    }
}
