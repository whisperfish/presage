use bytes::Bytes;
use libsignal_service::{
    models::Attachment,
    prelude::{phonenumber::PhoneNumber, Uuid},
    proto::{contact_record::IdentityState, verified, ContactRecord, Verified},
    utils::phonenumber_from_signal,
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
    #[serde(skip)]
    pub verified: Verified,
    pub profile_key: Vec<u8>,
    pub expire_timer: u32,
    #[serde(default = "default_expire_timer_version")]
    pub expire_timer_version: u32,
    pub inbox_position: u32,
    #[serde(skip)]
    pub avatar: Option<Attachment<Bytes>>,
}

impl From<libsignal_service::models::Contact> for Contact {
    fn from(c: libsignal_service::models::Contact) -> Self {
        Self {
            uuid: c.uuid,
            phone_number: c.phone_number.as_ref().map(phonenumber_from_signal),
            name: c.name,
            verified: Default::default(),
            profile_key: Default::default(),
            expire_timer: c.expire_timer,
            expire_timer_version: c.expire_timer_version,
            inbox_position: c.inbox_position,
            avatar: c.avatar,
        }
    }
}

impl Contact {
    /// Builds a contact from a storage service record, keeping the local-only fields of `existing`.
    ///
    /// Returns `None` for records without an ACI.
    pub fn from_contact_record(record: &ContactRecord, existing: Option<Contact>) -> Option<Self> {
        let uuid = contact_record_aci(record)?;

        let identity_state = match record.identity_state() {
            IdentityState::Default => verified::State::Default,
            IdentityState::Verified => verified::State::Verified,
            IdentityState::Unverified => verified::State::Unverified,
        };
        let verified = Verified {
            destination_aci: Some(uuid.to_string()),
            identity_key: Some(record.identity_key.clone()).filter(|key| !key.is_empty()),
            state: Some(identity_state.into()),
            ..Default::default()
        };

        let existing = existing.filter(|contact| contact.uuid == uuid);
        Some(Self {
            uuid,
            phone_number: record.e164.parse().ok(),
            name: display_name(record),
            verified,
            profile_key: record.profile_key.clone(),
            expire_timer: existing.as_ref().map_or(0, |c| c.expire_timer),
            expire_timer_version: existing
                .as_ref()
                .map_or_else(default_expire_timer_version, |c| c.expire_timer_version),
            inbox_position: existing.as_ref().map_or(0, |c| c.inbox_position),
            avatar: existing.and_then(|c| c.avatar),
        })
    }
}

pub(crate) fn contact_record_aci(record: &ContactRecord) -> Option<Uuid> {
    Uuid::from_slice(&record.aci_binary)
        .ok()
        .or_else(|| Uuid::parse_str(&record.aci).ok())
}

// Same precedence as Signal-Android's `Recipient.getDisplayName`.
fn display_name(record: &ContactRecord) -> String {
    let nickname = record
        .nickname
        .as_ref()
        .map(|name| full_name(&name.given, &name.family))
        .unwrap_or_default();
    [
        nickname,
        full_name(&record.system_given_name, &record.system_family_name),
        full_name(&record.given_name, &record.family_name),
        record.e164.clone(),
        record.username.clone(),
    ]
    .into_iter()
    .find(|name| !name.is_empty())
    .unwrap_or_default()
}

fn full_name(given: &str, family: &str) -> String {
    match (given.trim(), family.trim()) {
        (given, "") => given.to_owned(),
        ("", family) => family.to_owned(),
        (given, family) => format!("{given} {family}"),
    }
}

#[cfg(test)]
mod tests {
    use libsignal_service::proto::contact_record::Name;

    use super::*;

    fn record(aci: Uuid) -> ContactRecord {
        ContactRecord {
            aci_binary: aci.as_bytes().to_vec(),
            e164: "+41791234567".into(),
            given_name: "Profile".into(),
            family_name: "Name".into(),
            system_given_name: "System".into(),
            username: "user.01".into(),
            ..Default::default()
        }
    }

    #[test]
    fn display_name_precedence() {
        let mut record = record(Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0));
        record.nickname = Some(Name {
            given: "Nick".into(),
            family: String::new(),
        });
        assert_eq!(display_name(&record), "Nick");

        record.nickname = None;
        assert_eq!(display_name(&record), "System");

        record.system_given_name.clear();
        assert_eq!(display_name(&record), "Profile Name");

        record.given_name.clear();
        record.family_name.clear();
        assert_eq!(display_name(&record), "+41791234567");

        record.e164.clear();
        assert_eq!(display_name(&record), "user.01");
    }

    #[test]
    fn keeps_local_fields() {
        let aci = Uuid::from_u128(0x1234_5678_9abc_def0_1234_5678_9abc_def0);
        let existing = Contact {
            uuid: aci,
            phone_number: None,
            name: "old".into(),
            verified: Default::default(),
            profile_key: Vec::new(),
            expire_timer: 3600,
            expire_timer_version: 7,
            inbox_position: 3,
            avatar: None,
        };
        let contact = Contact::from_contact_record(&record(aci), Some(existing)).unwrap();
        assert_eq!(contact.name, "System");
        assert_eq!(contact.expire_timer, 3600);
        assert_eq!(contact.expire_timer_version, 7);
        assert_eq!(contact.inbox_position, 3);
        assert!(contact.phone_number.is_some());
    }

    #[test]
    fn skips_records_without_aci() {
        let record = ContactRecord {
            pni: "PNI:00000000-0000-0000-0000-000000000000".into(),
            ..Default::default()
        };
        assert!(Contact::from_contact_record(&record, None).is_none());
    }
}
