use crate::schema::*;
use chrono::NaiveDateTime;
use diesel::{Identifiable, Insertable, Queryable};

#[derive(Insertable, Queryable, Debug, Clone)]
pub struct State {
    pub id: i32,
    pub registration: Vec<u8>,
    pub pre_keys_offset_id: i32,
    pub next_signed_pre_key_id: i32,
}

#[derive(Insertable, Queryable, Identifiable, Debug, Clone)]
pub struct Prekey {
    pub id: i32,
    pub record: Vec<u8>,
}

#[derive(Queryable, Identifiable, Insertable, Debug, Clone)]
pub struct SignedPrekey {
    pub id: i32,
    pub record: Vec<u8>,
}

#[derive(Queryable, Identifiable, Insertable, Debug, Clone)]
#[diesel(primary_key(address, device_id))]
pub struct SessionRecord {
    pub address: String,
    pub device_id: i32,
    pub record: Vec<u8>,
}

#[derive(Queryable, Identifiable, Insertable, Debug, Clone)]
#[diesel(primary_key(address, device, distribution_id))]
pub struct SenderKeyRecord {
    pub address: String,
    pub device: i32,
    pub distribution_id: String,
    pub record: Vec<u8>,
    pub created_at: chrono::NaiveDateTime,
}

#[derive(Queryable, Identifiable, Insertable, Debug, Clone)]
#[diesel(primary_key(address))]
pub struct IdentityRecord {
    pub address: String,
    pub record: Vec<u8>,
}

#[derive(Queryable, Identifiable, Debug, Clone)]
pub struct Recipient {
    pub id: i32,
    pub e164: Option<String>,
    pub uuid: Option<String>,
    pub username: Option<String>,
    pub email: Option<String>,
    pub blocked: bool,

    pub profile_key: Option<Vec<u8>>,
    pub profile_key_credential: Option<Vec<u8>>,

    pub profile_given_name: Option<String>,
    pub profile_family_name: Option<String>,
    pub profile_joined_name: Option<String>,
    pub signal_profile_avatar: Option<String>,
    pub profile_sharing: bool,

    pub last_profile_fetch: Option<NaiveDateTime>,
    pub unidentified_access_mode: bool,

    pub storage_service_id: Option<Vec<u8>>,
    pub storage_proto: Option<Vec<u8>>,

    pub capabilities: i32,
    pub last_session_reset: Option<NaiveDateTime>,

    pub about: Option<String>,
    pub about_emoji: Option<String>,
}
