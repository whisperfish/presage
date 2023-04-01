use crate::schema::*;
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
