use std::ops::RangeBounds;

use super::SqliteStore;

use p::prelude::*;
use p::{
    ContactsStore, Error, GroupsStore, MessageStore, ProfilesStore, Registered, StateStore, Store,
    Thread,
};
use presage as p;

use async_trait::async_trait;
use diesel::prelude::*;

use libsignal_service::groups_v2::Group as GroupV2;
use libsignal_service::{
    models::Contact,
    prelude::{
        protocol::{
            Context, Direction, IdentityKey, IdentityKeyPair, IdentityKeyStore, PreKeyId,
            PreKeyRecord, PreKeyStore, ProtocolAddress, SenderKeyRecord, SenderKeyStore,
            SessionRecord, SessionStore, SessionStoreExt, SignalProtocolError, SignedPreKeyId,
            SignedPreKeyRecord, SignedPreKeyStore,
        },
        Content, ProfileKey, Uuid,
    },
    Profile,
};

impl Store for SqliteStore {
    fn clear_registration(&mut self) -> Result<(), Error> {
        log::error!("Clear registration currently not implemented!");
        Ok(())
    }

    fn clear(&mut self) -> Result<(), Error> {
        log::error!("Clearing currently not implemented!");
        Ok(())
    }

    fn pre_keys_offset_id(&self) -> Result<u32, Error> {
        log::trace!("Loading pre_keys_offset_id");
        use crate::schema::states::dsl::*;

        let data: crate::orm::State = states
            .filter(id.eq(0))
            .first(&mut *self.db())
            .optional()
            .expect("db")
            .ok_or(Error::NotYetRegisteredError)?;
        Ok(data.pre_keys_offset_id as u32)
    }

    fn set_pre_keys_offset_id(&mut self, pre_keys_offset: u32) -> Result<(), Error> {
        log::trace!("Setting pre_keys_offset_id");
        use crate::schema::states::dsl::*;
        diesel::update(states.filter(id.eq(0)))
            .set(pre_keys_offset_id.eq(pre_keys_offset as i32))
            .execute(&mut *self.db())
            .expect("db");
        Ok(())
    }

    fn next_signed_pre_key_id(&self) -> Result<u32, Error> {
        log::trace!("Loading next_signed_pre_key_id");
        use crate::schema::states::dsl::*;

        let data: crate::orm::State = states
            .filter(id.eq(0))
            .first(&mut *self.db())
            .optional()
            .expect("db")
            .ok_or(Error::NotYetRegisteredError)?;
        Ok(data.next_signed_pre_key_id as u32)
    }

    fn set_next_signed_pre_key_id(&mut self, pre_key_id: u32) -> Result<(), Error> {
        log::trace!("Setting next_signed_pre_key_id");
        use crate::schema::states::dsl::*;
        diesel::update(states.filter(id.eq(0)))
            .set(next_signed_pre_key_id.eq(pre_key_id as i32))
            .execute(&mut *self.db())
            .expect("db");
        Ok(())
    }
}

impl StateStore<Registered> for SqliteStore {
    fn load_state(&self) -> Result<Registered, Error> {
        log::trace!("Loading state");
        use crate::schema::states::dsl::*;

        let data: crate::orm::State = states
            .filter(id.eq(0))
            .first(&mut *self.db())
            .optional()
            .expect("db")
            .ok_or(Error::NotYetRegisteredError)?;
        Ok(serde_json::from_slice(&data.registration)?)
    }

    fn save_state(&mut self, state: &Registered) -> Result<(), Error> {
        log::trace!("Loading state");
        use crate::schema::states::dsl::*;

        diesel::insert_into(states)
            .values(crate::orm::State {
                id: 0,
                registration: serde_json::to_vec(state)?,
                pre_keys_offset_id: 0,
                next_signed_pre_key_id: 0,
            })
            .execute(&mut *self.db())
            .expect("db");

        Ok(())
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SqliteStore {
    async fn get_pre_key(
        &self,
        prekey_id: PreKeyId,
        _ctx: Context,
    ) -> Result<PreKeyRecord, SignalProtocolError> {
        log::trace!("Loading prekey {}", prekey_id);
        use crate::schema::prekeys::dsl::*;

        let prekey_record: Option<crate::orm::Prekey> = prekeys
            .filter(id.eq(u32::from(prekey_id) as i32))
            .first(&mut *self.db())
            .optional()
            .expect("db");
        if let Some(pkr) = prekey_record {
            Ok(PreKeyRecord::deserialize(&pkr.record)?)
        } else {
            Err(SignalProtocolError::InvalidPreKeyId)
        }
    }

    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        body: &PreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        log::trace!("Storing prekey {}", prekey_id);
        use crate::schema::prekeys::dsl::*;

        diesel::insert_into(prekeys)
            .values(crate::orm::Prekey {
                id: u32::from(prekey_id) as _,
                record: body.serialize()?,
            })
            .execute(&mut *self.db())
            .expect("db");

        Ok(())
    }

    async fn remove_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        log::trace!("Removing prekey {}", prekey_id);
        use crate::schema::prekeys::dsl::*;

        diesel::delete(prekeys)
            .filter(id.eq(u32::from(prekey_id) as i32))
            .execute(&mut *self.db())
            .expect("db");
        Ok(())
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqliteStore {
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
        _ctx: Context,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        log::trace!("Loading signed prekey {}", signed_prekey_id);
        use crate::schema::signed_prekeys::dsl::*;

        let prekey_record: Option<crate::orm::SignedPrekey> = signed_prekeys
            .filter(id.eq(u32::from(signed_prekey_id) as i32))
            .first(&mut *self.db())
            .optional()
            .expect("db");
        if let Some(pkr) = prekey_record {
            Ok(SignedPreKeyRecord::deserialize(&pkr.record)?)
        } else {
            Err(SignalProtocolError::InvalidSignedPreKeyId)
        }
    }

    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        body: &SignedPreKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        log::trace!("Storing prekey {}", signed_prekey_id);
        use crate::schema::signed_prekeys::dsl::*;

        // Insert or replace?
        diesel::insert_into(signed_prekeys)
            .values(crate::orm::SignedPrekey {
                id: u32::from(signed_prekey_id) as _,
                record: body.serialize()?,
            })
            .execute(&mut *self.db())
            .expect("db");

        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStore for SqliteStore {
    async fn load_session(
        &self,
        addr: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        log::trace!("Loading session for {:?}", addr);
        use crate::schema::session_records::dsl::*;

        let session_record: Option<crate::orm::SessionRecord> = session_records
            .filter(
                address
                    .eq(addr.name())
                    .and(device_id.eq(u32::from(addr.device_id()) as i32)),
            )
            .first(&mut *self.db())
            .optional()
            .expect("db");
        if let Some(session_record) = session_record {
            Ok(Some(SessionRecord::deserialize(&session_record.record)?))
        } else {
            Ok(None)
        }
    }

    async fn store_session(
        &mut self,
        addr: &ProtocolAddress,
        session: &SessionRecord,
        context: Context,
    ) -> Result<(), SignalProtocolError> {
        log::trace!("Storing session for {:?}", addr);
        use crate::schema::session_records::dsl::*;

        if self.contains_session(addr, context).await? {
            diesel::update(session_records)
                .filter(
                    address
                        .eq(addr.name())
                        .and(device_id.eq(u32::from(addr.device_id()) as i32)),
                )
                .set(record.eq(session.serialize()?))
                .execute(&mut *self.db())
                .expect("updated session");
        } else {
            diesel::insert_into(session_records)
                .values((
                    address.eq(addr.name()),
                    device_id.eq(u32::from(addr.device_id()) as i32),
                    record.eq(session.serialize()?),
                ))
                .execute(&mut *self.db())
                .expect("updated session");
        }

        Ok(())
    }
}

#[async_trait]
impl SessionStoreExt for SqliteStore {
    async fn get_sub_device_sessions(
        &self,
        addr: &ServiceAddress,
    ) -> Result<Vec<u32>, SignalProtocolError> {
        log::trace!("Looking for sub_device sessions for {:?}", addr);
        use crate::schema::session_records::dsl::*;

        let records: Vec<i32> = session_records
            .select(device_id)
            .filter(
                address
                    .eq(addr.uuid.to_string())
                    .and(device_id.ne(libsignal_service::push_service::DEFAULT_DEVICE_ID as i32)),
            )
            .load(&mut *self.db())
            .expect("db");
        Ok(records.into_iter().map(|x| x as u32).collect())
    }

    async fn delete_session(&self, addr: &ProtocolAddress) -> Result<(), SignalProtocolError> {
        use crate::schema::session_records::dsl::*;

        let num = diesel::delete(session_records)
            .filter(
                address
                    .eq(addr.name())
                    .and(device_id.eq(u32::from(addr.device_id()) as i32)),
            )
            .execute(&mut *self.db())
            .expect("db");

        if num != 1 {
            log::debug!(
                "Could not delete session {}, assuming non-existing.",
                addr.to_string(),
            );
            Err(SignalProtocolError::SessionNotFound(addr.clone()))
        } else {
            Ok(())
        }
    }

    async fn delete_all_sessions(
        &self,
        addr: &ServiceAddress,
    ) -> Result<usize, SignalProtocolError> {
        log::warn!("Deleting all sessions for {:?}", addr);
        use crate::schema::session_records::dsl::*;

        let num = diesel::delete(session_records)
            .filter(address.eq(addr.uuid.to_string()))
            .execute(&mut *self.db())
            .expect("db");

        Ok(num)
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqliteStore {
    async fn get_identity_key_pair(
        &self,
        _ctx: Context,
    ) -> Result<IdentityKeyPair, SignalProtocolError> {
        log::trace!("Getting identity_key_pair");
        let state = self.load_state().map_err(|e| {
            SignalProtocolError::InvalidState("failed to load presage state", e.to_string())
        })?;
        Ok(IdentityKeyPair::new(
            IdentityKey::new(state.public_key()),
            state.private_key(),
        ))
    }

    async fn get_local_registration_id(&self, _ctx: Context) -> Result<u32, SignalProtocolError> {
        let state = self.load_state().map_err(|e| {
            SignalProtocolError::InvalidState("failed to load presage state", e.to_string())
        })?;
        Ok(state.registration_id())
    }

    async fn save_identity(
        &mut self,
        addr: &ProtocolAddress,
        key: &IdentityKey,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        Ok(self.store_identity_key(addr, key))
    }

    async fn is_trusted_identity(
        &self,
        addr: &ProtocolAddress,
        key: &IdentityKey,
        _direction: Direction,
        _ctx: Context,
    ) -> Result<bool, SignalProtocolError> {
        if let Some(trusted_key) = self.fetch_identity_key(addr) {
            Ok(trusted_key == *key)
        } else {
            // Trust on first use
            Ok(true)
        }
    }

    async fn get_identity(
        &self,
        addr: &ProtocolAddress,
        _ctx: Context,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        Ok(self.fetch_identity_key(addr))
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for SqliteStore {
    async fn store_sender_key(
        &mut self,
        addr: &ProtocolAddress,
        distr_id: Uuid,
        record: &SenderKeyRecord,
        _ctx: Context,
    ) -> Result<(), SignalProtocolError> {
        log::trace!("Storing sender key {} {}", addr, distr_id);

        let to_insert = crate::orm::SenderKeyRecord {
            address: addr.name().to_owned(),
            device: u32::from(addr.device_id()) as i32,
            distribution_id: distr_id.to_string(),
            record: record.serialize()?,
            created_at: chrono::Utc::now().naive_utc(),
        };

        {
            use crate::schema::sender_key_records::dsl::*;
            diesel::insert_into(sender_key_records)
                .values(to_insert)
                .execute(&mut *self.db())
                .expect("db");
        }
        Ok(())
    }

    async fn load_sender_key(
        &mut self,
        addr: &ProtocolAddress,
        distr_id: Uuid,
        _ctx: Context,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        log::trace!("Loading sender key {} {}", addr, distr_id);

        let found: Option<crate::orm::SenderKeyRecord> = {
            use crate::schema::sender_key_records::dsl::*;
            sender_key_records
                .filter(
                    address
                        .eq(addr.name())
                        .and(device.eq(u32::from(addr.device_id()) as i32))
                        .and(distribution_id.eq(distr_id.to_string())),
                )
                .first(&mut *self.db())
                .optional()
                .expect("db")
        };

        match found {
            Some(x) => Ok(Some(SenderKeyRecord::deserialize(&x.record)?)),
            None => Ok(None),
        }
    }
}

impl ContactsStore for SqliteStore {
    type ContactsIter = std::iter::Empty<Result<Contact, Error>>;

    fn clear_contacts(&mut self) -> Result<(), Error> {
        log::error!("Contacts currently not implemented");
        Ok(())
    }

    fn save_contacts(&mut self, _: impl Iterator<Item = Contact>) -> Result<(), Error> {
        log::error!("Contacts currently not implemented");
        Ok(())
    }

    fn contacts(&self) -> Result<Self::ContactsIter, Error> {
        log::error!("Contacts currently not implemented");
        Ok(std::iter::empty())
    }

    fn contact_by_id(&self, _: Uuid) -> Result<Option<Contact>, Error> {
        log::error!("Contacts currently not implemented");
        Ok(None)
    }
}

impl MessageStore for SqliteStore {
    type MessagesIter = std::iter::Empty<Result<Content, Error>>;

    fn clear_messages(&mut self) -> Result<(), Error> {
        log::error!("Messages currently not implemented");
        Ok(())
    }

    fn save_message(&mut self, _thread: &Thread, _message: Content) -> Result<(), Error> {
        log::error!("Messages currently not implemented");
        Ok(())
    }

    fn delete_message(&mut self, _thread: &Thread, _timestamp: u64) -> Result<bool, Error> {
        log::error!("Messages currently not implemented");
        Ok(false)
    }

    fn message(&self, _thread: &Thread, _timestamp: u64) -> Result<Option<Content>, Error> {
        log::error!("Messages currently not implemented");
        Ok(None)
    }

    fn messages(
        &self,
        _thread: &Thread,
        _range: impl RangeBounds<u64>,
    ) -> Result<Self::MessagesIter, Error> {
        log::error!("Messages currently not implemented");
        Ok(std::iter::empty())
    }
}

impl GroupsStore for SqliteStore {
    type GroupsIter = std::iter::Empty<Result<([u8; 32], GroupV2), Error>>;

    fn clear_groups(&mut self) -> Result<(), Error> {
        log::error!("Groups currently not implemented");
        Ok(())
    }

    fn groups(&self) -> Result<Self::GroupsIter, Error> {
        log::error!("Groups currently not implemented");
        Ok(std::iter::empty())
    }

    fn group(&self, _master_key: &[u8]) -> Result<Option<GroupV2>, Error> {
        log::error!("Groups currently not implemented");
        Ok(None)
    }

    fn save_group(&self, _master_key: &[u8], _group: proto::Group) -> Result<(), Error> {
        log::error!("Groups currently not implemented");
        Ok(())
    }
}

impl ProfilesStore for SqliteStore {
    fn save_profile(
        &mut self,
        _uuid: Uuid,
        _key: ProfileKey,
        _profile: Profile,
    ) -> Result<(), Error> {
        log::error!("Profiles currently not implemented");
        Ok(())
    }

    fn profile(&self, _uuid: Uuid, _key: ProfileKey) -> Result<Option<Profile>, Error> {
        log::error!("Profiles currently not implemented");
        Ok(None)
    }
}

impl SqliteStore {
    /// Check whether session exists.
    ///
    /// This does *not* lock the protocol store.  If a transactional check is required, use the
    /// lock from outside.
    async fn contains_session(
        &self,
        addr: &ProtocolAddress,
        _: Context,
    ) -> Result<bool, SignalProtocolError> {
        use crate::schema::session_records::dsl::*;
        use diesel::dsl::*;

        let count: i64 = session_records
            .select(count_star())
            .filter(
                address
                    .eq(addr.name())
                    .and(device_id.eq(u32::from(addr.device_id()) as i32)),
            )
            .first(&mut *self.db())
            .expect("db");
        Ok(count != 0)
    }

    /// Fetches the identity matching `addr` from the database
    ///
    /// Does not lock the protocol storage.
    fn fetch_identity_key(&self, addr: &ProtocolAddress) -> Option<IdentityKey> {
        use crate::schema::identity_records::dsl::*;
        let addr = addr.name();
        let found: crate::orm::IdentityRecord = identity_records
            .filter(address.eq(addr))
            .first(&mut *self.db())
            .optional()
            .expect("db")?;

        Some(IdentityKey::decode(&found.record).expect("only valid identity keys in db"))
    }

    /// Removes the identity matching `addr` from the database
    ///
    /// Does not lock the protocol storage.
    pub fn delete_identity_key(&self, addr: &ProtocolAddress) -> bool {
        use crate::schema::identity_records::dsl::*;
        let addr = addr.name();
        let amount = diesel::delete(identity_records)
            .filter(address.eq(addr))
            .execute(&mut *self.db())
            .expect("db");

        amount == 1
    }

    /// (Over)writes the identity key for a given address.
    ///
    /// Returns whether the identity key has been altered.
    fn store_identity_key(&self, addr: &ProtocolAddress, key: &IdentityKey) -> bool {
        use crate::schema::identity_records::dsl::*;
        let previous = self.fetch_identity_key(addr);

        let ret = previous.as_ref() == Some(key);

        if previous.is_some() {
            diesel::update(identity_records)
                .filter(address.eq(addr.name()))
                .set(record.eq(key.serialize().to_vec()))
                .execute(&mut *self.db())
                .expect("db");
        } else {
            diesel::insert_into(identity_records)
                .values((address.eq(addr.name()), record.eq(key.serialize().to_vec())))
                .execute(&mut *self.db())
                .expect("db");
        }

        ret
    }
}
