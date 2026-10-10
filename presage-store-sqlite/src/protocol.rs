use async_trait::async_trait;
use chrono::{DateTime, Utc};
use presage::{
    libsignal_service::{
        pre_keys::{KyberPreKeyStoreExt, PreKeysStore},
        prelude::{SessionStoreExt, Uuid},
        protocol::{
            CiphertextMessageType, DeviceId, Direction, GenericSignedPreKey, IdentityChange,
            IdentityKey, IdentityKeyPair, IdentityKeyStore, KyberPreKeyId, KyberPreKeyRecord,
            KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, ProtocolStore,
            PublicKey, SenderKeyRecord, SenderKeyStore, ServiceId, SessionRecord, SessionStore,
            SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord, SignedPreKeyStore,
        },
        push_service::DEFAULT_DEVICE_ID,
    },
    model::identity::OnNewIdentity,
    proto::verified,
    store::{StateStore, save_trusted_identity_message},
};
use sqlx::{query, query_scalar};
use tracing::{debug, error, warn};

use crate::{SqliteStore, SqliteStoreError, error::SqlxErrorExt};

#[derive(Clone)]
pub struct SqliteProtocolStore {
    pub(crate) store: SqliteStore,
    pub(crate) identity: IdentityType,
}

#[derive(Debug, Clone, Copy, sqlx::Type)]
#[sqlx(rename_all = "lowercase")]
pub(crate) enum IdentityType {
    Aci,
    Pni,
}

impl SqliteProtocolStore {
    async fn load_identity(
        &self,
        identity: IdentityType,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        let address = address.name();
        query_scalar!(
            "SELECT record FROM identities
            WHERE address = ? AND identity = ?",
            address,
            identity,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|bytes| IdentityKey::decode(&bytes))
        .transpose()
    }

    async fn store_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<(), SignalProtocolError> {
        let address = address.name();
        let bytes = identity.serialize();

        let mut tx = self.store.db.begin().await.into_protocol_error()?;

        // Note: It is faster to do the update in a separate query and only insert the record if
        // the update did not do anything.
        let is_replaced = query!(
            "UPDATE identities SET record = ?3
            WHERE address = ?1 AND identity = ?2",
            address,
            self.identity,
            bytes,
        )
        .execute(&mut *tx)
        .await
        .into_protocol_error()?
        .rows_affected()
            != 0;

        if !is_replaced {
            query!(
                "INSERT INTO identities (address, identity, record)
                VALUES (?1, ?2, ?3)",
                address,
                self.identity,
                bytes,
            )
            .execute(&mut *tx)
            .await
            .into_protocol_error()?;
        }

        tx.commit().await.into_protocol_error().map(drop)
    }

    /// Replaces `old` with `new`; false if it wasn't `old` any more.
    async fn replace_identity(
        &self,
        identity: IdentityType,
        address: &ProtocolAddress,
        old: &IdentityKey,
        new: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        let address = address.name();
        let (old, new) = (old.serialize(), new.serialize());
        query!(
            "UPDATE identities SET record = ?4
            WHERE address = ?1 AND identity = ?2 AND record = ?3",
            address,
            identity,
            old,
            new,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()
        .map(|done| done.rows_affected() != 0)
    }

    /// Sessions on both keys mean libsignal is encrypting with a stale session, not that the
    /// key changed: the session bringing a really new key isn't stored yet.
    async fn is_stale_session(
        &self,
        address: &ProtocolAddress,
        stored: &IdentityKey,
        offered: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        let Some(service_id) = ServiceId::parse_from_service_id_string(address.name()) else {
            return Ok(false);
        };
        let mut devices = self.get_sub_device_sessions(&service_id).await?;
        devices.push(*DEFAULT_DEVICE_ID);
        let (stored, offered) = (stored.serialize(), offered.serialize());
        let (mut on_stored, mut on_offered) = (false, false);
        for device in devices {
            let device = ProtocolAddress::new(address.name().to_owned(), device);
            let Some(session) = self.load_session(&device).await? else {
                continue;
            };
            let key = session.remote_identity_key_bytes()?;
            on_stored |= key.as_deref() == Some(&*stored);
            on_offered |= key.as_deref() == Some(&*offered);
        }
        Ok(on_stored && on_offered)
    }
}

impl IdentityType {
    /// Our other identity: a contact's identity key is the same for both.
    fn other(self) -> Self {
        match self {
            Self::Aci => Self::Pni,
            Self::Pni => Self::Aci,
        }
    }

    pub(crate) fn identity_key_pair_key(&self) -> &'static str {
        match self {
            Self::Aci => "identity_keypair_aci",
            Self::Pni => "identity_keypair_pni",
        }
    }
}

impl ProtocolStore for SqliteProtocolStore {}

#[async_trait(?Send)]
impl SessionStore for SqliteProtocolStore {
    /// Look up the session corresponding to `address`.
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, SignalProtocolError> {
        let device_id: u8 = address.device_id().into();
        let address = address.name();
        query!(
            "SELECT record FROM sessions
            WHERE address = ? AND device_id = ? AND identity = ?",
            address,
            device_id,
            self.identity,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|record| SessionRecord::deserialize(&record.record))
        .transpose()
    }

    /// Set the entry for `address` to the value of `record`.
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), SignalProtocolError> {
        let device_id: u8 = address.device_id().into();
        let address = address.name();
        let record = record.serialize()?;

        let mut transaction = self.store.db.begin().await.into_protocol_error()?;

        // Note: It is faster to do the update in a separate query and only insert the record if
        // the update did not do anything.
        let res = query!(
            "UPDATE sessions SET record = ?4
            WHERE address = ?1 AND device_id = ?2 AND identity = ?3",
            address,
            device_id,
            self.identity,
            record,
        )
        .execute(&mut *transaction)
        .await
        .into_protocol_error()?;

        if res.rows_affected() == 0 {
            query!(
                "INSERT INTO sessions (address, device_id, identity, record)
                VALUES (?1, ?2, ?3, ?4)",
                address,
                device_id,
                self.identity,
                record,
            )
            .execute(&mut *transaction)
            .await
            .into_protocol_error()?;
        }

        transaction.commit().await.into_protocol_error()?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl SessionStoreExt for SqliteProtocolStore {
    /// Get the IDs of all known sub devices with active sessions for a recipient.
    ///
    /// This should return every device except for the main device [DEFAULT_DEVICE_ID].
    async fn get_sub_device_sessions(
        &self,
        name: &ServiceId,
    ) -> Result<Vec<DeviceId>, SignalProtocolError> {
        let address: String = name.raw_uuid().to_string();
        let device_id: u8 = (*DEFAULT_DEVICE_ID).into();
        query_scalar!(
            "SELECT device_id AS 'id: u32' FROM sessions
            WHERE address = ? AND device_id != ? AND identity = ?",
            address,
            device_id,
            self.identity,
        )
        .fetch_all(&self.store.db)
        .await
        .map(|device_ids| {
            device_ids
                .into_iter()
                .filter_map(|device_id| device_id.try_into().ok())
                .collect()
        })
        .into_protocol_error()
    }

    /// Remove a session record for a recipient ID + device ID tuple.
    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), SignalProtocolError> {
        let device_id: u8 = address.device_id().into();
        let address = address.name();
        query!(
            "DELETE FROM sessions WHERE address = ? AND device_id = ? AND identity = ?",
            address,
            device_id,
            self.identity,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Remove the session records corresponding to all devices of a recipient
    /// ID.
    ///
    /// Returns the number of deleted sessions.
    async fn delete_all_sessions(&self, name: &ServiceId) -> Result<usize, SignalProtocolError> {
        let address = name.raw_uuid();
        let res = query!(
            "DELETE FROM sessions WHERE address = ? AND identity = ?",
            address,
            self.identity
        )
        .execute(&self.store.db)
        .await
        .map_err(SqliteStoreError::from)?;
        Ok(res.rows_affected().try_into().expect("usize overflow"))
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SqliteProtocolStore {
    /// Look up the pre-key corresponding to `prekey_id`.
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let record = query_scalar!(
            "SELECT record FROM pre_keys WHERE id = ? AND identity = ?",
            id,
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        PreKeyRecord::deserialize(&record)
    }

    /// Set the entry for `prekey_id` to the value of `record`.
    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        let record = record.serialize()?;
        query!(
            "INSERT INTO pre_keys (id, identity, record)
            VALUES (?1, ?2, ?3)
            ON CONFLICT DO UPDATE SET record = ?3",
            id,
            self.identity,
            record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Remove the entry for `prekey_id`.
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), SignalProtocolError> {
        let id: u32 = prekey_id.into();
        query!(
            "DELETE FROM pre_keys WHERE id = ? AND identity = ?",
            id,
            self.identity
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl PreKeysStore for SqliteProtocolStore {
    /// ID of the next pre key
    async fn next_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        let max_id = query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM pre_keys WHERE identity = ?",
            self.identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(max_id.map(|id| id + 1).unwrap_or(1))
    }

    /// ID of the next signed pre key
    async fn next_signed_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        let max_id = query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM signed_pre_keys WHERE identity = ?",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(max_id.map(|id| id + 1).unwrap_or(1))
    }

    /// ID of the next PQ pre key
    async fn next_pq_pre_key_id(&self) -> Result<u32, SignalProtocolError> {
        let max_id = query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM kyber_pre_keys WHERE identity = ?",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(max_id.map(|id| id + 1).unwrap_or(1))
    }

    /// number of signed pre-keys we currently have in store
    async fn signed_pre_keys_count(&self) -> Result<usize, SignalProtocolError> {
        query_scalar!(
            "SELECT COUNT(id) FROM signed_pre_keys WHERE identity = ?",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()
        .map(|count| count.try_into().expect("invalid usize"))
    }

    /// number of kyber pre-keys we currently have in store
    async fn kyber_pre_keys_count(&self, _last_resort: bool) -> Result<usize, SignalProtocolError> {
        query_scalar!(
            "SELECT COUNT(id) FROM kyber_pre_keys WHERE identity = ?",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()
        .map(|count| count.try_into().expect("invalid usize"))
    }

    async fn signed_prekey_id(&self) -> Result<Option<SignedPreKeyId>, SignalProtocolError> {
        query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM signed_pre_keys WHERE identity = ?",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()
        .map(|id| id.map(From::from))
    }

    async fn last_resort_kyber_prekey_id(
        &self,
    ) -> Result<Option<KyberPreKeyId>, SignalProtocolError> {
        query_scalar!(
            "SELECT MAX(id) AS 'id: u32' FROM kyber_pre_keys
            WHERE identity = ? AND is_last_resort = TRUE",
            self.identity
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()
        .map(|id| id.map(From::from))
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqliteProtocolStore {
    /// Look up the signed pre-key corresponding to `signed_prekey_id`.
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        let bytes = query_scalar!(
            "SELECT record FROM signed_pre_keys WHERE id = ? AND identity = ?",
            id,
            self.identity,
        )
        .fetch_one(&self.store.db)
        .await
        .map_err(SqliteStoreError::from)?;
        SignedPreKeyRecord::deserialize(&bytes)
    }

    /// Set the entry for `signed_prekey_id` to the value of `record`.
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = signed_prekey_id.into();
        let bytes = record.serialize()?;
        query!(
            "INSERT INTO signed_pre_keys (id, identity, record)
            VALUES (?1, ?2, ?3)
            ON CONFLICT DO UPDATE SET record = ?3",
            id,
            self.identity,
            bytes,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SqliteProtocolStore {
    /// Look up the signed kyber pre-key corresponding to `kyber_prekey_id`.
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let bytes = query_scalar!(
            "SELECT record FROM kyber_pre_keys WHERE id = ? AND identity = ?",
            id,
            self.identity,
        )
        .fetch_one(&self.store.db)
        .await
        .into_protocol_error()?;
        KyberPreKeyRecord::deserialize(&bytes)
    }

    /// Set the entry for `kyber_prekey_id` to the value of `record`.
    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let record = record.serialize()?;
        query!(
            "INSERT INTO kyber_pre_keys (id, identity, record)
            VALUES (?1, ?2, ?3)
            ON CONFLICT DO UPDATE SET record = ?3",
            id,
            self.identity,
            record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Mark the entry for `kyber_prekey_id` as "used".
    ///
    /// This means different things for one-time and last-resort Kyber keys.
    /// See the [trait documentation](https://github.com/signalapp/libsignal/blob/eb616f63ed053af83e577f36169f5cb5889bb904/rust/protocol/src/storage/traits.rs#L129), [reference implementation](https://github.com/signalapp/libsignal/blob/eb616f63ed053af83e577f36169f5cb5889bb904/rust/protocol/src/storage/inmem.rs#L247) (and the [comment for it](https://github.com/signalapp/libsignal/blob/eb616f63ed053af83e577f36169f5cb5889bb904/rust/protocol/src/storage/inmem.rs#L196)).
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        ec_prekey_id: SignedPreKeyId,
        base_key: &PublicKey,
    ) -> Result<(), SignalProtocolError> {
        let mut transaction = self.store.db.begin().await.into_protocol_error()?;

        let kyber_prekey_id: u32 = kyber_prekey_id.into();

        // Check whether key is last resort
        let is_last_resort = query_scalar!(
            "SELECT is_last_resort FROM kyber_pre_keys WHERE id = ? and identity = ?",
            kyber_prekey_id,
            self.identity,
        )
        .fetch_one(&mut *transaction)
        .await
        .into_protocol_error()?
            != 0;

        if is_last_resort {
            // Mark last-resort keys as used with the corresponding ec_prekey_id and base_key in base_keys_seen table.

            let ec_prekey_id: u32 = ec_prekey_id.into();
            let base_key = base_key.serialize();

            let result = query!(
                "INSERT INTO base_keys_seen (kyber_pre_key_id, signed_pre_key_id, identity, base_key)
                VALUES (?1, ?2, ?3, ?4)",
                kyber_prekey_id,
                ec_prekey_id,
                self.identity,
                base_key
            )
            .execute(&mut *transaction)
            .await;

            if matches!(result, Err(sqlx::Error::Database(ref e)) if e.kind() == sqlx::error::ErrorKind::UniqueViolation)
            {
                return Err(SignalProtocolError::InvalidMessage(
                    CiphertextMessageType::PreKey,
                    "reused base key".to_owned(),
                ));
            }

            result.into_protocol_error()?;
        } else {
            // Delete only one-time (i.e. non-last-resort) pre keys.
            query!(
                "DELETE FROM kyber_pre_keys WHERE id = ? AND identity = ? AND is_last_resort = FALSE",
                kyber_prekey_id,
                self.identity,
            )
            .execute(&mut *transaction)
            .await
            .into_protocol_error()?;
        }

        transaction.commit().await.into_protocol_error()?;

        Ok(())
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStoreExt for SqliteProtocolStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        let record = record.serialize()?;
        query!(
            "INSERT INTO kyber_pre_keys
            (id, identity, is_last_resort, record)
            VALUES (?1, ?2, TRUE, ?3)
            ON CONFLICT DO UPDATE SET is_last_resort = TRUE, record = ?3",
            id,
            self.identity,
            record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> Result<Vec<KyberPreKeyRecord>, SignalProtocolError> {
        query_scalar!(
            "SELECT record FROM kyber_pre_keys
            WHERE identity = ? AND is_last_resort = TRUE",
            self.identity,
        )
        .fetch_all(&self.store.db)
        .await
        .into_protocol_error()?
        .into_iter()
        .map(|record| KyberPreKeyRecord::deserialize(&record))
        .collect()
    }

    async fn remove_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), SignalProtocolError> {
        let id: u32 = kyber_prekey_id.into();
        query!(
            "DELETE FROM kyber_pre_keys WHERE id = ? AND identity = ?",
            id,
            self.identity,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Analogous to markAllOneTimeKyberPreKeysStaleIfNecessary
    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        _stale_time: DateTime<Utc>,
    ) -> Result<(), SignalProtocolError> {
        unimplemented!("should not be used yet")
    }

    /// Analogue of deleteAllStaleOneTimeKyberPreKeys
    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        _threshold: DateTime<Utc>,
        _min_count: usize,
    ) -> Result<(), SignalProtocolError> {
        unimplemented!("should not be used yet")
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqliteProtocolStore {
    /// Return the single specific identity the store is assumed to represent, with private key.
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, SignalProtocolError> {
        let key = self.identity.identity_key_pair_key();
        let bytes = query_scalar!("SELECT value FROM kv WHERE key = ?", key)
            .fetch_one(&self.store.db)
            .await
            .into_protocol_error()?;
        IdentityKeyPair::try_from(&*bytes)
    }

    /// Return a [u32] specific to this store instance.
    ///
    /// This local registration id is separate from the per-device identifier used in
    /// [ProtocolAddress] and should not change run over run.
    ///
    /// If the same *device* is unregistered, then registers again, the [ProtocolAddress::device_id]
    /// may be the same, but the store registration id returned by this method should
    /// be regenerated.
    async fn get_local_registration_id(&self) -> Result<u32, SignalProtocolError> {
        let data = self.store.load_registration_data().await?.ok_or_else(|| {
            SignalProtocolError::InvalidState(
                "failed to load registration ID",
                "no registration data".into(),
            )
        })?;
        Ok(data.registration_id)
    }

    /// Record an identity into the store. The identity is then considered "trusted".
    ///
    /// Reports [`IdentityChange::ReplacedExisting`], and saves a notice in the thread, only when
    /// the key really changed. Our ACI's and PNI's copies are kept the same.
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<IdentityChange, SignalProtocolError> {
        // Read outside the write transaction: read-then-write can fail to take the lock.
        let ours = self.load_identity(self.identity, address).await?;
        let theirs = self.load_identity(self.identity.other(), address).await?;

        // New, unchanged, or a change already noted when our other identity saw it.
        let known = match ours.or(theirs) {
            Some(known) if ours != Some(*identity) && theirs != Some(*identity) => known,
            _ => {
                if ours != Some(*identity) {
                    self.store_identity(address, identity).await?;
                }
                return Ok(IdentityChange::NewOrUnchanged);
            }
        };

        if self.is_stale_session(address, &known, identity).await? {
            debug!(%address, "not switching back to the identity of a stale session");
            return Ok(IdentityChange::NewOrUnchanged);
        }

        match ours {
            // Of two saves of the same change, only one notes it.
            Some(ours) => {
                if !self
                    .replace_identity(self.identity, address, &ours, identity)
                    .await?
                {
                    return Ok(IdentityChange::NewOrUnchanged);
                }
            }
            None => self.store_identity(address, identity).await?,
        }
        if let Some(theirs) = theirs {
            self.replace_identity(self.identity.other(), address, &theirs, identity)
                .await?;
        }

        warn!(%address, "identity changed");
        // The new key starts out unverified: verification is per (contact, key).
        if let Err(error) =
            save_trusted_identity_message(&self.store, address, *identity, verified::State::Default)
                .await
        {
            // Losing the notice is better than failing to decrypt the message.
            error!(%error, %address, "failed to save the identity change notice");
        }
        Ok(IdentityChange::ReplacedExisting)
    }

    /// Return whether an identity is trusted for the role specified by `direction`.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        _direction: Direction,
    ) -> Result<bool, SignalProtocolError> {
        if let Some(trusted_key) = self.get_identity(address).await? {
            // when we encounter some identity we know, we need to decide whether we trust it or not
            if identity == &trusted_key {
                Ok(true)
            } else {
                match self.store.trust_new_identities {
                    OnNewIdentity::Trust => Ok(true),
                    OnNewIdentity::Reject => Ok(false),
                }
            }
        } else {
            // when we encounter a new identity, we trust it by default
            warn!(%address, "trusting new identity");
            Ok(true)
        }
    }

    /// Return the public identity for the given `address`, if known.
    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, SignalProtocolError> {
        self.load_identity(self.identity, address).await
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for SqliteProtocolStore {
    /// Assign `record` to the entry for `(sender, distribution_id)`.
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        record: &SenderKeyRecord,
    ) -> Result<(), SignalProtocolError> {
        let address = sender.name();
        let device_id: u8 = sender.device_id().into();
        let record = record.serialize()?;
        query!(
            "INSERT INTO sender_keys
            (address, device_id, identity, distribution_id, record)
            VALUES (?1, ?2, ?3, ?4, ?5)
            ON CONFLICT DO UPDATE SET record = ?5",
            address,
            device_id,
            self.identity,
            distribution_id,
            record,
        )
        .execute(&self.store.db)
        .await
        .into_protocol_error()?;
        Ok(())
    }

    /// Look up the entry corresponding to `(sender, distribution_id)`.
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, SignalProtocolError> {
        let address = sender.name();
        let device_id: u8 = sender.device_id().into();
        query_scalar!(
            "SELECT record FROM sender_keys
            WHERE address = ? AND device_id = ? AND identity = ? AND distribution_id = ?",
            address,
            device_id,
            self.identity,
            distribution_id,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|record| SenderKeyRecord::deserialize(&record))
        .transpose()
    }
}

#[cfg(test)]
mod test {
    use presage::libsignal_service::protocol::{KeyPair, KyberPreKeyStore, Timestamp};

    use super::*;

    /// Stores a session with `their` identity, as fetching a pre-key bundle does.
    async fn store_session_with(
        store: &mut SqliteProtocolStore,
        remote: &ProtocolAddress,
        their: &IdentityKeyPair,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use presage::libsignal_service::protocol::{
            InMemSignalProtocolStore, PreKeyBundle, kem, process_prekey_bundle,
        };
        let mut rng = rand::rng();
        let pre_key = KeyPair::generate(&mut rng);
        let signed = KeyPair::generate(&mut rng);
        let signed_signature = their
            .private_key()
            .calculate_signature(&signed.public_key.serialize(), &mut rng)?;
        let kyber = kem::KeyPair::generate(kem::KeyType::Kyber1024, &mut rng);
        let kyber_signature = their
            .private_key()
            .calculate_signature(&kyber.public_key.serialize(), &mut rng)?;
        let bundle = PreKeyBundle::new(
            7,
            remote.device_id(),
            Some((1.into(), pre_key.public_key)),
            2.into(),
            signed.public_key,
            signed_signature.to_vec(),
            3.into(),
            kyber.public_key,
            kyber_signature.to_vec(),
            *their.identity_key(),
        )?;
        let mut us = InMemSignalProtocolStore::new(IdentityKeyPair::generate(&mut rng), 1)?;
        let local = ProtocolAddress::new("us".into(), DeviceId::new(1).unwrap());
        process_prekey_bundle(
            remote,
            &local,
            &mut us.session_store,
            &mut us.identity_store,
            &bundle,
            std::time::SystemTime::now(),
            &mut rng,
        )
        .await?;
        let record = us.load_session(remote).await?.expect("a session");
        store.store_session(remote, &record).await?;
        Ok(())
    }

    async fn notices(store: &SqliteStore, contact: ServiceId) -> usize {
        use presage::store::{ContentsStore, Thread};
        store
            .messages(&Thread::Contact(contact), ..)
            .await
            .unwrap()
            .count()
    }

    /// The notice never takes the place of a message stored at the same millisecond.
    #[tokio::test]
    async fn the_notice_does_not_replace_a_message() -> Result<(), Box<dyn std::error::Error>> {
        use presage::{
            libsignal_service::content::{Content, ContentBody, Metadata},
            proto::DataMessage,
            store::{ContentsStore, Thread},
        };
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut store = SqliteProtocolStore {
            store: sqlite_store.clone(),
            identity: IdentityType::Aci,
        };
        let contact =
            ServiceId::parse_from_service_id_string("9d0652a3-dcc3-4d11-975f-74d61598733f")
                .unwrap();
        let address = ProtocolAddress::new(contact.service_id_string(), DeviceId::new(1).unwrap());
        let thread = Thread::Contact(contact);
        store
            .save_identity(
                &address,
                IdentityKeyPair::generate(&mut rand::rng()).identity_key(),
            )
            .await?;
        // Fill every millisecond of a window starting two seconds from now.
        let start = chrono::Utc::now().timestamp_millis() + 2000;
        const WINDOW: i64 = 300;
        let sqlite = sqlite_store.clone();
        for at in start..start + WINDOW {
            let at = chrono::DateTime::from_timestamp_millis(at).unwrap();
            let message = Content {
                metadata: Metadata {
                    sender: contact,
                    destination: contact,
                    sender_device: DeviceId::new(1).unwrap(),
                    server_guid: None,
                    client_timestamp: at,
                    server_timestamp: at,
                    needs_receipt: false,
                    unidentified_sender: false,
                    was_plaintext: false,
                    pni_verified: None,
                },
                body: ContentBody::DataMessage(DataMessage {
                    body: Some("busy".into()),
                    ..Default::default()
                }),
            };
            sqlite.save_message(&thread, message).await?;
        }
        let wait = start + 10 - chrono::Utc::now().timestamp_millis();
        assert!(
            wait > 0,
            "filling the window took too long for the test to mean anything"
        );
        tokio::time::sleep(std::time::Duration::from_millis(wait as u64)).await;
        store
            .save_identity(
                &address,
                IdentityKeyPair::generate(&mut rand::rng()).identity_key(),
            )
            .await?;
        assert_eq!(
            notices(&sqlite_store, contact).await,
            WINDOW as usize + 1,
            "the messages and the notice"
        );
        Ok(())
    }

    /// Encrypting for an old device's session doesn't switch the stored key back.
    #[tokio::test]
    async fn a_stale_session_does_not_switch_the_identity_back()
    -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut store = SqliteProtocolStore {
            store: sqlite_store.clone(),
            identity: IdentityType::Aci,
        };
        let contact =
            ServiceId::parse_from_service_id_string("9d0652a3-dcc3-4d11-975f-74d61598733f")
                .unwrap();
        let phone = ProtocolAddress::new(contact.service_id_string(), DeviceId::new(1).unwrap());
        let laptop = ProtocolAddress::new(contact.service_id_string(), DeviceId::new(2).unwrap());
        let old = IdentityKeyPair::generate(&mut rand::rng());
        let new = IdentityKeyPair::generate(&mut rand::rng());

        // Their laptop, on the old key; then a message from their reinstalled phone.
        store_session_with(&mut store, &laptop, &old).await?;
        store.save_identity(&laptop, old.identity_key()).await?;
        assert_eq!(
            store.save_identity(&phone, new.identity_key()).await?,
            IdentityChange::ReplacedExisting
        );
        // Decrypting it stores the phone's new session.
        store_session_with(&mut store, &phone, &new).await?;
        // We answer: encrypting for the laptop's stale session saves its (old) key.
        assert_eq!(
            store.save_identity(&laptop, old.identity_key()).await?,
            IdentityChange::NewOrUnchanged
        );
        assert_eq!(store.get_identity(&phone).await?, Some(*new.identity_key()));
        assert_eq!(notices(&sqlite_store, contact).await, 1);
        Ok(())
    }

    /// A stale stored key gives way once its session is dropped.
    #[tokio::test]
    async fn a_stale_stored_identity_gives_way() -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut store = SqliteProtocolStore {
            store: sqlite_store.clone(),
            identity: IdentityType::Aci,
        };
        let contact =
            ServiceId::parse_from_service_id_string("9d0652a3-dcc3-4d11-975f-74d61598733f")
                .unwrap();
        let phone = ProtocolAddress::new(contact.service_id_string(), DeviceId::new(1).unwrap());
        let laptop = ProtocolAddress::new(contact.service_id_string(), DeviceId::new(2).unwrap());
        let old = IdentityKeyPair::generate(&mut rand::rng());
        let new = IdentityKeyPair::generate(&mut rand::rng());

        // Stored: the old key, with sessions on both.
        store_session_with(&mut store, &laptop, &old).await?;
        store_session_with(&mut store, &phone, &new).await?;
        store.save_identity(&laptop, old.identity_key()).await?;
        // Ambiguous while both sessions exist: the stored key stays.
        store.save_identity(&phone, new.identity_key()).await?;
        assert_eq!(store.get_identity(&phone).await?, Some(*old.identity_key()));
        // The laptop is gone (the server answered 409/410 and its session was dropped).
        store.delete_session(&laptop).await?;
        assert_eq!(
            store.save_identity(&phone, new.identity_key()).await?,
            IdentityChange::ReplacedExisting
        );
        assert_eq!(store.get_identity(&phone).await?, Some(*new.identity_key()));
        Ok(())
    }

    /// One key change is one notice, whichever of our identities sees it.
    #[tokio::test]
    async fn a_change_seen_by_both_our_identities_is_noted_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut aci = SqliteProtocolStore {
            store: sqlite_store.clone(),
            identity: IdentityType::Aci,
        };
        let mut pni = SqliteProtocolStore {
            store: sqlite_store.clone(),
            identity: IdentityType::Pni,
        };
        let contact =
            ServiceId::parse_from_service_id_string("9d0652a3-dcc3-4d11-975f-74d61598733f")
                .unwrap();
        let address = ProtocolAddress::new(contact.service_id_string(), DeviceId::new(1).unwrap());
        let old = *IdentityKeyPair::generate(&mut rand::rng()).identity_key();
        let new = *IdentityKeyPair::generate(&mut rand::rng()).identity_key();

        aci.save_identity(&address, &old).await?;
        pni.save_identity(&address, &old).await?;
        assert_eq!(
            aci.save_identity(&address, &new).await?,
            IdentityChange::ReplacedExisting
        );
        // Weeks later they write to our PNI.
        assert_eq!(
            pni.save_identity(&address, &new).await?,
            IdentityChange::NewOrUnchanged
        );
        assert_eq!(pni.get_identity(&address).await?, Some(new));
        assert_eq!(notices(&sqlite_store, contact).await, 1);
        Ok(())
    }

    #[tokio::test]
    async fn changed_identity_leaves_one_notice() -> Result<(), Box<dyn std::error::Error>> {
        use presage::{
            libsignal_service::content::ContentBody,
            libsignal_service::proto::sync_message::Content as SyncContent,
            store::{ContentsStore, Thread},
        };

        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut store = SqliteProtocolStore {
            store: sqlite_store.clone(),
            identity: IdentityType::Aci,
        };
        let contact =
            ServiceId::parse_from_service_id_string("9d0652a3-dcc3-4d11-975f-74d61598733f")
                .unwrap();
        let address = ProtocolAddress::new(contact.service_id_string(), DeviceId::new(1).unwrap());
        let first = *IdentityKeyPair::generate(&mut rand::rng()).identity_key();
        let second = *IdentityKeyPair::generate(&mut rand::rng()).identity_key();

        store.save_identity(&address, &first).await?;
        store.save_identity(&address, &first).await?;
        store.save_identity(&address, &second).await?;
        store.save_identity(&address, &second).await?;

        let notices: Vec<_> = sqlite_store
            .messages(&Thread::Contact(contact), ..)
            .await?
            .collect::<Result<_, _>>()?;
        assert_eq!(notices.len(), 1, "one notice, for the one real change");
        let ContentBody::SynchronizeMessage(sync) = &notices[0].body else {
            panic!("the notice is a sync message");
        };
        let Some(SyncContent::Verified(verified)) = &sync.content else {
            panic!("the notice is a Verified sync message");
        };
        assert_eq!(
            verified.identity_key.as_deref(),
            Some(&*second.public_key().serialize()),
            "it names the new key"
        );
        assert_eq!(verified.destination_aci, None, "not a real Verified sync");
        Ok(())
    }

    #[tokio::test]
    async fn save_identity_reports_only_real_changes() -> Result<(), Box<dyn std::error::Error>> {
        let mut store = SqliteProtocolStore {
            store: SqliteStore::open(":memory:", OnNewIdentity::Trust).await?,
            identity: IdentityType::Aci,
        };
        let address = ProtocolAddress::new(
            "9d0652a3-dcc3-4d11-975f-74d61598733f".into(),
            DeviceId::new(1).unwrap(),
        );
        let first = *IdentityKeyPair::generate(&mut rand::rng()).identity_key();
        let second = *IdentityKeyPair::generate(&mut rand::rng()).identity_key();

        // A new contact, then the same key again: nothing was replaced.
        assert_eq!(
            store.save_identity(&address, &first).await?,
            IdentityChange::NewOrUnchanged
        );
        assert_eq!(
            store.save_identity(&address, &first).await?,
            IdentityChange::NewOrUnchanged
        );
        // Their key changed (e.g. they reinstalled Signal).
        assert_eq!(
            store.save_identity(&address, &second).await?,
            IdentityChange::ReplacedExisting
        );
        assert_eq!(store.get_identity(&address).await?, Some(second));
        assert_eq!(
            store.save_identity(&address, &second).await?,
            IdentityChange::NewOrUnchanged
        );
        Ok(())
    }

    #[tokio::test]
    async fn kyber_pre_keys_mark_used_one_time() -> Result<(), Box<dyn std::error::Error>> {
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut protocol_store = SqliteProtocolStore {
            store: sqlite_store,
            identity: IdentityType::Aci,
        };

        let id = KyberPreKeyId::from(0);
        let keypair = KeyPair::generate(&mut rand::rng());
        let record = KyberPreKeyRecord::generate(
            presage::libsignal_service::protocol::kem::KeyType::Kyber1024,
            id,
            &keypair.private_key,
        )?;
        let ec_prekey_id = SignedPreKeyId::from(1);

        protocol_store.save_kyber_pre_key(id, &record).await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_ok());
        protocol_store
            .mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
            .await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_err());

        Ok(())
    }

    #[tokio::test]
    async fn kyber_pre_keys_mark_used_last_resort() -> Result<(), Box<dyn std::error::Error>> {
        let mut rng = rand::rng();
        let sqlite_store = SqliteStore::open(":memory:", OnNewIdentity::Trust).await?;
        let mut protocol_store = SqliteProtocolStore {
            store: sqlite_store,
            identity: IdentityType::Aci,
        };

        let id = KyberPreKeyId::from(0);
        let keypair = KeyPair::generate(&mut rand::rng());

        // Signed pre key
        let ec_pre_key_pair = KeyPair::generate(&mut rng);
        let ec_pre_key_signature = keypair
            .private_key
            .calculate_signature(&ec_pre_key_pair.public_key.serialize(), &mut rng)?;
        let ec_prekey_id = SignedPreKeyId::from(1);
        let ec_prekey_record = SignedPreKeyRecord::new(
            ec_prekey_id,
            Timestamp::from_epoch_millis(1760968452908),
            &ec_pre_key_pair,
            &ec_pre_key_signature,
        );

        // Kyber pre key
        let kyber_pre_key_record = KyberPreKeyRecord::generate(
            presage::libsignal_service::protocol::kem::KeyType::Kyber1024,
            id,
            &keypair.private_key,
        )?;

        protocol_store
            .save_signed_pre_key(ec_prekey_id, &ec_prekey_record)
            .await?;

        protocol_store
            .store_last_resort_kyber_pre_key(id, &kyber_pre_key_record)
            .await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_ok());
        protocol_store
            .mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
            .await?;
        assert!(protocol_store.get_kyber_pre_key(id).await.is_ok());
        assert!(
            protocol_store
                .mark_kyber_pre_key_used(id, ec_prekey_id, &keypair.public_key)
                .await
                .is_err()
        );

        Ok(())
    }
}
