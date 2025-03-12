use async_trait::async_trait;
use chrono::{DateTime, Utc};
use presage::{
    libsignal_service::{
        pre_keys::{KyberPreKeyStoreExt, PreKeysStore},
        prelude::{IdentityKeyStore, SessionStoreExt, Uuid},
        protocol::{
            Direction, GenericSignedPreKey, IdentityKey, IdentityKeyPair, KyberPreKeyId,
            KyberPreKeyRecord, KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore,
            ProtocolAddress, ProtocolStore, SenderKeyRecord, SenderKeyStore, ServiceId,
            SessionRecord, SessionStore, SignalProtocolError, SignedPreKeyId, SignedPreKeyRecord,
            SignedPreKeyStore,
        },
        push_service::DEFAULT_DEVICE_ID,
    },
    model::identity::OnNewIdentity,
    store::StateStore,
};
use sqlx::{query, query_scalar};
use tracing::warn;

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

impl IdentityType {
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
        let device_id: u32 = address.device_id().into();
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
        let device_id: u32 = address.device_id().into();
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
    ) -> Result<Vec<u32>, SignalProtocolError> {
        let address = name.raw_uuid().to_string();
        query_scalar!(
            "SELECT device_id AS 'id: u32' FROM sessions
            WHERE address = ? AND device_id != ? AND identity = ?",
            address,
            DEFAULT_DEVICE_ID,
            self.identity,
        )
        .fetch_all(&self.store.db)
        .await
        .into_protocol_error()
    }

    /// Remove a session record for a recipient ID + device ID tuple.
    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), SignalProtocolError> {
        let device_id: u32 = address.device_id().into();
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
    /// This would mean different things for one-time and last-resort Kyber keys.
    async fn mark_kyber_pre_key_used(
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
    /// The return value represents whether an existing identity was replaced (`Ok(true)`). If it is
    /// new or hasn't changed, the return value should be `Ok(false)`.
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, SignalProtocolError> {
        let device_id: u32 = address.device_id().into();
        let address = address.name();
        let bytes = identity.serialize();

        let mut transaction = self.store.db.begin().await.into_protocol_error()?;

        // Note: It is faster to do the update in a separate query and only insert the record if
        // the update did not do anything.
        let is_replaced = query!(
            "UPDATE identities SET record = ?4
            WHERE address = ?1 AND device_id = ?2 AND identity = ?3",
            address,
            device_id,
            self.identity,
            bytes,
        )
        .execute(&mut *transaction)
        .await
        .into_protocol_error()?
        .rows_affected()
            != 0;

        if !is_replaced {
            query!(
                "INSERT INTO identities (address, device_id, identity, record)
                VALUES (?1, ?2, ?3, ?4)",
                address,
                device_id,
                self.identity,
                bytes,
            )
            .execute(&self.store.db)
            .await
            .into_protocol_error()?;
        }

        transaction.commit().await.into_protocol_error()?;

        Ok(is_replaced)
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
        let device_id: u32 = address.device_id().into();
        let address = address.name();
        query_scalar!(
            "SELECT record FROM identities
            WHERE address = ? AND device_id = ? AND identity = ?",
            address,
            device_id,
            self.identity,
        )
        .fetch_optional(&self.store.db)
        .await
        .into_protocol_error()?
        .map(|bytes| IdentityKey::decode(&bytes))
        .transpose()
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
        let device_id: u32 = sender.device_id().into();
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
        let device_id: u32 = sender.device_id().into();
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
