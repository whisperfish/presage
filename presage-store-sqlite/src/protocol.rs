use async_trait::async_trait;
use chrono::{DateTime, Utc};
use presage::libsignal_service::{
    pre_keys::{KyberPreKeyStoreExt, PreKeysStore},
    prelude::{IdentityKeyStore, SessionStoreExt, Uuid},
    protocol::{
        Direction, IdentityKey, IdentityKeyPair, KyberPreKeyId, KyberPreKeyRecord,
        KyberPreKeyStore, PreKeyId, PreKeyRecord, PreKeyStore, ProtocolAddress, ProtocolStore,
        SenderKeyRecord, SenderKeyStore, ServiceId, SessionRecord, SessionStore,
        SignalProtocolError as ProtocolError, SignedPreKeyId, SignedPreKeyRecord,
        SignedPreKeyStore,
    },
};

use crate::SqliteStore;

#[derive(Clone)]
pub struct SqliteProtocolStore {
    pub(crate) store: SqliteStore,
}

impl ProtocolStore for SqliteProtocolStore {}

#[async_trait(?Send)]
impl SessionStore for SqliteProtocolStore {
    /// Look up the session corresponding to `address`.
    async fn load_session(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<SessionRecord>, ProtocolError> {
        todo!()
    }

    /// Set the entry for `address` to the value of `record`.
    async fn store_session(
        &mut self,
        address: &ProtocolAddress,
        record: &SessionRecord,
    ) -> Result<(), ProtocolError> {
        todo!();
    }
}

#[async_trait(?Send)]
impl SessionStoreExt for SqliteProtocolStore {
    /// Get the IDs of all known sub devices with active sessions for a recipient.
    ///
    /// This should return every device except for the main device [DEFAULT_DEVICE_ID].
    async fn get_sub_device_sessions(
        &self,
        service_id: &ServiceId,
    ) -> Result<Vec<u32>, ProtocolError> {
        todo!()
    }

    /// Remove a session record for a recipient ID + device ID tuple.
    async fn delete_session(&self, address: &ProtocolAddress) -> Result<(), ProtocolError> {
        todo!()
    }

    /// Remove the session records corresponding to all devices of a recipient
    /// ID.
    ///
    /// Returns the number of deleted sessions.
    async fn delete_all_sessions(&self, service_id: &ServiceId) -> Result<usize, ProtocolError> {
        todo!()
    }
}

#[async_trait(?Send)]
impl PreKeyStore for SqliteProtocolStore {
    /// Look up the pre-key corresponding to `prekey_id`.
    async fn get_pre_key(&self, prekey_id: PreKeyId) -> Result<PreKeyRecord, ProtocolError> {
        todo!()
    }

    /// Set the entry for `prekey_id` to the value of `record`.
    async fn save_pre_key(
        &mut self,
        prekey_id: PreKeyId,
        record: &PreKeyRecord,
    ) -> Result<(), ProtocolError> {
        todo!()
    }

    /// Remove the entry for `prekey_id`.
    async fn remove_pre_key(&mut self, prekey_id: PreKeyId) -> Result<(), ProtocolError> {
        todo!()
    }
}

#[async_trait(?Send)]
impl PreKeysStore for SqliteProtocolStore {
    /// ID of the next pre key
    async fn next_pre_key_id(&self) -> Result<u32, ProtocolError> {
        todo!()
    }

    /// ID of the next signed pre key
    async fn next_signed_pre_key_id(&self) -> Result<u32, ProtocolError> {
        todo!()
    }

    /// ID of the next PQ pre key
    async fn next_pq_pre_key_id(&self) -> Result<u32, ProtocolError> {
        todo!()
    }

    /// number of signed pre-keys we currently have in store
    async fn signed_pre_keys_count(&self) -> Result<usize, ProtocolError> {
        todo!()
    }

    /// number of kyber pre-keys we currently have in store
    async fn kyber_pre_keys_count(&self, last_resort: bool) -> Result<usize, ProtocolError> {
        todo!()
    }
}

#[async_trait(?Send)]
impl SignedPreKeyStore for SqliteProtocolStore {
    /// Look up the signed pre-key corresponding to `signed_prekey_id`.
    async fn get_signed_pre_key(
        &self,
        signed_prekey_id: SignedPreKeyId,
    ) -> Result<SignedPreKeyRecord, ProtocolError> {
        todo!()
    }

    /// Set the entry for `signed_prekey_id` to the value of `record`.
    async fn save_signed_pre_key(
        &mut self,
        signed_prekey_id: SignedPreKeyId,
        record: &SignedPreKeyRecord,
    ) -> Result<(), ProtocolError> {
        todo!()
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStore for SqliteProtocolStore {
    /// Look up the signed kyber pre-key corresponding to `kyber_prekey_id`.
    async fn get_kyber_pre_key(
        &self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<KyberPreKeyRecord, ProtocolError> {
        todo!()
    }

    /// Set the entry for `kyber_prekey_id` to the value of `record`.
    async fn save_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), ProtocolError> {
        todo!()
    }

    /// Mark the entry for `kyber_prekey_id` as "used".
    /// This would mean different things for one-time and last-resort Kyber keys.
    async fn mark_kyber_pre_key_used(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), ProtocolError> {
        todo!()
    }
}

#[async_trait(?Send)]
impl KyberPreKeyStoreExt for SqliteProtocolStore {
    async fn store_last_resort_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
        record: &KyberPreKeyRecord,
    ) -> Result<(), ProtocolError> {
        todo!()
    }

    async fn load_last_resort_kyber_pre_keys(
        &self,
    ) -> Result<Vec<KyberPreKeyRecord>, ProtocolError> {
        todo!()
    }

    async fn remove_kyber_pre_key(
        &mut self,
        kyber_prekey_id: KyberPreKeyId,
    ) -> Result<(), ProtocolError> {
        todo!()
    }

    /// Analogous to markAllOneTimeKyberPreKeysStaleIfNecessary
    async fn mark_all_one_time_kyber_pre_keys_stale_if_necessary(
        &mut self,
        stale_time: DateTime<Utc>,
    ) -> Result<(), ProtocolError> {
        todo!()
    }

    /// Analogue of deleteAllStaleOneTimeKyberPreKeys
    async fn delete_all_stale_one_time_kyber_pre_keys(
        &mut self,
        threshold: DateTime<Utc>,
        min_count: usize,
    ) -> Result<(), ProtocolError> {
        todo!()
    }
}

#[async_trait(?Send)]
impl IdentityKeyStore for SqliteProtocolStore {
    /// Return the single specific identity the store is assumed to represent, with private key.
    async fn get_identity_key_pair(&self) -> Result<IdentityKeyPair, ProtocolError> {
        todo!()
    }

    /// Return a [u32] specific to this store instance.
    ///
    /// This local registration id is separate from the per-device identifier used in
    /// [ProtocolAddress] and should not change run over run.
    ///
    /// If the same *device* is unregistered, then registers again, the [ProtocolAddress::device_id]
    /// may be the same, but the store registration id returned by this method should
    /// be regenerated.
    async fn get_local_registration_id(&self) -> Result<u32, ProtocolError> {
        todo!()
    }

    // TODO: make this into an enum instead of a bool!
    /// Record an identity into the store. The identity is then considered "trusted".
    ///
    /// The return value represents whether an existing identity was replaced (`Ok(true)`). If it is
    /// new or hasn't changed, the return value should be `Ok(false)`.
    async fn save_identity(
        &mut self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
    ) -> Result<bool, ProtocolError> {
        todo!()
    }

    /// Return whether an identity is trusted for the role specified by `direction`.
    async fn is_trusted_identity(
        &self,
        address: &ProtocolAddress,
        identity: &IdentityKey,
        direction: Direction,
    ) -> Result<bool, ProtocolError> {
        todo!()
    }

    /// Return the public identity for the given `address`, if known.
    async fn get_identity(
        &self,
        address: &ProtocolAddress,
    ) -> Result<Option<IdentityKey>, ProtocolError> {
        todo!()
    }
}

#[async_trait(?Send)]
impl SenderKeyStore for SqliteProtocolStore {
    /// Assign `record` to the entry for `(sender, distribution_id)`.
    async fn store_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
        // TODO: pass this by value!
        record: &SenderKeyRecord,
    ) -> Result<(), ProtocolError> {
        todo!()
    }

    /// Look up the entry corresponding to `(sender, distribution_id)`.
    async fn load_sender_key(
        &mut self,
        sender: &ProtocolAddress,
        distribution_id: Uuid,
    ) -> Result<Option<SenderKeyRecord>, ProtocolError> {
        todo!()
    }
}
