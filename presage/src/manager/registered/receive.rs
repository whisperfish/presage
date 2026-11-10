use std::collections::HashMap;
use std::pin::Pin;
use std::str::FromStr;

use futures::{future, Stream, StreamExt};
use libsignal_service::{
    cipher::SealedSenderDecryptionError,
    content::{sync_message::request::Type as RequestType, Content, ContentBody},
    envelope::Envelope,
    groups_v2::{GroupsManager, InMemoryCredentialsCache},
    libsignal_account_keys::AccountEntropyPool,
    messagepipe::{Incoming, MessagePipe},
    prelude::ServiceError,
    proto::{
        receipt_message,
        sync_message::{
            self, sticker_pack_operation, Content as SyncContent, StickerPackOperation,
        },
        DataMessage, GroupContextV2, StoryMessage, SyncMessage,
    },
    protocol::ServiceId,
    sender::ContactDetails,
    websocket::{self, SignalWebSocket},
    AccountManager,
};
use rand::rng;
use tracing::{debug, error, info, trace, warn};

use self::origin::{Origin, OwnSync};
use super::{
    blocked_sync_message, delivery_receipt_timestamp, download_sticker_pack, is_blocked,
    register_pre_keys, save_message, set_account_attributes, sync_from_storage_service,
    upsert_group, MessageSender, Registered, RegistrationType,
};
use crate::model::messages::Received;
use crate::store::Store;
use crate::{Error, Manager};

impl<S: Store> Manager<S, Registered> {
    /// Starts receiving and storing messages.
    ///
    /// As a client, it is heavily recommended to process incoming messages and wait for the `Received::QueueEmpty` messages
    /// until giving the ability for users to send messages. That way, all possible updates (sessions, profile keys, sender keys)
    /// are processed _before_ trying to encrypt and send messages, which might get rejected by recipients otherwise.
    ///
    /// Returns a [futures::Stream] of messages to consume. Messages will also be stored by the implementation of the [Store].
    pub async fn receive_messages(
        &mut self,
    ) -> Result<impl Stream<Item = Received>, Error<S::Error>> {
        // NB: here, we initialise a *fresh* Signal websocket, which means any other use of the previous one will go into nirvana
        let identified_websocket = self.identified_websocket(true).await?;

        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            identified_websocket.clone(),
            None,
        );

        let store_inner = self.store.clone();
        let registration_data_inner = self.registration_data().clone();

        // We make a task to update the account attributes and refresh pre keys as needed that will
        // only yield a value if one of the two operations fail (stop signal).
        //
        // This is necessary because in this context, we can't do the classic tokio::spawn with a
        // oneshot::channel() or CancellationToken because of !Send constraints in the Store.
        let refresh_registration_task = async move {
            if let Err(error) =
                set_account_attributes(&mut account_manager, &store_inner, &registration_data_inner)
                    .await
            {
                error!(%error, "failed to set account attributes, this is problematic and should never happen!");
            }

            if let Err(error) = register_pre_keys(&store_inner, &mut account_manager).await {
                error!(%error, "failed to register pre-keys, this is problematic and should never happen!");
            }

            // Never return, which keeps the messages stream alive.
            future::pending::<()>().await
        };

        let receiver = Receiver::new(self.clone(), identified_websocket).await?;

        debug!("starting to consume incoming message stream");

        // The next envelope is read only when the stream is polled.
        let incoming_messages_stream = futures::stream::unfold(receiver, |mut receiver| async {
            let received = receiver.next().await?;
            Some((received, receiver))
        });

        Ok(Box::pin(
            // We use the returning of the async closure in take_until as a stop signal
            // if the future resolves *anything* the stream will end.
            incoming_messages_stream.take_until(refresh_registration_task),
        ))
    }
}

/// Decrypts, handles and stores what the message pipe brings, one envelope at a time.
struct Receiver<S: Store> {
    manager: Manager<S, Registered>,
    encrypted_messages: Pin<Box<dyn Stream<Item = Result<Incoming, ServiceError>> + Send>>,
    groups_manager: GroupsManager<InMemoryCredentialsCache>,
    message_sender: MessageSender<S::AciStore>,
    /// Delivery receipts batched while the queued messages are drained.
    ///
    /// NB: not persisted; receipts still pending when the stream is dropped are lost.
    pending_delivery_receipts: HashMap<ServiceId, Vec<u64>>,
    pending_delivery_receipts_count: usize,
    queue_empty: bool,
}

// Same batch size as Signal-Android's `IncomingMessageObserver`.
const DELIVERY_RECEIPT_BATCH_SIZE: usize = 30;

impl<S: Store> Receiver<S> {
    async fn new(
        manager: Manager<S, Registered>,
        identified_websocket: SignalWebSocket<websocket::Identified>,
    ) -> Result<Self, Error<S::Error>> {
        Ok(Self {
            encrypted_messages: Box::pin(MessagePipe::from_socket(identified_websocket).stream()),
            groups_manager: Box::pin(manager.groups_manager()).await?,
            message_sender: manager.new_message_sender().await?,
            pending_delivery_receipts: HashMap::new(),
            pending_delivery_receipts_count: 0,
            queue_empty: false,
            manager,
        })
    }

    /// The next thing to tell the client, `None` once the message pipe has ended.
    async fn next(&mut self) -> Option<Received> {
        loop {
            match self.encrypted_messages.next().await {
                Some(Ok(Incoming::Envelope(envelope))) => {
                    if let Some(received) = self.handle_envelope(envelope).await {
                        return Some(received);
                    }
                }
                Some(Ok(Incoming::QueueEmpty)) => return Some(self.handle_queue_empty().await),
                Some(Err(error)) => {
                    error!(%error, "unexpected error in message receiving loop")
                }
                None => return None,
            }
        }
    }

    async fn handle_envelope(&mut self, envelope: Envelope) -> Option<Received> {
        let opened = match envelope.parse_destination_service_id() {
            None => {
                warn!("Message has no destination service ID, dropping.");
                return None;
            }
            Some(ServiceId::Aci(_)) => {
                self.manager
                    .new_service_cipher_aci()
                    .open_envelope(envelope, &mut rng())
                    .await
            }
            Some(ServiceId::Pni(pni)) => {
                if pni == self.manager.state.data.service_ids.pni()
                    && envelope.parse_source_service_id().is_none()
                {
                    warn!("Got a sealed sender message to our PNI? Invalid message, ignoring.");
                    return None;
                }
                self.manager
                    .new_service_cipher_pni()
                    .open_envelope(envelope, &mut rng())
                    .await
            }
        };
        match opened {
            Ok(Some(content)) => self.handle_content(content).await,
            Ok(None) => {
                debug!("empty envelope, message will be skipped!");
                None
            }
            Err(error) => {
                error!(%error, "error opening envelope, message will be skipped!");
                if let ServiceError::SealedSenderDecryptionError(SealedSenderDecryptionError {
                    sender: Some(sender),
                    ..
                }) = &error
                {
                    if let Some(sender) = ServiceId::parse_from_service_id_string(sender.name()) {
                        return Some(Received::DecryptionError(sender));
                    }
                }
                None
            }
        }
    }

    async fn handle_content(&mut self, content: Content) -> Option<Received> {
        match is_blocked(&self.manager.store, &content).await {
            Ok(true) => {
                debug!(sender = %content.metadata.sender.service_id_string(), "dropping message from blocked contact or group");
                return None;
            }
            Ok(false) => {}
            Err(error) => {
                warn!(%error, "failed to check blocked state")
            }
        }

        if let ContentBody::DecryptionErrorMessage(e) = &content.body {
            error!(
                error = ?e,
                "got error decrypting a message"
            );
            return Some(Received::DecryptionError(content.metadata.sender));
        }

        match Origin::of(&content.metadata, &self.manager.state.data.service_ids) {
            Origin::Unauthenticated => {
                warn!(
                    sender = %content.metadata.sender.service_id_string(),
                    "dropping plaintext content that is no decryption error"
                );
                return None;
            }
            Origin::Peer if matches!(content.body, ContentBody::SynchronizeMessage(_)) => {
                warn!(
                    sender = %content.metadata.sender.service_id_string(),
                    "dropping a sync message from another account"
                );
                return None;
            }
            origin => {
                if let Some(sync) = origin.own_sync(&content.body) {
                    self.handle_sync(sync).await;
                }
            }
        }

        self.handle_group_context(&content).await;

        if let Some(timestamp) = delivery_receipt_timestamp(&content) {
            self.queue_delivery_receipt(content.metadata.sender, timestamp);
        }

        let saved = match self.manager.identified_websocket(false).await {
            Ok(mut websocket) => {
                save_message(
                    &mut self.manager.store,
                    &mut websocket,
                    content.clone(),
                    None,
                )
                .await
            }
            Err(error) => Err(error),
        };
        if let Err(error) = saved {
            error!(%error, "error saving message to store");
        }

        Some(Received::Content(Box::new(content)))
    }

    /// What only our own devices may ask.
    async fn handle_sync(&mut self, sync: OwnSync<'_>) {
        if let Some(SyncContent::Request(request)) = &sync.content {
            self.handle_sync_request(request).await;
        }

        for operation in &sync.sticker_pack_operation {
            self.handle_sticker_pack_operation(operation).await;
        }

        match &sync.content {
            // key synchronization sent from the primary device
            Some(SyncContent::Keys(keys)) => self.handle_keys(keys).await,
            Some(SyncContent::Configuration(configuration)) => {
                self.handle_configuration(configuration).await
            }
            // The primary device told us to fetch stuff again from the storage service.
            Some(SyncContent::FetchLatest(fetch_latest)) => {
                self.handle_fetch_latest(fetch_latest).await
            }
            _ => {}
        }
    }

    async fn handle_sync_request(&mut self, request: &sync_message::Request) {
        match request.r#type() {
            RequestType::Contacts => {
                let contacts = self
                    .manager
                    .store
                    .contacts()
                    .await
                    .map(|i| i.collect::<Result<Vec<_>, _>>().unwrap_or_default())
                    .unwrap_or_default();

                let mut message_sender = self.message_sender.clone();
                let aci = self.manager.state.data.service_ids.aci();
                tokio::task::spawn_local(async move {
                    let result = message_sender
                        .send_contact_details(
                            &ServiceId::Aci(aci),
                            None,
                            contacts.into_iter().map(|c| ContactDetails {
                                number: c.phone_number.map(|p| p.to_string()),
                                aci: Some(c.uuid.to_string()),
                                aci_binary: Some(c.uuid.into_bytes().into()),
                                name: Some(c.name),
                                // send_contact_details doesn't write avatar data yet.
                                avatar: None,
                                expire_timer: Some(c.expire_timer),
                                expire_timer_version: Some(c.expire_timer_version),
                                inbox_position: None,
                            }),
                            false,
                            true,
                        )
                        .await;

                    if let Err(error) = result {
                        warn!(%error, "Error sending contact details to other devices");
                    }
                });
            }
            RequestType::Keys => {
                let mut message_sender = self.message_sender.clone();
                let account_entropy_pool = match self.manager.account_entropy_pool().await {
                    Ok(aep) => aep.map(|aep| aep.to_string()),
                    Err(error) => {
                        warn!(%error, "failed to load account entropy pool");
                        None
                    }
                };
                tokio::task::spawn_local(async move {
                    let result = message_sender
                        .send_sync_message(SyncMessage {
                            content: Some(SyncContent::Keys(sync_message::Keys {
                                account_entropy_pool,
                                media_root_backup_key: None,
                            })),
                            ..SyncMessage::with_padding(&mut rand::rng())
                        })
                        .await;

                    if let Err(error) = result {
                        warn!(%error, "Error sending keys to other devices");
                    }
                });
            }
            RequestType::Blocked => {
                let blocked = match self.manager.store.blocked().await {
                    Ok(blocked) => blocked,
                    Err(error) => {
                        warn!(%error, "failed to load blocked contacts and groups");
                        Vec::new()
                    }
                };
                let mut message_sender = self.message_sender.clone();
                tokio::task::spawn_local(async move {
                    let result = message_sender
                        .send_sync_message(SyncMessage {
                            content: Some(SyncContent::Blocked(blocked_sync_message(&blocked))),
                            ..SyncMessage::with_padding(&mut rand::rng())
                        })
                        .await;

                    if let Err(error) = result {
                        warn!(%error, "Error sending blocked contacts to other devices");
                    }
                });
            }
            t => {
                info!(type = ?t, "Got sync request of currently unhandled type")
            }
        }
    }

    async fn handle_sticker_pack_operation(&mut self, operation: &StickerPackOperation) {
        match operation.r#type() {
            sticker_pack_operation::Type::Install => {
                // the primary resends every installed pack on a configuration request
                match self
                    .manager
                    .store
                    .has_sticker_pack(operation.pack_id())
                    .await
                {
                    Ok(true) => {
                        debug!("sticker pack already installed");
                        return;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        warn!(%error, "failed to look up sticker pack, downloading it")
                    }
                }
                let store = self.manager.store.clone();
                let unidentified_websocket = match self.manager.unidentified_websocket().await {
                    Ok(ws) => ws,
                    Err(error) => {
                        warn!(%error, "failed to open unidentified websocket, skipping sticker pack");
                        return;
                    }
                };
                let operation = operation.clone();

                // download stickers in the background
                tokio::spawn(async move {
                    match download_sticker_pack(store, unidentified_websocket, &operation).await {
                        Ok(sticker_pack) => {
                            debug!(
                                "downloaded sticker pack: {} made by {}",
                                sticker_pack.manifest.title, sticker_pack.manifest.author
                            );
                        }
                        Err(error) => error!(
                            %error,
                            "failed to download sticker pack"
                        ),
                    }
                });
            }
            sticker_pack_operation::Type::Remove => {
                match self
                    .manager
                    .store
                    .remove_sticker_pack(operation.pack_id())
                    .await
                {
                    Ok(was_present) => {
                        debug!(was_present, "removed stick pack")
                    }
                    Err(error) => {
                        error!(
                            %error,
                            "failed to remove sticker pack"
                        )
                    }
                }
            }
        }
    }

    async fn handle_keys(&mut self, keys: &sync_message::Keys) {
        debug!("received key sync message");
        if self.manager.registration_type() == RegistrationType::Primary {
            warn!("received a key sync message as a primary device; ignoring");
            return;
        }
        match keys
            .account_entropy_pool
            .as_ref()
            .map(|s| AccountEntropyPool::from_str(s))
        {
            Some(Ok(aep)) => {
                if let Err(error) = self
                    .manager
                    .store
                    .store_account_entropy_pool(Some(&aep))
                    .await
                {
                    error!(%error, "failed to store account entropy pool");
                }
            }
            Some(Err(error)) => {
                warn!(%error, "cannot convert account entropy pool from string")
            }
            None => {}
        }
    }

    async fn handle_configuration(&mut self, configuration: &sync_message::Configuration) {
        debug!(?configuration, "received configuration sync message");
        if self.manager.registration_type() == RegistrationType::Primary {
            warn!("received a configuration sync message as a primary device; ignoring")
        } else if let Err(error) = super::super::settings::update_settings(
            &mut self.manager.store,
            &self.manager.state.settings,
            |s| s.apply(configuration),
        )
        .await
        {
            error!(%error, "failed to store settings");
        }
    }

    async fn handle_fetch_latest(&mut self, fetch_latest: &sync_message::FetchLatest) {
        if fetch_latest.r#type() != sync_message::fetch_latest::Type::StorageManifest {
            return;
        }
        let stories = self.manager.settings().stories;
        if let Err(error) = sync_from_storage_service(
            &mut self.manager.store,
            self.manager.state.identified_push_service(),
            &mut self.groups_manager,
            &self.manager.state.settings,
        )
        .await
        {
            warn!(%error, "failed to sync from the storage service");
        }

        // The stories header is only read on connect; the server kicks the old socket.
        if stories != self.manager.settings().stories {
            debug!("stories setting changed, reconnecting identified websocket");
            if let Err(error) = self.reconnect_identified_websocket().await {
                error!(%error, "failed to reconnect identified websocket");
            }
        }
    }

    /// Brings the group a message was sent in up to the revision the message shows.
    async fn handle_group_context(&mut self, content: &Content) {
        if let ContentBody::DataMessage(DataMessage {
            group_v2:
                Some(GroupContextV2 {
                    master_key: Some(master_key_bytes),
                    revision: Some(revision),
                    ..
                }),
            ..
        })
        | ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    message:
                        Some(DataMessage {
                            group_v2:
                                Some(GroupContextV2 {
                                    master_key: Some(master_key_bytes),
                                    revision: Some(revision),
                                    ..
                                }),
                            ..
                        }),
                    ..
                })),
            ..
        })
        | ContentBody::StoryMessage(StoryMessage {
            group:
                Some(GroupContextV2 {
                    master_key: Some(master_key_bytes),
                    revision: Some(revision),
                    ..
                }),
            ..
        }) = &content.body
        {
            // there's two things to implement: the group metadata (fetched from HTTP API)
            // and the group changes, which are part of the protobuf messages
            // this means we kinda need our own internal representation of groups inside of presage?
            if let Ok(Some(group)) = upsert_group(
                &self.manager.store,
                &mut self.groups_manager,
                master_key_bytes,
                revision,
            )
            .await
            {
                trace!(?group, "upserted group");
            }
        }
    }

    async fn handle_queue_empty(&mut self) -> Received {
        debug!("got empty queue");
        self.queue_empty = true;
        self.flush_delivery_receipts();
        if matches!(self.manager.account_entropy_pool().await, Ok(None)) {
            debug!("device does not have the needed keys; requesting from primary device");

            let mut message_sender = self.message_sender.clone();
            tokio::task::spawn_local(async move {
                let result = message_sender
                    .send_sync_message(SyncMessage {
                        content: Some(SyncContent::Request(sync_message::Request {
                            r#type: Some(sync_message::request::Type::Keys.into()),
                        })),
                        ..SyncMessage::with_padding(&mut rand::rng())
                    })
                    .await;

                if let Err(error) = result {
                    warn!(%error, "Error sending blocked contacts to other devices");
                }
            });
        }
        Received::QueueEmpty
    }

    fn queue_delivery_receipt(&mut self, sender: ServiceId, timestamp: u64) {
        self.pending_delivery_receipts
            .entry(sender)
            .or_default()
            .push(timestamp);
        self.pending_delivery_receipts_count += 1;
        if self.queue_empty || self.pending_delivery_receipts_count >= DELIVERY_RECEIPT_BATCH_SIZE {
            self.flush_delivery_receipts();
        }
    }

    fn flush_delivery_receipts(&mut self) {
        self.pending_delivery_receipts_count = 0;
        for (recipient, timestamps) in self.pending_delivery_receipts.drain() {
            let manager = self.manager.clone();
            let mut message_sender = self.message_sender.clone();
            tokio::task::spawn_local(async move {
                if let Err(error) = manager
                    .send_receipt(
                        &mut message_sender,
                        recipient,
                        receipt_message::Type::Delivery,
                        timestamps,
                    )
                    .await
                {
                    warn!(%error, "failed to send delivery receipt");
                }
            });
        }
    }

    async fn reconnect_identified_websocket(&mut self) -> Result<(), Error<S::Error>> {
        let ws = self.manager.identified_websocket(true).await?;
        self.message_sender = self.manager.new_message_sender().await?;
        self.encrypted_messages = Box::pin(MessagePipe::from_socket(ws).stream());
        // The new socket drains its own queue first.
        self.queue_empty = false;
        debug!("reconnected identified websocket");
        Ok(())
    }
}

mod origin {
    use libsignal_service::content::{ContentBody, Metadata};
    use libsignal_service::proto::SyncMessage;
    use libsignal_service::protocol::ServiceId;
    use libsignal_service::push_service::ServiceIds;

    /// Who a decrypted content is from, decided once: what it may ask of this device follows
    /// from it.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum Origin {
        /// One of this account's devices, by a session with it.
        Own,
        /// Another account, by a session with it.
        Peer,
        /// A plaintext envelope: nothing shows who wrote it. Signal's apps take a decryption
        /// error message from one and nothing else.
        Unauthenticated,
    }

    impl Origin {
        pub(super) fn of(metadata: &Metadata, own: &ServiceIds) -> Self {
            if metadata.was_plaintext {
                Self::Unauthenticated
            } else if metadata.sender == ServiceId::from(own.aci()) {
                Self::Own
            } else {
                Self::Peer
            }
        }

        /// The sync message in `body`, if this is the origin that may send one.
        pub(super) fn own_sync<'a>(&self, body: &'a ContentBody) -> Option<OwnSync<'a>> {
            match (self, body) {
                (Self::Own, ContentBody::SynchronizeMessage(sync)) => Some(OwnSync(sync)),
                _ => None,
            }
        }
    }

    /// A sync message of [`Origin::Own`], which is the only way to make one: only our own
    /// devices change the account's state on this one.
    pub(super) struct OwnSync<'a>(&'a SyncMessage);

    impl std::ops::Deref for OwnSync<'_> {
        type Target = SyncMessage;

        fn deref(&self) -> &SyncMessage {
            self.0
        }
    }
}

#[cfg(test)]
mod tests {
    use libsignal_service::content::{ContentBody, Metadata};
    use libsignal_service::prelude::Uuid;
    use libsignal_service::proto::{NullMessage, SyncMessage};
    use libsignal_service::protocol::{Aci, ServiceId};
    use libsignal_service::push_service::ServiceIds;

    use super::Origin;

    const OWN: ServiceIds = ServiceIds {
        aci: Uuid::from_u128(1),
        pni: Uuid::from_u128(2),
    };

    fn metadata(sender: Uuid, was_plaintext: bool) -> Metadata {
        let sender: ServiceId = Aci::from(sender).into();
        let now = chrono::Utc::now();
        Metadata {
            sender,
            sender_device: 1.try_into().unwrap(),
            destination: sender,
            server_guid: None,
            client_timestamp: now,
            server_timestamp: now,
            needs_receipt: false,
            unidentified_sender: false,
            was_plaintext,
            pni_verified: None,
        }
    }

    #[test]
    fn origin_is_decided_by_session_and_sender() {
        let peer = Uuid::from_u128(3);
        assert_eq!(Origin::of(&metadata(OWN.aci, false), &OWN), Origin::Own);
        assert_eq!(Origin::of(&metadata(peer, false), &OWN), Origin::Peer);
        // Not ours either, whoever the envelope names.
        assert_eq!(
            Origin::of(&metadata(OWN.aci, true), &OWN),
            Origin::Unauthenticated
        );
    }

    #[test]
    fn only_our_own_devices_sync() {
        let sync = ContentBody::SynchronizeMessage(SyncMessage::default());
        assert!(Origin::Own.own_sync(&sync).is_some());
        assert!(Origin::Peer.own_sync(&sync).is_none());
        assert!(Origin::Unauthenticated.own_sync(&sync).is_none());
        let other = ContentBody::NullMessage(NullMessage::default());
        assert!(Origin::Own.own_sync(&other).is_none());
    }
}
