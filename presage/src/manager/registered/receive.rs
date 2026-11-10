use std::ops::ControlFlow;
use std::str::FromStr;

use futures::channel::mpsc;
use futures::future::{self, Either};
use futures::{Stream, StreamExt};
use libsignal_service::{
    cipher::SealedSenderDecryptionError,
    content::{sync_message::request::Type as RequestType, Content, ContentBody},
    envelope::Envelope,
    groups_v2::{GroupsManager, InMemoryCredentialsCache},
    libsignal_account_keys::AccountEntropyPool,
    messagepipe::{Incoming, MessagePipe},
    prelude::{ProtobufMessage, ServiceError},
    proto::{
        sync_message::{self, sticker_pack_operation, Content as SyncContent},
        DataMessage, GroupContextV2, SyncMessage,
    },
    protocol::ServiceId,
    push_service::{PushService, ServiceIds},
    AccountManager,
};
use rand::rng;
use tracing::{debug, error, info, trace, warn};

use self::origin::{Origin, OwnSync};
use super::{
    jobs, register_pre_keys, save_message, set_account_attributes, update_group_or_owe, Registered,
    RegistrationType, ServiceCipher,
};
use crate::model::jobs::Job;
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
    ///
    /// While the stream lives, the [jobs](Job) the store keeps run beside it in tasks of the
    /// [`tokio::task::LocalSet`] the stream is first polled in. What they bring is yielded too.
    pub async fn receive_messages(
        &mut self,
    ) -> Result<impl Stream<Item = Received>, Error<S::Error>> {
        let identified_push_service = self.identified_push_service();
        // NB: here, we initialise a *fresh* Signal websocket, which means any other use of the previous one will go into nirvana
        let identified_websocket = self.identified_websocket(true).await?;

        let mut account_manager = AccountManager::new(
            identified_push_service.clone(),
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

        let encrypted_messages = MessagePipe::from_socket(identified_websocket);
        // A primary makes its pool when first asked.
        self.account_entropy_pool().await?;
        let (told, background) = mpsc::unbounded();

        let receiver = Receiver {
            store: self.store.clone(),
            encrypted_messages: Box::pin(encrypted_messages.stream()),
            service_cipher_aci: self.new_service_cipher_aci(),
            service_cipher_pni: self.new_service_cipher_pni(),
            groups_manager: Box::pin(self.groups_manager()).await?,
            identified_push_service,
            service_ids: self.state.data.service_ids.clone(),
            registration_type: self.registration_type(),
            jobs_wake: self.state.jobs_wake.clone(),
            jobs: JobsRunner {
                manager: Some(Box::new(self.clone())),
                told,
                running: None,
            },
            background,
        };

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

/// The task that runs the queued jobs: started when the stream is first polled, aborted when
/// it is dropped. A job that runs then is not interrupted.
struct JobsRunner<S: Store> {
    manager: Option<Box<Manager<S, Registered>>>,
    /// Where the jobs tell what they bring.
    told: mpsc::UnboundedSender<Received>,
    running: Option<tokio::task::JoinHandle<()>>,
}

impl<S: Store> JobsRunner<S> {
    fn start(&mut self) {
        if let Some(manager) = self.manager.take() {
            let run = jobs::run(*manager, self.told.clone());
            self.running = Some(tokio::task::spawn_local(run));
        }
    }
}

impl<S: Store> Drop for JobsRunner<S> {
    fn drop(&mut self) {
        if let Some(runner) = &self.running {
            runner.abort();
        }
    }
}

/// Decrypts, handles and stores what the message pipe brings, one envelope at a time.
struct Receiver<S: Store, E> {
    store: S,
    encrypted_messages: E,
    service_cipher_aci: ServiceCipher<S::AciStore>,
    service_cipher_pni: ServiceCipher<S::PniStore>,
    groups_manager: GroupsManager<InMemoryCredentialsCache>,
    identified_push_service: PushService,
    service_ids: ServiceIds,
    registration_type: RegistrationType,
    jobs_wake: std::sync::Arc<tokio::sync::Notify>,
    jobs: JobsRunner<S>,
    /// What the jobs bring.
    background: mpsc::UnboundedReceiver<Received>,
}

impl<S, E> Receiver<S, E>
where
    S: Store,
    E: Stream<Item = Result<Incoming, ServiceError>> + Unpin,
{
    /// The next thing to tell the client, `None` once the message pipe has ended.
    async fn next(&mut self) -> Option<Received> {
        self.jobs.start();
        loop {
            // What a job brought, or the next envelope.
            let incoming = match future::select(
                self.background.next(),
                self.encrypted_messages.next(),
            )
            .await
            {
                Either::Left((Some(received), _)) => return Some(received),
                Either::Left((None, incoming)) => incoming.await,
                Either::Right((incoming, _)) => incoming,
            };
            match incoming {
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

    async fn enqueue(&mut self, job: Job) {
        jobs::enqueue(&mut self.store, &self.jobs_wake, job).await;
    }

    async fn handle_envelope(&mut self, envelope: Envelope) -> Option<Received> {
        let opened = match envelope.parse_destination_service_id() {
            None => {
                warn!("Message has no destination service ID, dropping.");
                return None;
            }
            Some(ServiceId::Aci(_)) => {
                self.service_cipher_aci
                    .open_envelope(envelope, &mut rng())
                    .await
            }
            Some(ServiceId::Pni(pni)) => {
                if pni == self.service_ids.pni() && envelope.parse_source_service_id().is_none() {
                    warn!("Got a sealed sender message to our PNI? Invalid message, ignoring.");
                    return None;
                }
                self.service_cipher_pni
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
        if let ContentBody::DecryptionErrorMessage(e) = &content.body {
            error!(
                error = ?e,
                "got error decrypting a message"
            );
            return Some(Received::DecryptionError(content.metadata.sender));
        }

        match Origin::of(&content.metadata, &self.service_ids) {
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
                    if let ControlFlow::Break(received) = self.handle_sync(sync).await {
                        return received;
                    }
                }
            }
        }

        self.handle_group_context(&content).await;

        if let Err(error) =
            save_message(&mut self.store, &self.jobs_wake, content.clone(), None).await
        {
            error!(%error, "error saving message to store");
        }

        Some(Received::Content(Box::new(content)))
    }

    /// What only our own devices may ask. Breaks with what to tell the client if the sync
    /// message is nothing more than that.
    async fn handle_sync(&mut self, sync: OwnSync<'_>) -> ControlFlow<Option<Received>> {
        for job in jobs_of(&sync) {
            self.enqueue(job).await;
        }

        match &sync.content {
            // contacts synchronization sent from the primary device (happens after linking, or on demand)
            Some(SyncContent::Contacts(contacts)) => {
                return ControlFlow::Break(self.handle_contacts(contacts).await);
            }
            // key synchronization sent from the primary device
            Some(SyncContent::Keys(keys)) => self.handle_keys(keys).await,
            _ => {}
        }

        for operation in &sync.sticker_pack_operation {
            if operation.r#type() == sticker_pack_operation::Type::Remove {
                match self.store.remove_sticker_pack(operation.pack_id()).await {
                    Ok(was_present) => debug!(was_present, "removed stick pack"),
                    Err(error) => error!(%error, "failed to remove sticker pack"),
                }
            }
        }
        ControlFlow::Continue(())
    }

    /// Saves the contacts now, or by a job if that fails.
    async fn handle_contacts(&mut self, contacts: &sync_message::Contacts) -> Option<Received> {
        info!("saving contacts");
        let saved = jobs::save_contacts(
            &mut self.store,
            self.identified_push_service.clone(),
            contacts,
        )
        .await;
        match saved {
            Ok(()) => Some(Received::Contacts),
            Err(error) => {
                warn!(%error, "failed to save contacts; trying again later");
                self.enqueue(Job::SaveContacts {
                    contacts: contacts.encode_to_vec(),
                })
                .await;
                None
            }
        }
    }

    async fn handle_keys(&mut self, keys: &sync_message::Keys) {
        debug!("received key sync message");
        if self.registration_type == RegistrationType::Primary {
            warn!("received a key sync message as a primary device; ignoring");
            return;
        }
        match keys
            .account_entropy_pool
            .as_ref()
            .map(|s| AccountEntropyPool::from_str(s))
        {
            Some(Ok(aep)) => {
                if let Err(error) = self.store.store_account_entropy_pool(Some(&aep)).await {
                    error!(%error, "failed to store account entropy pool");
                }
            }
            Some(Err(error)) => {
                warn!(%error, "cannot convert account entropy pool from string")
            }
            None => {}
        }
    }

    /// Brings the group a message was sent in up to the revision the message shows, by a job if
    /// the connection fails.
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
        }) = &content.body
        {
            // there's two things to implement: the group metadata (fetched from HTTP API)
            // and the group changes, which are part of the protobuf messages
            // this means we kinda need our own internal representation of groups inside of presage?
            let updated = update_group_or_owe(
                &self.store,
                &self.jobs_wake,
                &mut self.groups_manager,
                master_key_bytes,
                revision,
            )
            .await;
            if let Ok(group) = updated {
                trace!(?group, "upserted group");
            }
        }
    }

    async fn handle_queue_empty(&mut self) -> Received {
        debug!("got empty queue");
        match self.store.fetch_account_entropy_pool().await {
            Ok(None) => {
                debug!("device does not have the needed keys; requesting from primary device");
                self.enqueue(Job::RequestKeys).await;
            }
            Ok(Some(_)) => {}
            Err(error) => error!(%error, "failed to read the account entropy pool"),
        }
        Received::QueueEmpty
    }
}

/// The work a sync message of ours asks for that is left to a [`Job`].
fn jobs_of(sync: &OwnSync<'_>) -> Vec<Job> {
    let mut jobs = Vec::new();
    match &sync.content {
        Some(SyncContent::Request(request)) => match request.r#type() {
            RequestType::Contacts => jobs.push(Job::AnswerContacts),
            RequestType::Keys => jobs.push(Job::AnswerKeys),
            RequestType::Blocked => jobs.push(Job::AnswerBlocked),
            t => info!(type = ?t, "Got sync request of currently unhandled type"),
        },
        // The primary device told us to fetch stuff again from the storage service.
        Some(SyncContent::FetchLatest(fetch_latest))
            if fetch_latest.r#type() == sync_message::fetch_latest::Type::StorageManifest =>
        {
            jobs.push(Job::SyncStorage)
        }
        _ => {}
    }
    for operation in &sync.sticker_pack_operation {
        if operation.r#type() == sticker_pack_operation::Type::Install {
            jobs.push(Job::InstallStickerPack {
                pack_id: operation.pack_id().to_vec(),
                pack_key: operation.pack_key().to_vec(),
            });
        }
    }
    jobs
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
    use libsignal_service::proto::{sync_message, NullMessage, SyncMessage};
    use libsignal_service::protocol::{Aci, ServiceId};
    use libsignal_service::push_service::ServiceIds;

    use super::{jobs_of, Origin};
    use crate::model::jobs::Job;

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

    /// What our own devices ask in a sync message is queued, not done on the spot.
    #[test]
    fn a_sync_message_queues_its_work() {
        let jobs = |sync| {
            let body = ContentBody::SynchronizeMessage(sync);
            jobs_of(&Origin::Own.own_sync(&body).unwrap())
        };
        let install = sync_message::StickerPackOperation {
            pack_id: Some(vec![1; 16]),
            pack_key: Some(vec![2; 32]),
            r#type: Some(sync_message::sticker_pack_operation::Type::Install as i32),
        };
        let remove = sync_message::StickerPackOperation {
            r#type: Some(sync_message::sticker_pack_operation::Type::Remove as i32),
            ..install.clone()
        };
        assert_eq!(
            jobs(SyncMessage {
                sticker_pack_operation: vec![install, remove],
                ..Default::default()
            }),
            [Job::InstallStickerPack {
                pack_id: vec![1; 16],
                pack_key: vec![2; 32],
            }]
        );

        let request = |r#type: sync_message::request::Type| SyncMessage {
            content: Some(sync_message::Content::Request(sync_message::Request {
                r#type: Some(r#type.into()),
            })),
            ..Default::default()
        };
        use sync_message::request::Type;
        assert_eq!(jobs(request(Type::Contacts)), [Job::AnswerContacts]);
        assert_eq!(jobs(request(Type::Keys)), [Job::AnswerKeys]);
        assert_eq!(jobs(request(Type::Blocked)), [Job::AnswerBlocked]);

        let fetch_latest = SyncMessage {
            content: Some(sync_message::Content::FetchLatest(
                sync_message::FetchLatest {
                    r#type: Some(sync_message::fetch_latest::Type::StorageManifest.into()),
                },
            )),
            ..Default::default()
        };
        assert_eq!(jobs(fetch_latest), [Job::SyncStorage]);
        assert_eq!(jobs(SyncMessage::default()), []);
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
