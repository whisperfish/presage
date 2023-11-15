use std::fmt;
use std::ops::RangeBounds;
use std::pin::pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures::{future, AsyncReadExt, Stream, StreamExt};
use libsignal_service::attachment_cipher::decrypt_in_place;
use libsignal_service::configuration::{ServiceConfiguration, SignalServers, SignalingKey};
use libsignal_service::content::{Content, ContentBody, DataMessageFlags, Metadata};
use libsignal_service::groups_v2::{decrypt_group, Group, GroupsManager, InMemoryCredentialsCache};
use libsignal_service::messagepipe::{Incoming, ServiceCredentials};
use libsignal_service::models::Contact;
use libsignal_service::prelude::phonenumber::PhoneNumber;
use libsignal_service::prelude::Uuid;
use libsignal_service::proto::data_message::Delete;
use libsignal_service::proto::{
    sync_message, AttachmentPointer, DataMessage, EditMessage, GroupContextV2, NullMessage,
    SyncMessage,
};
use libsignal_service::protocol::SenderCertificate;
use libsignal_service::protocol::{PrivateKey, PublicKey};
use libsignal_service::provisioning::generate_registration_id;
use libsignal_service::push_service::{
    AccountAttributes, DeviceCapabilities, PushService, ServiceError, ServiceIds, WhoAmIResponse,
    DEFAULT_DEVICE_ID,
};
use libsignal_service::receiver::MessageReceiver;
use libsignal_service::sender::{AttachmentSpec, AttachmentUploadError};
use libsignal_service::unidentified_access::UnidentifiedAccess;
use libsignal_service::utils::{
    serde_optional_private_key, serde_optional_public_key, serde_private_key, serde_public_key,
    serde_signaling_key,
};
use libsignal_service::websocket::SignalWebSocket;
use libsignal_service::zkgroup::profiles::ProfileKey;
use libsignal_service::{cipher, AccountManager, Profile, ServiceAddress};
use libsignal_service_hyper::push_service::HyperPushService;
use log::{debug, error, info, trace, warn};
use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

use crate::cache::CacheCell;
use crate::serde::serde_profile_key;
use crate::store::{Store, Thread};
use crate::{Error, Manager};

type ServiceCipher<C> = cipher::ServiceCipher<C, StdRng>;
type MessageSender<C> = libsignal_service::prelude::MessageSender<HyperPushService, C, StdRng>;

/// Manager state where Signal can be used
#[derive(Clone, Serialize, Deserialize)]
pub struct Registered {
    #[serde(skip)]
    pub(crate) push_service_cache: CacheCell<HyperPushService>,
    #[serde(skip)]
    pub(crate) identified_websocket: Arc<Mutex<Option<SignalWebSocket>>>,
    #[serde(skip)]
    pub(crate) unidentified_websocket: Arc<Mutex<Option<SignalWebSocket>>>,
    #[serde(skip)]
    pub(crate) unidentified_sender_certificate: Option<SenderCertificate>,

    pub signal_servers: SignalServers,
    pub device_name: Option<String>,
    pub phone_number: PhoneNumber,
    #[serde(flatten)]
    pub service_ids: ServiceIds,
    pub(crate) password: String,
    #[serde(with = "serde_signaling_key")]
    pub(crate) signaling_key: SignalingKey,
    pub device_id: Option<u32>,
    pub registration_id: u32,
    #[serde(default)]
    pub pni_registration_id: Option<u32>,
    #[serde(with = "serde_private_key", rename = "private_key")]
    pub aci_private_key: PrivateKey,
    #[serde(with = "serde_public_key", rename = "public_key")]
    pub aci_public_key: PublicKey,
    #[serde(with = "serde_optional_private_key", default)]
    pub pni_private_key: Option<PrivateKey>,
    #[serde(with = "serde_optional_public_key", default)]
    pub pni_public_key: Option<PublicKey>,
    #[serde(with = "serde_profile_key")]
    pub(crate) profile_key: ProfileKey,
}

impl fmt::Debug for Registered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registered").finish_non_exhaustive()
    }
}

impl Registered {
    pub fn device_id(&self) -> u32 {
        self.device_id.unwrap_or(DEFAULT_DEVICE_ID)
    }
}

impl<C: Store> Manager<C, Registered> {
    /// Loads a previously registered account from the implemented [Store].
    ///
    /// Returns a instance of [Manager] you can use to send & receive messages.
    pub async fn load_registered(config_store: C) -> Result<Self, Error<C::Error>> {
        let state = config_store
            .load_state()?
            .ok_or(Error::NotYetRegisteredError)?;

        let mut manager = Self {
            rng: StdRng::from_entropy(),
            config_store,
            state,
        };

        if manager.state.pni_registration_id.is_none() {
            manager.set_account_attributes().await?;
        }

        Ok(manager)
    }

    pub(crate) async fn register_pre_keys(&mut self) -> Result<(), Error<C::Error>> {
        trace!("registering pre keys");
        let mut account_manager =
            AccountManager::new(self.push_service()?, Some(self.state.profile_key));

        let (pre_keys_offset_id, next_signed_pre_key_id, next_pq_pre_key_id) = account_manager
            .update_pre_key_bundle(
                &mut self.config_store.clone(),
                &mut self.rng,
                self.config_store.pre_keys_offset_id()?,
                self.config_store.next_signed_pre_key_id()?,
                self.config_store.next_pq_pre_key_id()?,
                true,
            )
            .await?;

        self.config_store
            .set_pre_keys_offset_id(pre_keys_offset_id)?;
        self.config_store
            .set_next_signed_pre_key_id(next_signed_pre_key_id)?;
        self.config_store
            .set_next_pq_pre_key_id(next_pq_pre_key_id)?;

        trace!("registered pre keys");
        Ok(())
    }

    pub(crate) async fn set_account_attributes(&mut self) -> Result<(), Error<C::Error>> {
        trace!("setting account attributes");
        let mut account_manager =
            AccountManager::new(self.push_service()?, Some(self.state.profile_key));

        let pni_registration_id = if let Some(pni_registration_id) = self.state.pni_registration_id
        {
            pni_registration_id
        } else {
            info!("migrating to PNI");
            let pni_registration_id = generate_registration_id(&mut StdRng::from_entropy());
            self.state.pni_registration_id = Some(pni_registration_id);
            self.config_store.save_state(&self.state)?;
            pni_registration_id
        };

        account_manager
            .set_account_attributes(AccountAttributes {
                name: self.state.device_name.clone(),
                registration_id: self.state.registration_id,
                pni_registration_id,
                signaling_key: None,
                voice: false,
                video: false,
                fetches_messages: true,
                pin: None,
                registration_lock: None,
                unidentified_access_key: Some(self.state.profile_key.derive_access_key().to_vec()),
                unrestricted_unidentified_access: false,
                discoverable_by_phone_number: true,
                capabilities: DeviceCapabilities {
                    gv2: true,
                    gv1_migration: true,
                    ..Default::default()
                },
            })
            .await?;

        if self.state.pni_registration_id.is_none() {
            debug!("fetching PNI UUID and updating state");
            let whoami = self.whoami().await?;
            self.state.service_ids.pni = whoami.pni;
            self.config_store.save_state(&self.state)?;
        }

        trace!("done setting account attributes");
        Ok(())
    }

    async fn wait_for_contacts_sync(
        &mut self,
        mut messages: impl Stream<Item = Content> + Unpin,
    ) -> Result<(), Error<C::Error>> {
        let mut message_receiver = MessageReceiver::new(self.push_service()?);
        while let Some(Content { body, .. }) = messages.next().await {
            if let ContentBody::SynchronizeMessage(SyncMessage {
                contacts: Some(contacts),
                ..
            }) = body
            {
                let contacts = message_receiver.retrieve_contacts(&contacts).await?;
                let _ = self.config_store.clear_contacts();
                self.config_store
                    .save_contacts(contacts.filter_map(Result::ok))?;
                info!("saved contacts");
                return Ok(());
            }
        }
        Ok(())
    }

    pub(crate) async fn sync_contacts(&mut self) -> Result<(), Error<C::Error>> {
        let messages = pin!(
            self.receive_messages_stream(ReceivingMode::WaitForContacts)
                .await?
        );
        self.request_contacts_sync().await?;

        info!("waiting for contacts sync for up to 60 seconds");

        tokio::time::timeout(
            Duration::from_secs(60),
            self.wait_for_contacts_sync(messages),
        )
        .await
        .map_err(Error::from)??;

        Ok(())
    }

    /// Request that the primary device to encrypt & send all of its contacts as a message to ourselves
    /// which can be then received, decrypted and stored in the message receiving loop.
    ///
    /// **Note**: If successful, the contacts are not yet received and stored, but will only be
    /// processed when they're received using the `MessageReceiver`.
    pub async fn request_contacts_sync(&mut self) -> Result<(), Error<C::Error>> {
        trace!("requesting contacts sync");
        let var_name = sync_message::request::Type::Contacts as i32;
        let sync_message = SyncMessage {
            request: Some(sync_message::Request {
                r#type: Some(var_name),
            }),
            ..Default::default()
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.service_ids.aci, sync_message, timestamp)
            .await?;

        Ok(())
    }

    async fn sender_certificate(&mut self) -> Result<SenderCertificate, Error<C::Error>> {
        let needs_renewal = |sender_certificate: Option<&SenderCertificate>| -> bool {
            if sender_certificate.is_none() {
                return true;
            }

            let seconds_since_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            if let Some(expiration) = sender_certificate.and_then(|s| s.expiration().ok()) {
                expiration >= seconds_since_epoch - 600
            } else {
                true
            }
        };

        if needs_renewal(self.state.unidentified_sender_certificate.as_ref()) {
            let sender_certificate = self
                .push_service()?
                .get_uuid_only_sender_certificate()
                .await?;

            self.state
                .unidentified_sender_certificate
                .replace(sender_certificate);
        }

        Ok(self
            .state
            .unidentified_sender_certificate
            .clone()
            .expect("logic error"))
    }

    pub async fn submit_recaptcha_challenge(
        &self,
        token: &str,
        captcha: &str,
    ) -> Result<(), Error<C::Error>> {
        let mut account_manager = AccountManager::new(self.push_service()?, None);
        account_manager
            .submit_recaptcha_challenge(token, captcha)
            .await?;
        Ok(())
    }

    /// Returns a handle on the registered state
    pub fn state(&self) -> &Registered {
        &self.state
    }

    /// Fetches basic information on the registered device.
    pub async fn whoami(&self) -> Result<WhoAmIResponse, Error<C::Error>> {
        Ok(self.push_service()?.whoami().await?)
    }

    /// Fetches the profile (name, about, status emoji) of the registered user.
    pub async fn retrieve_profile(&mut self) -> Result<Profile, Error<C::Error>> {
        self.retrieve_profile_by_uuid(self.state.service_ids.aci, self.state.profile_key)
            .await
    }

    /// Fetches the profile of the provided user by UUID and profile key.
    pub async fn retrieve_profile_by_uuid(
        &mut self,
        uuid: Uuid,
        profile_key: ProfileKey,
    ) -> Result<Profile, Error<C::Error>> {
        // Check if profile is cached.
        if let Some(profile) = self.config_store.profile(uuid, profile_key).ok().flatten() {
            return Ok(profile);
        }

        let mut account_manager = AccountManager::new(self.push_service()?, Some(profile_key));

        let profile = account_manager.retrieve_profile(uuid.into()).await?;

        let _ = self
            .config_store
            .save_profile(uuid, profile_key, profile.clone());
        Ok(profile)
    }

    /// Get a single contact by its UUID
    ///
    /// Note: this only currently works when linked as secondary device (the contacts are sent by the primary device at linking time)
    pub fn contact_by_id(&self, id: &Uuid) -> Result<Option<Contact>, Error<C::Error>> {
        Ok(self.config_store.contact_by_id(*id)?)
    }

    /// Returns an iterator on contacts stored in the [Store].
    pub fn contacts(
        &self,
    ) -> Result<impl Iterator<Item = Result<Contact, Error<C::Error>>>, Error<C::Error>> {
        let iter = self.config_store.contacts()?;
        Ok(iter.map(|r| r.map_err(Into::into)))
    }

    /// Get a group (either from the local cache, or fetch it remotely) using its master key
    pub fn group(&self, master_key_bytes: &[u8]) -> Result<Option<Group>, Error<C::Error>> {
        Ok(self.config_store.group(master_key_bytes.try_into()?)?)
    }

    /// Returns an iterator on groups stored in the [Store].
    pub fn groups(&self) -> Result<C::GroupsIter, Error<C::Error>> {
        Ok(self.config_store.groups()?)
    }

    /// Get a single message in a thread (identified by its server-side sent timestamp)
    pub fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<Content>, Error<C::Error>> {
        Ok(self.config_store.message(thread, timestamp)?)
    }

    /// Get an iterator of messages in a thread, optionally starting from a point in time.
    pub fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> Result<C::MessagesIter, Error<C::Error>> {
        Ok(self.config_store.messages(thread, range)?)
    }

    async fn receive_messages_encrypted(
        &mut self,
    ) -> Result<impl Stream<Item = Result<Incoming, ServiceError>>, Error<C::Error>> {
        let credentials = self.credentials().ok_or(Error::NotYetRegisteredError)?;
        let allow_stories = false;
        let pipe = MessageReceiver::new(self.push_service()?)
            .create_message_pipe(credentials, allow_stories)
            .await?;

        let service_configuration: ServiceConfiguration = self.state.signal_servers.into();
        let mut unidentified_push_service =
            HyperPushService::new(service_configuration, None, crate::USER_AGENT.to_string());
        let unidentified_ws = unidentified_push_service
            .ws("/v1/websocket/", &[], None, false)
            .await?;
        self.state.identified_websocket.lock().replace(pipe.ws());
        self.state
            .unidentified_websocket
            .lock()
            .replace(unidentified_ws);

        Ok(pipe.stream())
    }

    /// Starts receiving and storing messages.
    ///
    /// Returns a [futures::Stream] of messages to consume. Messages will also be stored by the implementation of the [Store].
    pub async fn receive_messages(
        &mut self,
    ) -> Result<impl Stream<Item = Content>, Error<C::Error>> {
        self.receive_messages_stream(ReceivingMode::Forever).await
    }

    pub async fn receive_messages_with_mode(
        &mut self,
        mode: ReceivingMode,
    ) -> Result<impl Stream<Item = Content>, Error<C::Error>> {
        self.receive_messages_stream(mode).await
    }

    fn groups_manager(
        &self,
    ) -> Result<GroupsManager<HyperPushService, InMemoryCredentialsCache>, Error<C::Error>> {
        let service_configuration: ServiceConfiguration = self.state.signal_servers.into();
        let server_public_params = service_configuration.zkgroup_server_public_params;

        let groups_credentials_cache = InMemoryCredentialsCache::default();
        let groups_manager = GroupsManager::new(
            self.state.service_ids.clone(),
            self.push_service()?,
            groups_credentials_cache,
            server_public_params,
        );

        Ok(groups_manager)
    }

    async fn receive_messages_stream(
        &mut self,
        mode: ReceivingMode,
    ) -> Result<impl Stream<Item = Content>, Error<C::Error>> {
        struct StreamState<S, C> {
            encrypted_messages: S,
            message_receiver: MessageReceiver<HyperPushService>,
            service_cipher: ServiceCipher<C>,
            config_store: C,
            groups_manager: GroupsManager<HyperPushService, InMemoryCredentialsCache>,
            mode: ReceivingMode,
        }

        let init = StreamState {
            encrypted_messages: Box::pin(self.receive_messages_encrypted().await?),
            message_receiver: MessageReceiver::new(self.push_service()?),
            service_cipher: self.new_service_cipher()?,
            config_store: self.config_store.clone(),
            groups_manager: self.groups_manager()?,
            mode,
        };

        Ok(futures::stream::unfold(init, |mut state| async move {
            loop {
                match state.encrypted_messages.next().await {
                    Some(Ok(Incoming::Envelope(envelope))) => {
                        match state.service_cipher.open_envelope(envelope).await {
                            Ok(Some(content)) => {
                                // contacts synchronization sent from the primary device (happens after linking, or on demand)
                                if let ContentBody::SynchronizeMessage(SyncMessage {
                                    contacts: Some(contacts),
                                    ..
                                }) = &content.body
                                {
                                    match state.message_receiver.retrieve_contacts(contacts).await {
                                        Ok(contacts) => {
                                            let _ = state.config_store.clear_contacts();
                                            match state
                                                .config_store
                                                .save_contacts(contacts.filter_map(Result::ok))
                                            {
                                                Ok(()) => {
                                                    info!("saved contacts");
                                                }
                                                Err(e) => {
                                                    warn!("failed to save contacts: {e}");
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            warn!("failed to retrieve contacts: {e}");
                                        }
                                    }

                                    if let ReceivingMode::WaitForContacts = state.mode {
                                        return None;
                                    }
                                }

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
                                    sent:
                                        Some(sync_message::Sent {
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
                                        }),
                                    ..
                                }) = &content.body
                                {
                                    // there's two things to implement: the group metadata (fetched from HTTP API)
                                    // and the group changes, which are part of the protobuf messages
                                    // this means we kinda need our own internal representation of groups inside of presage?
                                    if let Ok(Some(group)) = upsert_group(
                                        &state.config_store,
                                        &mut state.groups_manager,
                                        master_key_bytes,
                                        revision,
                                    )
                                    .await
                                    {
                                        log::trace!("{group:?}");
                                    }
                                }

                                if let Err(e) =
                                    save_message(&mut state.config_store, content.clone())
                                {
                                    log::error!("Error saving message to store: {}", e);
                                }

                                return Some((content, state));
                            }
                            Ok(None) => {
                                debug!("Empty envelope..., message will be skipped!")
                            }
                            Err(e) => {
                                error!("Error opening envelope: {:?}, message will be skipped!", e);
                            }
                        }
                    }
                    Some(Ok(Incoming::QueueEmpty)) => {
                        debug!("empty queue");
                        if let ReceivingMode::InitialSync = state.mode {
                            return None;
                        }
                    }
                    Some(Err(e)) => error!("Error: {}", e),
                    None => return None,
                }
            }
        }))
    }

    /// Sends a messages to the provided [ServiceAddress].
    /// The timestamp should be set to now and is used by Signal mobile apps
    /// to order messages later, and apply reactions.
    ///
    /// This method will automatically update the [DataMessage::expire_timer] if it is set to
    /// [None] such that the chat will keep the current expire timer.
    pub async fn send_message(
        &mut self,
        recipient_addr: impl Into<ServiceAddress>,
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error<C::Error>> {
        let mut sender = self.new_message_sender().await?;

        let online_only = false;
        let recipient = recipient_addr.into();
        let mut content_body: ContentBody = message.into();

        // Only update the expiration timer if it is not set.
        match content_body {
            ContentBody::DataMessage(DataMessage {
                expire_timer: ref mut timer,
                ..
            }) if timer.is_none() => {
                // Set the expire timer to None for errors.
                let store_expire_timer = self
                    .config_store
                    .expire_timer(&Thread::Contact(recipient.uuid))
                    .unwrap_or_default();

                *timer = store_expire_timer;
            }
            _ => {}
        }

        let sender_certificate = self.sender_certificate().await?;
        let unidentified_access =
            self.config_store
                .profile_key(&recipient.uuid)?
                .map(|profile_key| UnidentifiedAccess {
                    key: profile_key.derive_access_key().to_vec(),
                    certificate: sender_certificate.clone(),
                });

        sender
            .send_message(
                &recipient,
                unidentified_access,
                content_body.clone(),
                timestamp,
                online_only,
            )
            .await?;

        // save the message
        let content = Content {
            metadata: Metadata {
                sender: self.state.service_ids.aci.into(),
                sender_device: self.state.device_id(),
                timestamp,
                needs_receipt: false,
                unidentified_sender: false,
            },
            body: content_body,
        };

        save_message(&mut self.config_store, content)?;

        Ok(())
    }

    /// Uploads attachments prior to linking them in a message.
    pub async fn upload_attachments(
        &self,
        attachments: Vec<(AttachmentSpec, Vec<u8>)>,
    ) -> Result<Vec<Result<AttachmentPointer, AttachmentUploadError>>, Error<C::Error>> {
        if attachments.is_empty() {
            return Ok(Vec::new());
        }
        let sender = self.new_message_sender().await?;
        let upload = future::join_all(attachments.into_iter().map(move |(spec, contents)| {
            let mut sender = sender.clone();
            async move { sender.upload_attachment(spec, contents).await }
        }));
        Ok(upload.await)
    }

    /// Sends one message in a group (v2). The `master_key_bytes` is required to have 32 elements.
    ///
    /// This method will automatically update the [DataMessage::expire_timer] if it is set to
    /// [None] such that the chat will keep the current expire timer.
    pub async fn send_message_to_group(
        &mut self,
        master_key_bytes: &[u8],
        mut message: DataMessage,
        timestamp: u64,
    ) -> Result<(), Error<C::Error>> {
        // Only update the expiration timer if it is not set.
        match message {
            DataMessage {
                expire_timer: ref mut timer,
                ..
            } if timer.is_none() => {
                // Set the expire timer to None for errors.
                let store_expire_timer = self
                    .config_store
                    .expire_timer(&Thread::Group(
                        master_key_bytes
                            .try_into()
                            .expect("Master key bytes to be of size 32."),
                    ))
                    .unwrap_or_default();

                *timer = store_expire_timer;
            }
            _ => {}
        }
        let mut sender = self.new_message_sender().await?;

        let mut groups_manager = self.groups_manager()?;
        let Some(group) = upsert_group(
            &self.config_store,
            &mut groups_manager,
            master_key_bytes,
            &0,
        )
        .await?
        else {
            return Err(Error::UnknownGroup);
        };

        let sender_certificate = self.sender_certificate().await?;
        let mut recipients = Vec::new();
        for member in group
            .members
            .into_iter()
            .filter(|m| m.uuid != self.state.service_ids.aci)
        {
            let unidentified_access =
                self.config_store
                    .profile_key(&member.uuid)?
                    .map(|profile_key| UnidentifiedAccess {
                        key: profile_key.derive_access_key().to_vec(),
                        certificate: sender_certificate.clone(),
                    });
            recipients.push((member.uuid.into(), unidentified_access));
        }

        let online_only = false;
        let results = sender
            .send_message_to_group(recipients, message.clone(), timestamp, online_only)
            .await;

        // return first error if any
        results.into_iter().find(|res| res.is_err()).transpose()?;

        let content = Content {
            metadata: Metadata {
                sender: self.state.service_ids.aci.into(),
                sender_device: self.state.device_id(),
                timestamp,
                needs_receipt: false, // TODO: this is just wrong
                unidentified_sender: false,
            },
            body: message.into(),
        };

        save_message(&mut self.config_store, content)?;

        Ok(())
    }

    /// Clears all sessions established wiht [recipient](ServiceAddress).
    pub async fn clear_sessions(&self, recipient: &ServiceAddress) -> Result<(), Error<C::Error>> {
        self.config_store.delete_all_sessions(recipient).await?;
        Ok(())
    }

    /// Downloads and decrypts a single attachment.
    pub async fn get_attachment(
        &self,
        attachment_pointer: &AttachmentPointer,
    ) -> Result<Vec<u8>, Error<C::Error>> {
        let mut service = self.push_service()?;
        let mut attachment_stream = service.get_attachment(attachment_pointer).await?;

        // We need the whole file for the crypto to check out
        let mut ciphertext = Vec::new();
        let len = attachment_stream.read_to_end(&mut ciphertext).await?;

        trace!("downloaded encrypted attachment of {} bytes", len);

        let key: [u8; 64] = attachment_pointer.key().try_into()?;
        decrypt_in_place(key, &mut ciphertext)?;

        Ok(ciphertext)
    }

    pub async fn send_session_reset(
        &mut self,
        recipient: &ServiceAddress,
        timestamp: u64,
    ) -> Result<(), Error<C::Error>> {
        log::trace!("Resetting session for address: {}", recipient.uuid);
        let message = DataMessage {
            flags: Some(DataMessageFlags::EndSession as u32),
            ..Default::default()
        };

        self.send_message(*recipient, message, timestamp).await?;

        Ok(())
    }

    fn credentials(&self) -> Option<ServiceCredentials> {
        Some(ServiceCredentials {
            uuid: Some(self.state.service_ids.aci),
            phonenumber: self.state.phone_number.clone(),
            password: Some(self.state.password.clone()),
            signaling_key: Some(self.state.signaling_key),
            device_id: self.state.device_id,
        })
    }

    /// Returns a clone of a cached push service.
    ///
    /// If no service is yet cached, it will create and cache one.
    fn push_service(&self) -> Result<HyperPushService, Error<C::Error>> {
        self.state.push_service_cache.get(|| {
            let credentials = self.credentials();
            let service_configuration: ServiceConfiguration = self.state.signal_servers.into();

            Ok(HyperPushService::new(
                service_configuration,
                credentials,
                crate::USER_AGENT.to_string(),
            ))
        })
    }

    /// Creates a new message sender.
    async fn new_message_sender(&self) -> Result<MessageSender<C>, Error<C::Error>> {
        let local_addr = ServiceAddress {
            uuid: self.state.service_ids.aci,
        };

        let identified_websocket = self
            .state
            .identified_websocket
            .lock()
            .clone()
            .ok_or(Error::MessagePipeNotStarted)?;

        let service_configuration: ServiceConfiguration = self.state.signal_servers.into();
        let mut unidentified_push_service =
            HyperPushService::new(service_configuration, None, crate::USER_AGENT.to_string());
        let unidentified_websocket = unidentified_push_service
            .ws("/v1/websocket/", &[], None, false)
            .await?;

        Ok(MessageSender::new(
            identified_websocket,
            unidentified_websocket,
            self.push_service()?,
            self.new_service_cipher()?,
            self.rng.clone(),
            self.config_store.clone(),
            local_addr,
            self.state.device_id.unwrap_or(DEFAULT_DEVICE_ID).into(),
        ))
    }

    /// Creates a new service cipher.
    fn new_service_cipher(&self) -> Result<ServiceCipher<C>, Error<C::Error>> {
        let service_configuration: ServiceConfiguration = self.state.signal_servers.into();
        let service_cipher = ServiceCipher::new(
            self.config_store.clone(),
            self.rng.clone(),
            service_configuration.unidentified_sender_trust_root,
            self.state.service_ids.aci,
            self.state.device_id.unwrap_or(DEFAULT_DEVICE_ID),
        );

        Ok(service_cipher)
    }

    /// Returns the title of a thread (contact or group).
    pub async fn thread_title(&self, thread: &Thread) -> Result<String, Error<C::Error>> {
        match thread {
            Thread::Contact(uuid) => {
                let contact = match self.contact_by_id(uuid) {
                    Ok(contact) => contact,
                    Err(e) => {
                        log::info!("Error getting contact by id: {}, {:?}", e, uuid);
                        None
                    }
                };
                Ok(match contact {
                    Some(contact) => contact.name,
                    None => uuid.to_string(),
                })
            }
            Thread::Group(id) => match self.group(id)? {
                Some(group) => Ok(group.title),
                None => Ok("".to_string()),
            },
        }
    }

    #[deprecated = "use Manager::contact_by_id"]
    pub fn get_contacts(
        &self,
    ) -> Result<impl Iterator<Item = Result<Contact, Error<C::Error>>>, Error<C::Error>> {
        self.contacts()
    }

    #[deprecated = "use Manager::contact_by_id"]
    pub fn get_contact_by_id(&self, id: Uuid) -> Result<Option<Contact>, Error<C::Error>> {
        self.contact_by_id(&id)
    }

    #[deprecated = "use Manager::groups"]
    pub fn get_groups(&self) -> Result<C::GroupsIter, Error<C::Error>> {
        self.groups()
    }

    #[deprecated = "use Manager::group"]
    pub fn get_group(&self, master_key_bytes: &[u8]) -> Result<Option<Group>, Error<C::Error>> {
        self.group(master_key_bytes)
    }
}

/// The mode receiving messages stream
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ReceivingMode {
    /// Don't stop the stream
    #[default]
    Forever,
    /// Stop the stream after the initial sync
    ///
    /// That is, when the Signal's message queue becomes empty.
    InitialSync,
    /// Stop the stream after contacts are synced
    WaitForContacts,
}

async fn upsert_group<C: Store>(
    config_store: &C,
    groups_manager: &mut GroupsManager<HyperPushService, InMemoryCredentialsCache>,
    master_key_bytes: &[u8],
    revision: &u32,
) -> Result<Option<Group>, Error<C::Error>> {
    let upsert_group = match config_store.group(master_key_bytes.try_into()?) {
        Ok(Some(group)) => {
            log::debug!("loaded group from local db {}", group.title);
            group.revision < *revision
        }
        Ok(None) => true,
        Err(e) => {
            log::warn!("failed to retrieve group from local db {}", e);
            true
        }
    };

    if upsert_group {
        log::debug!("fetching and saving group");
        match groups_manager.fetch_encrypted_group(master_key_bytes).await {
            Ok(encrypted_group) => {
                let group = decrypt_group(master_key_bytes, encrypted_group)?;
                if let Err(e) = config_store.save_group(master_key_bytes.try_into()?, &group) {
                    log::error!("failed to save group {master_key_bytes:?}: {e}",);
                }
            }
            Err(e) => {
                log::warn!("failed to fetch encrypted group: {e}")
            }
        }
    }

    Ok(config_store.group(master_key_bytes.try_into()?)?)
}

fn save_message<C: Store>(config_store: &mut C, message: Content) -> Result<(), Error<C::Error>> {
    // derive the thread from the message type
    let thread = Thread::try_from(&message)?;

    // update recipient profile keys
    if let ContentBody::DataMessage(DataMessage {
        profile_key: Some(profile_key_bytes),
        ..
    }) = &message.body
    {
        if let Ok(profile_key_bytes) = profile_key_bytes.clone().try_into() {
            let sender_uuid = message.metadata.sender.uuid;
            let profile_key = ProfileKey::create(profile_key_bytes);
            log::debug!("inserting profile key for {sender_uuid}");
            config_store.upsert_profile_key(&sender_uuid, profile_key)?;
        }
    }

    // only save DataMessage and SynchronizeMessage (sent)
    let message = match message.body {
        ContentBody::NullMessage(_) => Some(message),
        ContentBody::DataMessage(ref data_message)
        | ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(sync_message::Sent {
                    message: Some(ref data_message),
                    ..
                }),
            ..
        }) => match data_message {
            DataMessage {
                delete:
                    Some(Delete {
                        target_sent_timestamp: Some(ts),
                    }),
                ..
            } => {
                // replace an existing message by an empty NullMessage
                if let Some(mut existing_msg) = config_store.message(&thread, *ts)? {
                    existing_msg.metadata.sender.uuid = Uuid::nil();
                    existing_msg.body = NullMessage::default().into();
                    config_store.save_message(&thread, existing_msg)?;
                    debug!("message in thread {thread} @ {ts} deleted");
                    None
                } else {
                    warn!("could not find message to delete in thread {thread} @ {ts}");
                    None
                }
            }
            _ => Some(message),
        },
        ContentBody::EditMessage(EditMessage {
            target_sent_timestamp: Some(ts),
            data_message: Some(data_message),
        })
        | ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(sync_message::Sent {
                    edit_message:
                        Some(EditMessage {
                            target_sent_timestamp: Some(ts),
                            data_message: Some(data_message),
                        }),
                    ..
                }),
            ..
        }) => {
            if let Some(mut existing_msg) = config_store.message(&thread, ts)? {
                existing_msg.metadata = message.metadata;
                existing_msg.body = ContentBody::DataMessage(data_message);
                // TODO: find a way to mark the message as edited (so that it's visible in a client)
                trace!("message in thread {thread} @ {ts} edited");
                Some(existing_msg)
            } else {
                warn!("could not find edited message {thread} @ {ts}");
                None
            }
        }
        ContentBody::CallMessage(_)
        | ContentBody::SynchronizeMessage(SyncMessage {
            call_event: Some(_),
            ..
        }) => Some(message),
        ContentBody::SynchronizeMessage(s) => {
            debug!("skipping saving sync message without interesting fields: {s:?}");
            None
        }
        ContentBody::ReceiptMessage(_) => {
            debug!("skipping saving receipt message");
            None
        }
        ContentBody::TypingMessage(_) => {
            debug!("skipping saving typing message");
            None
        }
        ContentBody::StoryMessage(_) => {
            debug!("skipping story message");
            None
        }
        ContentBody::PniSignatureMessage(_) => {
            debug!("skipping PNI signature message");
            None
        }
        ContentBody::EditMessage(_) => {
            debug!("invalid edited");
            None
        }
    };

    if let Some(message) = message {
        config_store.save_message(&thread, message)?;
    }

    Ok(())
}
