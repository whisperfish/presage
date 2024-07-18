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
use libsignal_service::messagepipe::{Incoming, MessagePipe, ServiceCredentials};
use libsignal_service::models::Contact;
use libsignal_service::prelude::phonenumber::PhoneNumber;
use libsignal_service::prelude::{MessageSenderError, ProtobufMessage, Uuid};
use libsignal_service::profile_cipher::ProfileCipher;
use libsignal_service::proto::data_message::Delete;
use libsignal_service::proto::{
    sync_message::{self, sticker_pack_operation, StickerPackOperation},
    AttachmentPointer, DataMessage, EditMessage, GroupContextV2, NullMessage, SyncMessage,
    Verified,
};
use libsignal_service::protocol::{IdentityKeyStore, SenderCertificate};
use libsignal_service::provisioning::{generate_registration_id, ProvisioningError};
use libsignal_service::push_service::{
    AccountAttributes, DeviceCapabilities, DeviceInfo, PushService, ServiceError, ServiceIdType,
    ServiceIds, WhoAmIResponse, DEFAULT_DEVICE_ID,
};
use libsignal_service::receiver::MessageReceiver;
use libsignal_service::sender::{AttachmentSpec, AttachmentUploadError};
use libsignal_service::sticker_cipher::derive_key;
use libsignal_service::unidentified_access::UnidentifiedAccess;
use libsignal_service::utils::serde_signaling_key;
use libsignal_service::websocket::SignalWebSocket;
use libsignal_service::zkgroup::groups::{GroupMasterKey, GroupSecretParams};
use libsignal_service::zkgroup::profiles::ProfileKey;
use libsignal_service::{cipher, AccountManager, Profile, ServiceAddress};
use libsignal_service_hyper::push_service::HyperPushService;
use log::{debug, error, info, trace, warn};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::sync::Mutex;
use url::Url;

use crate::cache::CacheCell;
use crate::serde::serde_profile_key;
use crate::store::{ContentsStore, Sticker, StickerPack, StickerPackManifest, Store, Thread};
use crate::{AvatarBytes, Error, Manager};

type ServiceCipher<S> = cipher::ServiceCipher<S, StdRng>;
type MessageSender<S> = libsignal_service::prelude::MessageSender<HyperPushService, S, StdRng>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationType {
    Primary,
    Secondary,
}

/// Manager state when the client is registered and can send and receive messages from Signal
#[derive(Clone)]
pub struct Registered {
    pub(crate) identified_push_service: CacheCell<HyperPushService>,
    pub(crate) unidentified_push_service: CacheCell<HyperPushService>,
    pub(crate) identified_websocket: Arc<Mutex<Option<SignalWebSocket>>>,
    pub(crate) unidentified_websocket: Arc<Mutex<Option<SignalWebSocket>>>,
    pub(crate) unidentified_sender_certificate: Option<SenderCertificate>,

    pub(crate) data: RegistrationData,
}

impl fmt::Debug for Registered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registered").finish_non_exhaustive()
    }
}

impl Registered {
    pub(crate) fn with_data(data: RegistrationData) -> Self {
        Self {
            identified_push_service: CacheCell::default(),
            unidentified_push_service: CacheCell::default(),
            identified_websocket: Default::default(),
            unidentified_websocket: Default::default(),
            unidentified_sender_certificate: Default::default(),
            data,
        }
    }

    fn service_configuration(&self) -> ServiceConfiguration {
        self.data.signal_servers.into()
    }

    pub fn device_id(&self) -> u32 {
        self.data.device_id.unwrap_or(DEFAULT_DEVICE_ID)
    }
}

/// Registration data like device name, and credentials to connect to Signal
#[derive(Serialize, Deserialize, Clone)]
pub struct RegistrationData {
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
    #[serde(with = "serde_profile_key")]
    pub(crate) profile_key: ProfileKey,
}

impl RegistrationData {
    /// Account identity
    pub fn aci(&self) -> Uuid {
        self.service_ids.aci
    }

    /// Phone number identity
    pub fn pni(&self) -> Uuid {
        self.service_ids.pni
    }

    /// Our own profile key
    pub fn profile_key(&self) -> ProfileKey {
        self.profile_key
    }

    /// The name of the device (if linked as secondary)
    pub fn device_name(&self) -> Option<&str> {
        self.device_name.as_deref()
    }
}

impl<S: Store> Manager<S, Registered> {
    /// Loads a previously registered account from the implemented [Store].
    ///
    /// Returns a instance of [Manager] you can use to send & receive messages.
    pub async fn load_registered(store: S) -> Result<Self, Error<S::Error>> {
        let registration_data = store
            .load_registration_data()?
            .ok_or(Error::NotYetRegisteredError)?;

        let mut manager = Self {
            rng: StdRng::from_entropy(),
            store,
            state: Registered::with_data(registration_data),
        };

        if manager.state.data.pni_registration_id.is_none() {
            manager.set_account_attributes().await?;
        }

        manager.register_pre_keys().await?;

        Ok(manager)
    }

    /// Returns a handle to the [Store] implementation.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Returns a handle on the [RegistrationData].
    pub fn registration_data(&self) -> &RegistrationData {
        &self.state.data
    }

    /// Returns a clone of a cached push service (with credentials).
    ///
    /// If no service is yet cached, it will create and cache one.
    fn identified_push_service(&self) -> HyperPushService {
        self.state.identified_push_service.get(|| {
            HyperPushService::new(
                self.state.service_configuration(),
                self.credentials(),
                crate::USER_AGENT.to_string(),
            )
        })
    }

    /// Returns a clone of a cached push service (without credentials).
    ///
    /// If no service is yet cached, it will create and cache one.
    fn unidentified_push_service(&self) -> HyperPushService {
        self.state.unidentified_push_service.get(|| {
            HyperPushService::new(
                self.state.service_configuration(),
                None,
                crate::USER_AGENT.to_string(),
            )
        })
    }

    /// Returns the current identified websocket, or creates a new one
    ///
    /// A new one is created if the current websocket is closed, or if there is none yet.
    async fn identified_websocket(
        &self,
        require_unused: bool,
    ) -> Result<SignalWebSocket, Error<S::Error>> {
        let mut identified_ws = self.state.identified_websocket.lock().await;
        match identified_ws
            .as_ref()
            .filter(|ws| !ws.is_closed())
            .filter(|ws| !(require_unused && ws.is_used()))
        {
            Some(ws) => Ok(ws.clone()),
            None => {
                let headers = &[("X-Signal-Receive-Stories", "false")];
                let ws = self
                    .identified_push_service()
                    .ws(
                        "/v1/websocket/",
                        "/v1/keepalive",
                        headers,
                        self.credentials(),
                    )
                    .await?;
                identified_ws.replace(ws.clone());
                debug!("initialized identified websocket");

                Ok(ws)
            }
        }
    }

    /// Returns the current unidentified websocket, or creates a new one
    ///
    /// A new one is created if the current websocket is closed, or if there is none yet.
    async fn unidentified_websocket(&self) -> Result<SignalWebSocket, Error<S::Error>> {
        let mut unidentified_ws = self.state.unidentified_websocket.lock().await;
        match unidentified_ws.as_ref().filter(|ws| !ws.is_closed()) {
            Some(ws) => Ok(ws.clone()),
            None => {
                let ws = self
                    .unidentified_push_service()
                    .ws("/v1/websocket/", "/v1/keepalive", &[], None)
                    .await?;
                unidentified_ws.replace(ws.clone());
                debug!("initialized unidentified websocket");

                Ok(ws)
            }
        }
    }

    pub(crate) async fn register_pre_keys(&mut self) -> Result<(), Error<S::Error>> {
        trace!("registering pre keys");
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            Some(self.state.data.profile_key),
        );

        account_manager
            .update_pre_key_bundle(
                &mut self.store.aci_protocol_store(),
                ServiceIdType::AccountIdentity,
                &mut self.rng,
                true,
            )
            .await?;

        account_manager
            .update_pre_key_bundle(
                &mut self.store.pni_protocol_store(),
                ServiceIdType::PhoneNumberIdentity,
                &mut self.rng,
                true,
            )
            .await?;

        trace!("registered pre keys");
        Ok(())
    }

    pub(crate) async fn set_account_attributes(&mut self) -> Result<(), Error<S::Error>> {
        trace!("setting account attributes");
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            Some(self.state.data.profile_key),
        );

        let pni_registration_id =
            if let Some(pni_registration_id) = self.state.data.pni_registration_id {
                pni_registration_id
            } else {
                info!("migrating to PNI");
                let pni_registration_id = generate_registration_id(&mut StdRng::from_entropy());
                self.store.save_registration_data(&self.state.data)?;
                pni_registration_id
            };

        account_manager
            .set_account_attributes(AccountAttributes {
                name: self.state.data.device_name().map(|d| d.to_string()),
                registration_id: self.state.data.registration_id,
                pni_registration_id,
                signaling_key: None,
                voice: false,
                video: false,
                fetches_messages: true,
                pin: None,
                registration_lock: None,
                unidentified_access_key: Some(
                    self.state.data.profile_key.derive_access_key().to_vec(),
                ),
                unrestricted_unidentified_access: false,
                discoverable_by_phone_number: true,
                capabilities: DeviceCapabilities {
                    gift_badges: true,
                    payment_activation: false,
                    pni: true,
                    sender_key: true,
                    stories: false,
                    ..Default::default()
                },
            })
            .await?;

        if self.state.data.pni_registration_id.is_none() {
            debug!("fetching PNI UUID and updating state");
            let whoami = self.whoami().await?;
            self.state.data.service_ids.pni = whoami.pni;
            self.store.save_registration_data(&self.state.data)?;
        }

        trace!("done setting account attributes");
        Ok(())
    }

    /// Requests contacts synchronization and waits until the primary device sends them
    ///
    /// Note: DO NOT call this function if you're already running a receiving loop
    pub async fn sync_contacts(&mut self) -> Result<(), Error<S::Error>> {
        debug!("synchronizing contacts");

        let mut messages = pin!(
            self.receive_messages(ReceivingMode::WaitForContacts)
                .await?
        );

        self.request_contacts().await?;

        tokio::time::timeout(Duration::from_secs(60), async move {
            while let Some(msg) = messages.next().await {
                log::trace!("got message while waiting for contacts sync: {msg:?}");
            }
        })
        .await?;

        Ok(())
    }

    /// Request the primary device to encrypt & send all of its contacts.
    ///
    /// **Note**: If successful, the contacts are not yet received and stored, but will only be
    /// processed when they're received after polling on the
    pub async fn request_contacts(&mut self) -> Result<(), Error<S::Error>> {
        trace!("requesting contacts sync");
        let sync_message = SyncMessage {
            request: Some(sync_message::Request {
                r#type: Some(sync_message::request::Type::Contacts.into()),
            }),
            ..SyncMessage::with_padding()
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci, sync_message, timestamp)
            .await?;

        Ok(())
    }

    async fn sender_certificate(&mut self) -> Result<SenderCertificate, Error<S::Error>> {
        let needs_renewal = |sender_certificate: Option<&SenderCertificate>| -> bool {
            if sender_certificate.is_none() {
                return true;
            }

            let seconds_since_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            if let Some(expiration) = sender_certificate.and_then(|s| s.expiration().ok()) {
                seconds_since_epoch <= expiration.epoch_millis() / 1000 + 600
            } else {
                true
            }
        };

        if needs_renewal(self.state.unidentified_sender_certificate.as_ref()) {
            let sender_certificate = self
                .identified_push_service()
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
    ) -> Result<(), Error<S::Error>> {
        let mut account_manager = AccountManager::new(self.identified_push_service(), None);
        account_manager
            .submit_recaptcha_challenge(token, captcha)
            .await?;
        Ok(())
    }

    /// Fetches basic information on the registered device.
    pub async fn whoami(&self) -> Result<WhoAmIResponse, Error<S::Error>> {
        Ok(self.identified_push_service().whoami().await?)
    }

    pub fn device_id(&self) -> u32 {
        return self.state.device_id();
    }

    /// Fetches the profile (name, about, status emoji) of the registered user.
    pub async fn retrieve_profile(&mut self) -> Result<Profile, Error<S::Error>> {
        self.retrieve_profile_by_uuid(self.state.data.service_ids.aci, self.state.data.profile_key)
            .await
    }

    /// Fetches the profile of the provided user by UUID and profile key.
    pub async fn retrieve_profile_by_uuid(
        &mut self,
        uuid: Uuid,
        profile_key: ProfileKey,
    ) -> Result<Profile, Error<S::Error>> {
        // Check if profile is cached.
        // TODO: Create a migration in the store removing all profiles.
        // TODO: Is there some way to know if this is outdated?
        if let Some(profile) = self.store.profile(uuid, profile_key).ok().flatten() {
            return Ok(profile);
        }

        let mut account_manager =
            AccountManager::new(self.identified_push_service(), Some(profile_key));

        let profile = account_manager.retrieve_profile(uuid.into()).await?;

        let _ = self.store.save_profile(uuid, profile_key, profile.clone());
        Ok(profile)
    }

    pub async fn retrieve_group_avatar(
        &mut self,
        context: GroupContextV2,
    ) -> Result<Option<AvatarBytes>, Error<S::Error>> {
        let master_key_bytes = context
            .master_key()
            .try_into()
            .expect("Master key bytes to be of size 32.");

        // Check if group avatar is cached.
        // TODO: Is there some way to know if this is outdated?
        if let Some(avatar) = self.store.group_avatar(master_key_bytes).ok().flatten() {
            return Ok(Some(avatar));
        }

        let mut gm = self.groups_manager()?;
        let Some(group) = upsert_group(
            self.store(),
            &mut gm,
            context.master_key(),
            &context.revision(),
        )
        .await?
        else {
            return Ok(None);
        };

        // Empty path means no avatar was set.
        if group.avatar.is_empty() {
            return Ok(None);
        }

        let avatar = gm
            .retrieve_avatar(
                &group.avatar,
                GroupSecretParams::derive_from_master_key(GroupMasterKey::new(master_key_bytes)),
            )
            .await?;
        if let Some(avatar) = &avatar {
            let _ = self.store.save_group_avatar(master_key_bytes, avatar);
        }
        Ok(avatar)
    }

    pub async fn retrieve_profile_avatar_by_uuid(
        &mut self,
        uuid: Uuid,
        profile_key: ProfileKey,
    ) -> Result<Option<AvatarBytes>, Error<S::Error>> {
        // Check if profile avatar is cached.
        // TODO: Is there some way to know if this is outdated?
        if let Some(avatar) = self.store.profile_avatar(uuid, profile_key).ok().flatten() {
            return Ok(Some(avatar));
        }

        let profile = if let Some(profile) = self.store.profile(uuid, profile_key).ok().flatten() {
            profile
        } else {
            self.retrieve_profile_by_uuid(uuid, profile_key).await?
        };

        let Some(avatar) = profile.avatar.as_ref() else {
            return Ok(None);
        };

        let mut service = self.unidentified_push_service();

        let mut avatar_stream = service.retrieve_profile_avatar(avatar).await?;
        // 10MB is what Signal Android allocates
        let mut contents = Vec::with_capacity(10 * 1024 * 1024);
        let len = avatar_stream.read_to_end(&mut contents).await?;
        contents.truncate(len);

        let cipher = ProfileCipher::from(profile_key);

        let avatar = cipher.decrypt_avatar(&contents)?;
        let _ = self.store.save_profile_avatar(uuid, profile_key, &avatar);
        Ok(Some(avatar))
    }

    /// Gets an iterator of messages in a thread, optionally starting from a point in time.
    pub fn messages(
        &self,
        thread: &Thread,
        range: impl RangeBounds<u64>,
    ) -> Result<S::MessagesIter, Error<S::Error>> {
        Ok(self.store.messages(thread, range)?)
    }

    async fn receive_messages_encrypted(
        &mut self,
    ) -> Result<impl Stream<Item = Result<Incoming, ServiceError>>, Error<S::Error>> {
        let credentials = self.credentials().ok_or(Error::NotYetRegisteredError)?;
        let ws = self.identified_websocket(true).await?;
        let pipe = MessagePipe::from_socket(ws, credentials);
        Ok(pipe.stream())
    }

    /// Starts receiving and storing messages.
    ///
    /// As a client, it is heavily recommended to run this once in `ReceivingMode::InitialSync` once
    /// before enabling the possiblity of sending messages. That way, all possible updates (sessions, profile keys, sender keys)
    /// are processed _before_ trying to encrypt and send messages which might fail otherwise.
    ///
    /// Returns a [futures::Stream] of messages to consume. Messages will also be stored by the implementation of the [Store].
    pub async fn receive_messages(
        &mut self,
        mode: ReceivingMode,
    ) -> Result<impl Stream<Item = Content>, Error<S::Error>> {
        self.receive_messages_stream(mode).await
    }

    fn groups_manager(
        &self,
    ) -> Result<GroupsManager<HyperPushService, InMemoryCredentialsCache>, Error<S::Error>> {
        let service_configuration = self.state.service_configuration();
        let server_public_params = service_configuration.zkgroup_server_public_params;

        let groups_credentials_cache = InMemoryCredentialsCache::default();
        let groups_manager = GroupsManager::new(
            self.state.data.service_ids.clone(),
            self.identified_push_service(),
            groups_credentials_cache,
            server_public_params,
        );

        Ok(groups_manager)
    }

    async fn receive_messages_stream(
        &mut self,
        mode: ReceivingMode,
    ) -> Result<impl Stream<Item = Content>, Error<S::Error>> {
        struct StreamState<Receiver, Store, AciStore> {
            encrypted_messages: Receiver,
            message_receiver: MessageReceiver<HyperPushService>,
            service_cipher: ServiceCipher<AciStore>,
            push_service: HyperPushService,
            store: Store,
            groups_manager: GroupsManager<HyperPushService, InMemoryCredentialsCache>,
            mode: ReceivingMode,
        }

        let push_service = self.identified_push_service();

        let init = StreamState {
            encrypted_messages: Box::pin(self.receive_messages_encrypted().await?),
            message_receiver: MessageReceiver::new(push_service.clone()),
            service_cipher: self.new_service_cipher()?,
            push_service,
            store: self.store.clone(),
            groups_manager: self.groups_manager()?,
            mode,
        };

        debug!("starting to consume incoming message stream");

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
                                            let _ = state.store.clear_contacts();
                                            info!("saving contacts");
                                            for contact in contacts.filter_map(Result::ok) {
                                                if let Err(e) = state.store.save_contact(&contact) {
                                                    warn!("failed to save contacts: {e}");
                                                    break;
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

                                // sticker pack operations
                                if let ContentBody::SynchronizeMessage(SyncMessage {
                                    sticker_pack_operation,
                                    ..
                                }) = &content.body
                                {
                                    for operation in sticker_pack_operation {
                                        match operation.r#type() {
                                            sticker_pack_operation::Type::Install => {
                                                let store = state.store.clone();
                                                let push_service = state.push_service.clone();
                                                let operation = operation.clone();

                                                // download stickers in the background
                                                tokio::spawn(async move {
                                                    match download_sticker_pack(
                                                        store,
                                                        push_service,
                                                        &operation,
                                                    )
                                                    .await
                                                    {
                                                        Ok(sticker_pack) => {
                                                            debug!(
                                                                "downloaded sticker pack: {} made by {}",
                                                                sticker_pack.manifest.title,
                                                                sticker_pack.manifest.author
                                                            );
                                                        }
                                                        Err(error) => error!(
                                                            "failed to download sticker pack: {error}"
                                                        ),
                                                    }
                                                });
                                            }
                                            sticker_pack_operation::Type::Remove => {
                                                match state
                                                    .store
                                                    .remove_sticker_pack(operation.pack_id())
                                                {
                                                    Ok(removed) => {
                                                        debug!(
                                                            "removed stick pack: present={removed}"
                                                        )
                                                    }
                                                    Err(error) => {
                                                        error!(
                                                            "failed to remove sticker pack: {error}"
                                                        )
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                // group update
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
                                        &state.store,
                                        &mut state.groups_manager,
                                        master_key_bytes,
                                        revision,
                                    )
                                    .await
                                    {
                                        trace!("{group:?}");
                                    }
                                }

                                if let Err(e) = save_message(
                                    &mut state.store,
                                    &mut state.push_service,
                                    content.clone(),
                                    None,
                                )
                                .await
                                {
                                    error!("Error saving message to store: {}", e);
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
    ) -> Result<(), Error<S::Error>> {
        let mut sender = self.new_message_sender().await?;

        let online_only = false;
        // TODO: Populate this flag based on the recipient information
        //
        // Issue <https://github.com/whisperfish/presage/issues/252>
        let include_pni_signature = false;
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
                    .store
                    .expire_timer(&Thread::Contact(recipient.uuid))
                    .unwrap_or_default();

                *timer = store_expire_timer;
            }
            _ => {}
        }

        let sender_certificate = self.sender_certificate().await?;
        let unidentified_access =
            self.store
                .profile_key(&recipient.uuid)?
                .map(|profile_key| UnidentifiedAccess {
                    key: profile_key.derive_access_key().to_vec(),
                    certificate: sender_certificate.clone(),
                });

        // we need to put our profile key in DataMessage
        if let ContentBody::DataMessage(message) = &mut content_body {
            message
                .profile_key
                .get_or_insert(self.state.data.profile_key().get_bytes().to_vec());
            message.required_protocol_version = Some(0);
        }

        sender
            .send_message(
                &recipient,
                unidentified_access,
                content_body.clone(),
                timestamp,
                online_only,
                include_pni_signature,
            )
            .await?;

        // save the message
        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci.into(),
                sender_device: self.state.device_id(),
                server_guid: None,
                timestamp,
                needs_receipt: false,
                unidentified_sender: false,
            },
            body: content_body,
        };

        let mut push_service = self.identified_push_service();
        save_message(
            &mut self.store,
            &mut push_service,
            content,
            Some(Thread::Contact(recipient.uuid)),
        )
        .await?;

        Ok(())
    }

    /// Uploads attachments prior to linking them in a message.
    pub async fn upload_attachments(
        &self,
        attachments: Vec<(AttachmentSpec, Vec<u8>)>,
    ) -> Result<Vec<Result<AttachmentPointer, AttachmentUploadError>>, Error<S::Error>> {
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
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        let mut content_body = message.into();
        let master_key_bytes = master_key_bytes
            .try_into()
            .expect("Master key bytes to be of size 32.");

        // Only update the expiration timer if it is not set.
        match content_body {
            ContentBody::DataMessage(DataMessage {
                expire_timer: ref mut timer,
                ..
            }) if timer.is_none() => {
                // Set the expire timer to None for errors.
                let store_expire_timer = self
                    .store
                    .expire_timer(&Thread::Group(master_key_bytes))
                    .unwrap_or_default();

                *timer = store_expire_timer;
            }
            _ => {}
        }
        let mut sender = self.new_message_sender().await?;

        let mut groups_manager = self.groups_manager()?;
        let Some(group) =
            upsert_group(&self.store, &mut groups_manager, &master_key_bytes, &0).await?
        else {
            return Err(Error::UnknownGroup);
        };

        let sender_certificate = self.sender_certificate().await?;
        let mut recipients = Vec::new();
        for member in group
            .members
            .into_iter()
            .filter(|m| m.uuid != self.state.data.service_ids.aci)
        {
            let unidentified_access =
                self.store
                    .profile_key(&member.uuid)?
                    .map(|profile_key| UnidentifiedAccess {
                        key: profile_key.derive_access_key().to_vec(),
                        certificate: sender_certificate.clone(),
                    });
            let include_pni_signature = true;
            recipients.push((
                member.uuid.into(),
                unidentified_access,
                include_pni_signature,
            ));
        }

        let online_only = false;
        let results = sender
            .send_message_to_group(recipients, content_body.clone(), timestamp, online_only)
            .await;

        // TODO: Handle the NotFound error in the future by removing all sessions to this UUID and marking it as unregistered, not sending any messages to this contact anymore.
        results
            .into_iter()
            .find(|res| match res {
                Ok(_) => false,
                // Ignore any NotFound errors, those mean that e.g. some contact in a group deleted his account.
                Err(MessageSenderError::NotFound { uuid }) => {
                    debug!("UUID {uuid} not found, skipping sent message result");
                    false
                }
                // return first error if any
                Err(_) => true,
            })
            .transpose()?;

        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci.into(),
                sender_device: self.state.device_id(),
                server_guid: None,
                timestamp,
                needs_receipt: false, // TODO: this is just wrong
                unidentified_sender: false,
            },
            body: content_body,
        };

        let mut push_service = self.identified_push_service();
        save_message(
            &mut self.store,
            &mut push_service,
            content,
            Some(Thread::Group(master_key_bytes)),
        )
        .await?;

        Ok(())
    }

    /// Clears all sessions established wiht [recipient](ServiceAddress).
    pub async fn clear_sessions(&self, recipient: &ServiceAddress) -> Result<(), Error<S::Error>> {
        use libsignal_service::session_store::SessionStoreExt;
        self.store
            .aci_protocol_store()
            .delete_all_sessions(recipient)
            .await?;
        self.store
            .pni_protocol_store()
            .delete_all_sessions(recipient)
            .await?;
        Ok(())
    }

    /// Downloads and decrypts a single attachment.
    pub async fn get_attachment(
        &self,
        attachment_pointer: &AttachmentPointer,
    ) -> Result<Vec<u8>, Error<S::Error>> {
        let expected_digest = attachment_pointer
            .digest
            .as_ref()
            .ok_or_else(|| Error::UnexpectedAttachmentChecksum)?;

        let mut service = self.identified_push_service();
        let mut attachment_stream = service.get_attachment(attachment_pointer).await?;

        // We need the whole file for the crypto to check out
        let mut ciphertext = Vec::new();
        let len = attachment_stream.read_to_end(&mut ciphertext).await?;
        trace!("downloaded encrypted attachment of {} bytes", len);

        let digest = sha2::Sha256::digest(&ciphertext);
        if &digest[..] != expected_digest {
            return Err(Error::UnexpectedAttachmentChecksum);
        }

        let key: [u8; 64] = attachment_pointer.key().try_into()?;
        decrypt_in_place(key, &mut ciphertext)?;

        Ok(ciphertext)
    }

    /// Gets an iterator over installed sticker packs
    pub async fn sticker_packs(&self) -> Result<S::StickerPacksIter, Error<S::Error>> {
        Ok(self.store.sticker_packs()?)
    }

    /// Gets a sticker pack by id
    pub async fn sticker_pack(
        &self,
        pack_id: &[u8],
    ) -> Result<Option<StickerPack>, Error<S::Error>> {
        Ok(self.store.sticker_pack(pack_id)?)
    }

    /// Gets the metadata of a sticker
    pub async fn sticker_metadata(
        &mut self,
        pack_id: &[u8],
        sticker_id: u32,
    ) -> Result<Option<Sticker>, Error<S::Error>> {
        Ok(self.store.sticker_pack(pack_id)?.and_then(|pack| {
            pack.manifest
                .stickers
                .iter()
                .find(|&x| x.id == sticker_id)
                .cloned()
        }))
    }

    /// Installs a sticker pack and notifies other registered devices
    pub async fn install_sticker_pack(
        &mut self,
        pack_id: &[u8],
        pack_key: &[u8],
    ) -> Result<(), Error<S::Error>> {
        let sticker_pack_operation = StickerPackOperation {
            pack_id: Some(pack_id.to_vec()),
            pack_key: Some(pack_key.to_vec()),
            r#type: Some(sticker_pack_operation::Type::Install as i32),
        };

        let push_service = self.unidentified_push_service();
        download_sticker_pack(self.store.clone(), push_service, &sticker_pack_operation).await?;

        // Sync the change with the other devices
        let sync_message = SyncMessage {
            sticker_pack_operation: vec![sticker_pack_operation],
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.aci(), sync_message, timestamp)
            .await?;

        Ok(())
    }

    /// Removes an installed sticker pack
    pub async fn remove_sticker_pack(
        &mut self,
        pack_id: &[u8],
        pack_key: &[u8],
    ) -> Result<(), Error<S::Error>> {
        // Sync the change with the other clients
        let sync_message = SyncMessage {
            sticker_pack_operation: vec![StickerPackOperation {
                pack_id: Some(pack_id.to_vec()),
                pack_key: Some(pack_key.to_vec()), // The pack key might not be neccesary in the message
                r#type: Some(sticker_pack_operation::Type::Remove as i32),
            }],
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.aci(), sync_message, timestamp)
            .await?;

        self.store.remove_sticker_pack(pack_id)?;

        Ok(())
    }

    pub async fn send_session_reset(
        &mut self,
        recipient: &ServiceAddress,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        trace!("Resetting session for address: {}", recipient.uuid);
        let message = DataMessage {
            flags: Some(DataMessageFlags::EndSession as u32),
            ..Default::default()
        };

        self.send_message(*recipient, message, timestamp).await?;

        Ok(())
    }

    fn credentials(&self) -> Option<ServiceCredentials> {
        Some(ServiceCredentials {
            aci: Some(self.state.data.service_ids.aci),
            pni: Some(self.state.data.service_ids.pni),
            phonenumber: self.state.data.phone_number.clone(),
            password: Some(self.state.data.password.clone()),
            signaling_key: Some(self.state.data.signaling_key),
            device_id: self.state.data.device_id,
        })
    }

    /// Creates a new message sender.
    async fn new_message_sender(&self) -> Result<MessageSender<S::AciStore>, Error<S::Error>> {
        let identified_websocket = self.identified_websocket(false).await?;
        let unidentified_websocket = self.unidentified_websocket().await?;

        let aci_protocol_store = self.store.aci_protocol_store();
        let aci_identity_keypair = aci_protocol_store.get_identity_key_pair().await?;
        let pni_identity_keypair = self
            .store
            .pni_protocol_store()
            .get_identity_key_pair()
            .await?;

        Ok(MessageSender::new(
            identified_websocket,
            unidentified_websocket,
            self.identified_push_service(),
            self.new_service_cipher()?,
            self.rng.clone(),
            aci_protocol_store,
            self.state.data.service_ids.aci,
            self.state.data.service_ids.pni,
            aci_identity_keypair,
            Some(pni_identity_keypair),
            self.state.device_id().into(),
        ))
    }

    /// Creates a new service cipher.
    fn new_service_cipher(&self) -> Result<ServiceCipher<S::AciStore>, Error<S::Error>> {
        let service_cipher = ServiceCipher::new(
            self.store.aci_protocol_store(),
            self.rng.clone(),
            self.state
                .service_configuration()
                .unidentified_sender_trust_root,
            self.state.data.service_ids.aci,
            self.state.device_id(),
        );

        Ok(service_cipher)
    }

    /// Returns the title of a thread (contact or group).
    pub async fn thread_title(&self, thread: &Thread) -> Result<String, Error<S::Error>> {
        match thread {
            Thread::Contact(uuid) => {
                let contact = match self.store.contact_by_id(uuid) {
                    Ok(contact) => contact,
                    Err(e) => {
                        info!("Error getting contact by id: {}, {:?}", e, uuid);
                        None
                    }
                };
                Ok(match contact {
                    Some(contact) => contact.name,
                    None => uuid.to_string(),
                })
            }
            Thread::Group(id) => match self.store.group(*id)? {
                Some(group) => Ok(group.title),
                None => Ok("".to_string()),
            },
        }
    }

    /// Returns how this client was registered, either as a primary or secondary device.
    pub fn registration_type(&self) -> RegistrationType {
        if self.state.data.device_name.is_some() {
            RegistrationType::Secondary
        } else {
            RegistrationType::Primary
        }
    }

    /// As a primary device, link a secondary device.
    pub async fn link_secondary(&self, secondary: Url) -> Result<(), Error<S::Error>> {
        // XXX: What happens if secondary device? Possible to use static typing to make this method call impossible in that case?
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }

        let credentials = self.credentials().ok_or(Error::NotYetRegisteredError)?;
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            Some(self.state.data.profile_key),
        );
        let store = self.store();

        account_manager
            .link_device(
                secondary,
                &store.aci_protocol_store(),
                &store.pni_protocol_store(),
                credentials,
            )
            .await?;
        Ok(())
    }

    /// As a primary device, unlink a secondary device.
    pub async fn unlink_secondary(&self, device_id: i64) -> Result<(), Error<S::Error>> {
        // XXX: What happens if secondary device? Possible to use static typing to make this method call impossible in that case?
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }
        self.identified_push_service()
            .unlink_device(device_id)
            .await?;
        Ok(())
    }

    /// As a primary device, list all the devices (including the current device).
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>, Error<S::Error>> {
        let aci_protocol_store = self.store.aci_protocol_store();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            Some(self.state.data.profile_key),
        );

        Ok(account_manager.linked_devices(&aci_protocol_store).await?)
    }

    /// Deprecated methods

    /// Get a single contact by its UUID
    ///
    /// Note: this only currently works when linked as secondary device (the contacts are sent by the primary device at linking time)
    #[deprecated = "use the store handle directly"]
    pub fn contact_by_id(&self, id: &Uuid) -> Result<Option<Contact>, Error<S::Error>> {
        Ok(self.store.contact_by_id(id)?)
    }

    /// Returns an iterator on contacts stored in the [Store].
    #[deprecated = "use the store handle directly"]
    pub fn contacts(
        &self,
    ) -> Result<impl Iterator<Item = Result<Contact, Error<S::Error>>>, Error<S::Error>> {
        let iter = self.store.contacts()?;
        Ok(iter.map(|r| r.map_err(Into::into)))
    }

    /// Get a group (either from the local cache, or fetch it remotely) using its master key
    #[deprecated = "use the store handle directly"]
    pub fn group(&self, master_key_bytes: &[u8]) -> Result<Option<Group>, Error<S::Error>> {
        Ok(self.store.group(master_key_bytes.try_into()?)?)
    }

    /// Returns an iterator on groups stored in the [Store].
    #[deprecated = "use the store handle directly"]
    pub fn groups(&self) -> Result<S::GroupsIter, Error<S::Error>> {
        Ok(self.store.groups()?)
    }

    /// Get a single message in a thread (identified by its server-side sent timestamp)
    #[deprecated = "use the store handle directly"]
    pub fn message(
        &self,
        thread: &Thread,
        timestamp: u64,
    ) -> Result<Option<Content>, Error<S::Error>> {
        Ok(self.store.message(thread, timestamp)?)
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

async fn upsert_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<HyperPushService, InMemoryCredentialsCache>,
    master_key_bytes: &[u8],
    revision: &u32,
) -> Result<Option<Group>, Error<S::Error>> {
    let upsert_group = match store.group(master_key_bytes.try_into()?) {
        Ok(Some(group)) => {
            debug!("loaded group from local db {}", group.title);
            group.revision < *revision
        }
        Ok(None) => true,
        Err(e) => {
            warn!("failed to retrieve group from local db {}", e);
            true
        }
    };

    if upsert_group {
        debug!("fetching and saving group");
        match groups_manager.fetch_encrypted_group(master_key_bytes).await {
            Ok(encrypted_group) => {
                let group = decrypt_group(master_key_bytes, encrypted_group)?;
                if let Err(e) = store.save_group(master_key_bytes.try_into()?, &group) {
                    error!("failed to save group {master_key_bytes:?}: {e}",);
                }
            }
            Err(e) => {
                warn!("failed to fetch encrypted group: {e}")
            }
        }
    }

    Ok(store.group(master_key_bytes.try_into()?)?)
}

/// Download and decrypt a sticker manifest
async fn download_sticker_pack<C: ContentsStore>(
    mut store: C,
    mut push_service: HyperPushService,
    operation: &StickerPackOperation,
) -> Result<StickerPack, Error<C::ContentsStoreError>> {
    debug!("downloading sticker pack");
    let pack_key = operation.pack_key();
    let pack_id = operation.pack_id();
    let key = derive_key(pack_key)?;

    let mut ciphertext = Vec::new();

    let len = push_service
        .get_sticker_pack_manifest(&hex::encode(pack_id))
        .await?
        .read_to_end(&mut ciphertext)
        .await?;

    trace!(
        "downloaded encrypted sticker pack manifest of {} bytes",
        len
    );

    decrypt_in_place(key, &mut ciphertext)?;

    let mut sticker_pack_manifest: StickerPackManifest =
        libsignal_service::proto::Pack::decode(ciphertext.as_slice())
            .map_err(ProvisioningError::from)?
            .into();

    for sticker in &mut sticker_pack_manifest.stickers {
        match download_sticker(&mut store, &mut push_service, pack_id, pack_key, sticker.id).await {
            Ok(decrypted_sticker_bytes) => {
                debug!("downloaded sticker {}", sticker.id);
                sticker.bytes = Some(decrypted_sticker_bytes);
            }
            Err(error) => error!("failed to download sticker {}: {error}", sticker.id),
        }
    }

    let sticker_pack = StickerPack {
        id: pack_id.to_vec(),
        key: pack_key.to_vec(),
        manifest: sticker_pack_manifest,
    };

    // save everything in store
    store.add_sticker_pack(&sticker_pack)?;

    Ok(sticker_pack)
}

/// Downloads and decrypts a single sticker
async fn download_sticker<C: ContentsStore>(
    _store: &mut C,
    push_service: &mut HyperPushService,
    pack_id: &[u8],
    pack_key: &[u8],
    sticker_id: u32,
) -> Result<Vec<u8>, Error<C::ContentsStoreError>> {
    let key = derive_key(pack_key)?;

    let mut sticker_stream = push_service
        .get_sticker(&hex::encode(pack_id), sticker_id)
        .await?;

    let mut ciphertext = Vec::new();
    let len = sticker_stream.read_to_end(&mut ciphertext).await?;

    trace!("downloaded encrypted sticker of {} bytes", len);

    decrypt_in_place(key, &mut ciphertext)?;

    Ok(ciphertext)
}

/// Save a message into the store.
/// Note that `override_thread` can be used to specify the thread the message will be stored in.
/// This is required when storing outgoing messages, as in this case the appropriate storage place cannot be derived from the message itself.
async fn save_message<S: Store>(
    store: &mut S,
    push_service: &mut HyperPushService,
    message: Content,
    override_thread: Option<Thread>,
) -> Result<(), Error<S::Error>> {
    // derive the thread from the message type
    let thread = override_thread.unwrap_or(Thread::try_from(&message)?);

    // only save DataMessage and SynchronizeMessage (sent)
    let message = match message.body {
        ContentBody::NullMessage(_) => Some(message),
        ContentBody::DataMessage(
            ref data_message @ DataMessage {
                ref profile_key, ..
            },
        )
        | ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(sync_message::Sent {
                    message:
                        Some(
                            ref data_message @ DataMessage {
                                ref profile_key, ..
                            },
                        ),
                    ..
                }),
            ..
        }) => {
            // update recipient profile key if changed
            if let Some(profile_key_bytes) = profile_key.clone().and_then(|p| p.try_into().ok()) {
                let sender_uuid = message.metadata.sender.uuid;
                let profile_key = ProfileKey::create(profile_key_bytes);
                debug!("inserting profile key for {sender_uuid}");

                // Either:
                // - insert a new contact with the profile information
                // - update the contact if the profile key has changed
                // TODO: mark this contact as "created by us" maybe to know whether we should update it or not
                if store.contact_by_id(&sender_uuid)?.is_none()
                    || !store
                        .profile_key(&sender_uuid)?
                        .is_some_and(|p| p.bytes == profile_key.bytes)
                {
                    let encrypted_profile = push_service
                        .retrieve_profile_by_id(sender_uuid.into(), Some(profile_key))
                        .await?;
                    let profile_cipher = ProfileCipher::from(profile_key);
                    let decrypted_profile = encrypted_profile.decrypt(profile_cipher).unwrap();

                    let contact = Contact {
                        uuid: sender_uuid,
                        phone_number: None,
                        name: decrypted_profile
                            .name
                            // FIXME: this assumes [firstname] [lastname]
                            .map(|pn| {
                                if let Some(family_name) = pn.family_name {
                                    format!("{} {}", pn.given_name, family_name)
                                } else {
                                    pn.given_name
                                }
                            })
                            .unwrap_or_default(),
                        profile_key: profile_key.bytes.to_vec(),
                        color: None,
                        expire_timer: data_message.expire_timer.unwrap_or_default(),
                        inbox_position: 0,
                        archived: false,
                        avatar: None,
                        verified: Verified::default(),
                    };

                    info!("saved contact after seeing {sender_uuid} for the first time");
                    store.save_contact(&contact)?;
                }

                store.upsert_profile_key(&sender_uuid, profile_key)?;
            }

            if let Some(expire_timer) = data_message.expire_timer {
                store.update_expire_timer(&thread, expire_timer)?;
            }

            match data_message {
                DataMessage {
                    delete:
                        Some(Delete {
                            target_sent_timestamp: Some(ts),
                        }),
                    ..
                } => {
                    // replace an existing message by an empty NullMessage
                    if let Some(mut existing_msg) = store.message(&thread, *ts)? {
                        existing_msg.metadata.sender.uuid = Uuid::nil();
                        existing_msg.body = NullMessage::default().into();
                        store.save_message(&thread, existing_msg)?;
                        debug!("message in thread {thread} @ {ts} deleted");
                        None
                    } else {
                        warn!("could not find message to delete in thread {thread} @ {ts}");
                        None
                    }
                }
                _ => Some(message),
            }
        }
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
            if let Some(mut existing_msg) = store.message(&thread, ts)? {
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
        ContentBody::SynchronizeMessage(_) => {
            debug!("skipping saving sync message without interesting fields");
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
        store.save_message(&thread, message)?;
    }

    Ok(())
}
