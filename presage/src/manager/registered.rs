use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use chrono::TimeZone;
use futures::{future, AsyncReadExt};
use libsignal_service::prelude::SessionStoreExt;
use libsignal_service::protocol::{ProtocolAddress, SessionStore};
use libsignal_service::provisioning::ProvisioningSecrets;
use libsignal_service::{
    attachment_cipher::decrypt_in_place,
    cipher,
    configuration::{ServiceConfiguration, SignalServers},
    content::{Content, ContentBody, Metadata},
    encrypt_device_name,
    groups_v2::{decrypt_group, GroupsManager, InMemoryCredentialsCache},
    messagepipe::ServiceCredentials,
    prelude::{phonenumber::PhoneNumber, MessageSenderError, ProtobufMessage, Uuid},
    profile_cipher::ProfileCipher,
    proto::{
        data_message::Delete,
        sync_message::{
            self, sticker_pack_operation, Content as SyncContent, StickerPackOperation,
        },
        AttachmentPointer, DataMessage, EditMessage, GroupContextV2, NullMessage, SyncMessage,
        Verified,
    },
    protocol::{
        Aci, DeviceId, IdentityKeyStore, SenderCertificate, ServiceId, ServiceIdKind, Username,
    },
    provisioning::ProvisioningError,
    push_service::{PushService, ServiceIds, DEFAULT_DEVICE_ID},
    sender::{AttachmentSpec, AttachmentUploadError},
    sticker_cipher::derive_key,
    unidentified_access::UnidentifiedAccess,
    utils::TryIntoE164,
    websocket::{
        self,
        account::{AccountAttributes, DeviceCapabilities, DeviceInfo, WhoAmIResponse},
        calling::TurnServer,
        SignalWebSocket,
    },
    zkgroup::{
        groups::{GroupMasterKey, GroupSecretParams},
        profiles::ProfileKey,
        GroupMasterKeyBytes,
    },
    AccountManager, Profile, ServiceIdExt,
};
use libsignal_service::{
    libsignal_account_keys::AccountEntropyPool, proto::addressable_message::Author,
};
use rand::rng;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use tokio::sync::Mutex;
use tracing::{debug, error, info, trace, warn};
use url::Url;

use super::account_keys::AccountKeys;
use super::keep::keep_profile_key;
use crate::model::contacts::Contact;
use crate::model::previews;
use crate::serde::serde_profile_key;
use crate::store::{ContentsStore, Sticker, StickerPack, StickerPackManifest, Store, Thread};
use crate::{model::groups::Group, AvatarBytes, Error, Manager};
use libsignal_service::proto::{manifest_record, storage_record};
use libsignal_service::StorageService;

mod jobs;
mod receive;

type ServiceCipher<S> = cipher::ServiceCipher<S>;
type MessageSender<S> = libsignal_service::prelude::MessageSender<S>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegistrationType {
    Primary,
    Secondary,
}

/// Manager state when the client is registered and can send and receive messages from Signal
#[derive(Clone)]
pub struct Registered {
    pub(crate) identified_push_service: OnceLock<PushService>,
    pub(crate) unidentified_push_service: OnceLock<PushService>,
    pub(crate) identified_websocket: Arc<Mutex<Option<SignalWebSocket<websocket::Identified>>>>,
    pub(crate) unidentified_websocket: Arc<Mutex<Option<SignalWebSocket<websocket::Unidentified>>>>,
    pub(crate) unidentified_sender_certificate: Arc<Mutex<Option<SenderCertificate>>>,
    pub(crate) link_preview_client: OnceLock<reqwest::Client>,
    /// Wakes the runner of the queued jobs.
    pub(crate) jobs_wake: Arc<tokio::sync::Notify>,

    pub(crate) data: Arc<RegistrationData>,
}

impl fmt::Debug for Registered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registered").finish_non_exhaustive()
    }
}

impl Registered {
    pub(crate) fn with_data(data: RegistrationData) -> Self {
        Self {
            identified_push_service: Default::default(),
            unidentified_push_service: Default::default(),
            identified_websocket: Default::default(),
            unidentified_websocket: Default::default(),
            unidentified_sender_certificate: Default::default(),
            link_preview_client: Default::default(),
            jobs_wake: Default::default(),
            data: Arc::new(data),
        }
    }

    fn servers(&self) -> SignalServers {
        self.data.signal_servers
    }

    fn service_configuration(&self) -> ServiceConfiguration {
        self.servers().into()
    }

    pub fn device_id(&self) -> DeviceId {
        self.data
            .device_id
            .and_then(|d| d.try_into().ok())
            .unwrap_or(*DEFAULT_DEVICE_ID)
    }

    pub(crate) fn identified_push_service(&self) -> PushService {
        self.identified_push_service
            .get_or_init(|| {
                PushService::new(self.servers(), Some(self.credentials()), crate::USER_AGENT)
            })
            .clone()
    }

    pub(crate) fn credentials(&self) -> ServiceCredentials {
        ServiceCredentials {
            aci: Some(self.data.service_ids.aci),
            pni: Some(self.data.service_ids.pni),
            phonenumber: (&self.data.phone_number)
                .try_into_e164()
                .expect("valid phone number"),
            password: Some(self.data.password.clone()),
            device_id: self.data.device_id.and_then(|d| d.try_into().ok()),
        }
    }
}

/// See [`Manager::services`].
pub struct Services {
    /// The cached push service presage uses itself, with the account's credentials.
    pub identified_push_service: PushService,
    /// `None` on a linked device until the primary has sent the account's keys.
    pub account_keys: Option<AccountKeys>,
}

impl Services {
    /// Connects to the storage service. `None` as for [`Self::account_keys`].
    pub async fn storage_service(
        &self,
    ) -> Result<Option<StorageService>, libsignal_service::prelude::ServiceError> {
        let Some(keys) = &self.account_keys else {
            return Ok(None);
        };
        let service =
            StorageService::new(self.identified_push_service.clone(), keys.storage_key()).await?;
        Ok(Some(service))
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
    pub device_id: Option<u32>,
    pub registration_id: u32,
    #[serde(default)]
    pub pni_registration_id: Option<u32>,
    #[serde(with = "serde_profile_key")]
    pub(crate) profile_key: ProfileKey,
    /// Decrypts the link-time message history archive. Single-use, so not persisted.
    #[serde(skip)]
    pub(crate) ephemeral_backup_key: Option<[u8; 32]>,
}

impl RegistrationData {
    /// Our own profile key
    pub fn profile_key(&self) -> ProfileKey {
        self.profile_key
    }

    /// The name of the device (if linked as secondary)
    pub fn device_name(&self) -> Option<&str> {
        self.device_name.as_deref()
    }

    /// Set right after [`Manager::link_secondary_device`][crate::Manager::link_secondary_device]
    /// if the primary device offered to transfer message history.
    pub fn ephemeral_backup_key(&self) -> Option<[u8; 32]> {
        self.ephemeral_backup_key
    }
}

impl<S: Store> Manager<S, Registered> {
    /// Loads a previously registered account from the implemented [Store].
    ///
    /// Returns a instance of [Manager] you can use to send & receive messages.
    pub async fn load_registered(store: S) -> Result<Self, Error<S::Error>> {
        let registration_data = store
            .load_registration_data()
            .await?
            .ok_or(Error::NotYetRegisteredError)?;

        let registered = Registered::with_data(registration_data);

        if let Some(sender_certificate) = store.sender_certificate().await? {
            registered
                .unidentified_sender_certificate
                .lock()
                .await
                .replace(sender_certificate);
        }

        Ok(Self {
            store,
            state: registered,
        })
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
    fn identified_push_service(&self) -> PushService {
        self.state.identified_push_service()
    }

    /// What this manager connects to Signal with, for requests presage doesn't make itself:
    /// authenticated requests, and reading or writing the storage service.
    pub async fn services(&self) -> Result<Services, Error<S::Error>> {
        // A primary makes its pool when first asked.
        self.account_entropy_pool().await?;
        Ok(Services {
            identified_push_service: self.identified_push_service(),
            account_keys: AccountKeys::load(&self.store).await?,
        })
    }

    /// Returns a clone of a cached push service (without credentials).
    ///
    /// If no service is yet cached, it will create and cache one.
    fn unidentified_push_service(&self) -> PushService {
        self.state
            .unidentified_push_service
            .get_or_init(|| PushService::new(self.state.servers(), None, crate::USER_AGENT))
            .clone()
    }

    /// Returns the current identified websocket, or creates a new one
    ///
    /// A new one is created if the current websocket is closed, or if there is none yet.
    async fn identified_websocket(
        &self,
        require_unused: bool,
    ) -> Result<SignalWebSocket<websocket::Identified>, Error<S::Error>> {
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
                        Some(self.credentials()),
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
    async fn unidentified_websocket(
        &self,
    ) -> Result<SignalWebSocket<websocket::Unidentified>, Error<S::Error>> {
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

    /// Request the primary device to encrypt & send all of its contacts.
    ///
    /// **Note**: If successful, the contacts are not yet received and stored, but will only be
    /// processed when they're received after polling on the
    pub async fn request_contacts(&mut self) -> Result<(), Error<S::Error>> {
        trace!("requesting contacts sync");
        let sync_message = SyncMessage {
            content: Some(SyncContent::Request(sync_message::Request {
                r#type: Some(sync_message::request::Type::Contacts.into()),
            })),
            ..SyncMessage::with_padding(&mut rand::rng())
        };

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        Ok(())
    }

    async fn sender_certificate(&self) -> Result<SenderCertificate, Error<S::Error>> {
        let needs_renewal = |sender_certificate: Option<&SenderCertificate>| -> bool {
            if sender_certificate.is_none() {
                return true;
            }

            let seconds_since_epoch = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_secs();

            if let Some(expiration) = sender_certificate.and_then(|s| s.expiration().ok()) {
                expiration.epoch_millis() / 1000 <= seconds_since_epoch + 600
            } else {
                true
            }
        };

        let mut unidentified_sender_certificate =
            self.state.unidentified_sender_certificate.lock().await;
        if needs_renewal(unidentified_sender_certificate.as_ref()) {
            let sender_certificate = self
                .identified_websocket(false)
                .await?
                .get_uuid_only_sender_certificate()
                .await?;
            self.store
                .save_sender_certificate(&sender_certificate)
                .await?;
            unidentified_sender_certificate.replace(sender_certificate);
        }

        Ok(unidentified_sender_certificate
            .clone()
            .expect("logic error"))
    }

    async fn account_entropy_pool(&self) -> Result<Option<AccountEntropyPool>, Error<S::Error>> {
        let from_store = self.store().fetch_account_entropy_pool().await?;

        if let Some(key) = from_store {
            Ok(Some(key))
        } else if self.registration_type() == RegistrationType::Primary {
            let key = AccountEntropyPool::generate(&mut rand::rng());
            self.store().store_account_entropy_pool(Some(&key)).await?;
            Ok(Some(key))
        } else {
            Ok(None)
        }
    }

    pub async fn submit_recaptcha_challenge(
        &self,
        token: &str,
        captcha: &str,
    ) -> Result<(), Error<S::Error>> {
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            None,
        );
        account_manager
            .submit_recaptcha_challenge(token, captcha)
            .await?;
        Ok(())
    }

    /// Fetches basic information on the registered device.
    pub async fn whoami(&self) -> Result<WhoAmIResponse, Error<S::Error>> {
        Ok(self.identified_websocket(false).await?.whoami().await?)
    }

    pub fn device_id(&self) -> DeviceId {
        self.state.device_id()
    }

    /// Fetches the profile (name, about, status emoji) of the registered user.
    pub async fn retrieve_profile(&mut self) -> Result<Profile, Error<S::Error>> {
        self.retrieve_profile_by_uuid(self.state.data.service_ids.aci, self.state.data.profile_key)
            .await
    }

    /// Fetches the profile of the provided user by UUID and profile key.
    pub async fn retrieve_profile_by_uuid(
        &mut self,
        aci: impl Into<Aci>,
        profile_key: ProfileKey,
    ) -> Result<Profile, Error<S::Error>> {
        let aci = aci.into();

        // Check if profile is cached.
        // TODO: Create a migration in the store removing all profiles.
        // TODO: Is there some way to know if this is outdated?
        if let Some(profile) = self
            .store
            .profile(aci.into(), profile_key)
            .await
            .ok()
            .flatten()
        {
            return Ok(profile);
        }

        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(profile_key),
        );

        let profile = account_manager.retrieve_profile(aci).await?;

        let _ = self
            .store
            .save_profile(aci.into(), profile_key, profile.clone())
            .await;
        Ok(profile)
    }

    /// Updates the user's profile information.
    pub async fn update_profile(
        &mut self,
        name: libsignal_service::profile_name::ProfileName<String>,
        about: Option<String>,
        emoji: Option<String>,
    ) -> Result<(), Error<S::Error>> {
        let aci = self.state.data.service_ids.aci();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        account_manager
            .upload_versioned_profile_without_avatar::<_, String>(
                aci,
                name,
                about,
                emoji,
                true, // retain_avatar
                &mut rand::rng(),
            )
            .await?;

        // Retrieve and save locally so we have the updated version
        let profile = account_manager.retrieve_profile(aci).await?;
        let _ = self
            .store
            .save_profile(aci.into(), self.state.data.profile_key, profile)
            .await;

        Ok(())
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
        if let Some(avatar) = self
            .store
            .group_avatar(master_key_bytes)
            .await
            .ok()
            .flatten()
        {
            return Ok(Some(avatar));
        }

        let mut gm = Box::pin(self.groups_manager()).await?;
        let Some(group) = upsert_group(
            &self.store,
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
            let _ = self.store.save_group_avatar(master_key_bytes, avatar).await;
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
        if let Some(avatar) = self
            .store
            .profile_avatar(uuid, profile_key)
            .await
            .ok()
            .flatten()
        {
            return Ok(Some(avatar));
        }

        let profile =
            if let Some(profile) = self.store.profile(uuid, profile_key).await.ok().flatten() {
                profile
            } else {
                self.retrieve_profile_by_uuid(uuid, profile_key).await?
            };

        let Some(avatar) = profile.avatar.as_ref() else {
            return Ok(None);
        };

        let mut websocket = self.unidentified_websocket().await?;

        let mut avatar_stream = websocket.retrieve_profile_avatar(avatar).await?;
        // 10MB is what Signal Android allocates
        let mut contents = Vec::with_capacity(10 * 1024 * 1024);
        let len = avatar_stream.read_to_end(&mut contents).await?;
        contents.truncate(len);

        let cipher = ProfileCipher::new(profile_key);

        let avatar = cipher.decrypt_avatar(&contents)?;
        let _ = self
            .store
            .save_profile_avatar(uuid, profile_key, &avatar)
            .await;
        Ok(Some(avatar))
    }

    async fn groups_manager(
        &self,
    ) -> Result<GroupsManager<InMemoryCredentialsCache>, Error<S::Error>> {
        let service_configuration = self.state.service_configuration();
        let server_public_params = service_configuration.zkgroup_server_public_params;

        let groups_credentials_cache = InMemoryCredentialsCache::default();
        let groups_manager = GroupsManager::new(
            self.state.data.service_ids.clone(),
            self.identified_push_service(),
            self.unidentified_websocket().await?,
            groups_credentials_cache,
            server_public_params,
        );

        Ok(groups_manager)
    }

    /// See [`sync_groups_from_storage_service`].
    pub(super) async fn sync_groups_from_storage_service(&self) -> Result<(), Error<S::Error>> {
        let mut groups_manager = Box::pin(self.groups_manager()).await?;
        sync_groups_from_storage_service(
            &self.store,
            self.identified_push_service(),
            &mut groups_manager,
        )
        .await
    }

    /// Uses Signal's SGX contact discovery service to resolve a phone number to its matching account identity
    #[cfg(feature = "cdsi")]
    pub async fn discover_contacts_by_phone_number<P: TryIntoE164>(
        &mut self,
        phone_numbers: impl IntoIterator<Item = P>,
    ) -> Result<Vec<(PhoneNumber, Option<ServiceId>)>, Error<S::Error>> {
        use libsignal_service::websocket::directory::LookupRequest;

        let mut ws = self.identified_websocket(false).await?;

        let lookup_request = LookupRequest {
            new_e164s: phone_numbers
                .into_iter()
                .filter_map(|p| p.try_into_e164().ok())
                .collect(),
            ..Default::default()
        };

        Ok(ws
            .discover_contacts(lookup_request)
            .await?
            .into_iter()
            .map(|(e164, service_id)| {
                use libsignal_service::utils::phonenumber_from_signal;
                (phonenumber_from_signal(&e164), service_id)
            })
            .collect())
    }

    /// Resolves a username (which has a text part and an additional random number) to its account identity
    /// for sending messages.
    pub async fn lookup_username(
        &mut self,
        username: &str,
    ) -> Result<Option<Aci>, Error<S::Error>> {
        let username = Username::new(username)?;
        let mut ws = self.unidentified_websocket().await?;
        let resolved_username = ws.look_up_username(&username).await?;
        Ok(resolved_username)
    }

    /// Sends a messages to the provided [ServiceId].
    /// The timestamp should be set to now and is used by Signal mobile apps
    /// to order messages later, and apply reactions.
    ///
    /// This method will automatically update the [DataMessage::expire_timer] if it is set to
    /// [None] such that the chat will keep the current expire timer. If the expire timer is set,
    /// it will be used as is, and the expire timer version will be incremented.
    pub async fn send_message(
        &mut self,
        recipient: impl Into<ServiceId>,
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        let mut sender = self.new_message_sender().await?;
        let recipient = recipient.into();

        let online_only = false;
        // TODO: Populate this flag based on the recipient information
        //
        // Issue <https://github.com/whisperfish/presage/issues/252>
        let include_pni_signature = false;
        let thread = Thread::Contact(recipient);
        let mut content_body: ContentBody = message.into();

        self.restore_thread_timer(&thread, &mut content_body).await;
        self.fetch_link_previews(&mut content_body).await;

        let sender_certificate = self.sender_certificate().await?;
        let unidentified_access = self
            .store
            .profile_key(&recipient)
            .await?
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

        ensure_data_message_timestamp(&mut content_body, timestamp);

        sender
            .send_message(
                &recipient,
                unidentified_access.as_ref(),
                content_body.clone(),
                timestamp,
                include_pni_signature,
                online_only,
            )
            .await?;

        // save the message
        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci().into(),
                sender_device: self.state.device_id(),
                destination: recipient,
                server_guid: None,
                client_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                // Note: Currently no way to get the timestamp the server received the message; just use our timestamp as a fallback.
                server_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                needs_receipt: false,
                unidentified_sender: false,
                was_plaintext: false,
                pni_verified: None,
            },
            body: content_body,
        };

        save_message(
            &mut self.store,
            &self.state.jobs_wake,
            content,
            Some(thread),
        )
        .await?;

        Ok(())
    }

    /// Fetches a preview (title, description, image) for the first link in `body`, and
    /// uploads its image as an attachment, ready to be set as the `preview` of the
    /// `DataMessage` sending `body`.
    ///
    /// Returns `None` if `body` has no link to preview.
    ///
    /// This fetches the linked page, which reveals the user's IP address to its server.
    pub async fn link_preview(
        &self,
        body: &str,
    ) -> Result<Option<libsignal_service::proto::Preview>, Error<S::Error>> {
        let client = match self.state.link_preview_client.get() {
            Some(client) => client,
            None => {
                let client = previews::client_builder()
                    .build()
                    .map_err(previews::Error::from)?;
                self.state.link_preview_client.get_or_init(|| client)
            }
        };
        let Some(content) = previews::generate_preview_from_message(body, client).await? else {
            return Ok(None);
        };

        // the preview is still useful without its image
        let image = match previews::build_preview_image(&content) {
            Some((spec, bytes)) => match self.upload_attachment(spec, bytes).await {
                Ok(Ok(pointer)) => Some(pointer),
                Ok(Err(error)) => {
                    warn!(%error, "failed to upload link preview image");
                    None
                }
                Err(error) => {
                    warn!(%error, "failed to upload link preview image");
                    None
                }
            },
            None => None,
        };

        Ok(Some(libsignal_service::proto::Preview {
            url: content.url,
            title: content.title,
            image,
            description: content.description,
            date: content.date,
        }))
    }

    /// Sets a preview of the first link of a data message that has no preview yet.
    async fn fetch_link_previews(&self, content_body: &mut ContentBody) {
        let ContentBody::DataMessage(message) = content_body else {
            return;
        };
        if !message.preview.is_empty() {
            return;
        }
        let Some(body) = message.body.as_deref() else {
            return;
        };
        match self.link_preview(body).await {
            Ok(preview) => message.preview.extend(preview),
            Err(error) => warn!(%error, "failed to build link preview, sending without"),
        }
    }

    /// Uploads one attachment prior to linking them in a message.
    pub async fn upload_attachment(
        &self,
        spec: AttachmentSpec,
        contents: Vec<u8>,
    ) -> Result<Result<AttachmentPointer, AttachmentUploadError>, Error<S::Error>> {
        Ok(self
            .new_message_sender()
            .await?
            .upload_attachment(spec, contents, &mut rng())
            .await)
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
            async move { sender.upload_attachment(spec, contents, &mut rng()).await }
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
        let thread = Thread::Group(master_key_bytes);

        self.restore_thread_timer(&thread, &mut content_body).await;
        self.fetch_link_previews(&mut content_body).await;
        ensure_data_message_timestamp(&mut content_body, timestamp);

        let mut sender = self.new_message_sender().await?;

        let mut groups_manager = Box::pin(self.groups_manager()).await?;
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
            .filter(|m| m.aci != self.state.data.service_ids.aci())
        {
            let unidentified_access =
                self.store
                    .profile_key(&member.aci.into())
                    .await?
                    .map(|profile_key| UnidentifiedAccess {
                        key: profile_key.derive_access_key().to_vec(),
                        certificate: sender_certificate.clone(),
                    });
            let include_pni_signature = false;
            recipients.push((
                member.aci.into(),
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
                Err(MessageSenderError::NotFound { service_id }) => {
                    debug!(service_id = %service_id.service_id_string(), "recipient not found, skipping sent message result");
                    false
                }
                // return first error if any
                Err(_) => true,
            })
            .transpose()?;

        let content = Content {
            metadata: Metadata {
                sender: self.state.data.service_ids.aci().into(),
                destination: self.state.data.service_ids.aci().into(),
                sender_device: self.state.device_id(),
                server_guid: None,
                client_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                // Note: Currently no way to get the timestamp the server received the message; just use our timestamp as a fallback.
                server_timestamp: chrono::Utc.timestamp_millis_opt(timestamp as i64).unwrap(),
                needs_receipt: false, // TODO: this is just wrong
                unidentified_sender: false,
                was_plaintext: false,
                pni_verified: None,
            },
            body: content_body,
        };

        save_message(
            &mut self.store,
            &self.state.jobs_wake,
            content,
            Some(thread),
        )
        .await?;

        Ok(())
    }

    async fn restore_thread_timer(&mut self, thread: &Thread, content_body: &mut ContentBody) {
        let store_expire_timer = self.store.expire_timer(thread).await.unwrap_or_default();

        if let ContentBody::DataMessage(DataMessage {
            expire_timer: ref mut timer,
            expire_timer_version: ref mut version,
            ..
        }) = content_body
        {
            if timer.is_none() {
                *timer = store_expire_timer.and_then(|(t, _)| if t == 0 { None } else { Some(t) });
                *version = Some(store_expire_timer.map(|(_, v)| v).unwrap_or_default());
            } else {
                *version = Some(store_expire_timer.map(|(_, v)| v).unwrap_or_default() + 1);
            }
        }
    }

    /// Clears all sessions established with [recipient](ServiceId).
    pub async fn clear_sessions(&self, recipient: &ServiceId) -> Result<(), Error<S::Error>> {
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

        let plaintext_len = attachment_pointer.size.and_then(|len| len.try_into().ok());

        // We need the whole file for the crypto to check out
        let mut ciphertext = Vec::with_capacity(plaintext_len.unwrap_or(0));
        let size_bytes = attachment_stream
            .stream
            .read_to_end(&mut ciphertext)
            .await?;
        trace!(size_bytes, "downloaded encrypted attachment");

        let digest = sha2::Sha256::digest(&ciphertext);
        if &digest[..] != expected_digest {
            return Err(Error::UnexpectedAttachmentChecksum);
        }

        let key: [u8; 64] = attachment_pointer.key().try_into()?;

        // Offload decryption of large attachments to another thread.
        // Chose arbitrary threshold here.
        const DECRYPT_IN_THREAD_THRESHOLD: usize = 100 * 1024;
        if ciphertext.len() > DECRYPT_IN_THREAD_THRESHOLD {
            ciphertext = tokio::task::spawn_blocking(move || {
                decrypt_in_place(key, &mut ciphertext).map(|_| ciphertext)
            })
            .await
            .expect("decryption in another thread")?;
        } else {
            decrypt_in_place(key, &mut ciphertext)?;
        };

        if let Some(len) = plaintext_len {
            if len < ciphertext.len() {
                // remove padding
                ciphertext.truncate(len);
            }
        }

        Ok(ciphertext)
    }

    /// Gets the metadata of a sticker
    pub async fn sticker_metadata(
        &mut self,
        pack_id: &[u8],
        sticker_id: u32,
    ) -> Result<Option<Sticker>, Error<S::Error>> {
        Ok(self.store.sticker_pack(pack_id).await?.and_then(|pack| {
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

        let unidentified_websocket = self.unidentified_websocket().await?;
        download_sticker_pack(
            self.store.clone(),
            unidentified_websocket,
            &sticker_pack_operation,
        )
        .await?;

        // Sync the change with the other devices
        let sync_message = SyncMessage {
            sticker_pack_operation: vec![sticker_pack_operation],
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
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

        self.send_message(self.state.data.service_ids.aci(), sync_message, timestamp)
            .await?;

        self.store.remove_sticker_pack(pack_id).await?;

        Ok(())
    }

    pub async fn send_session_reset(
        &mut self,
        recipient: &ServiceId,
        timestamp: u64,
    ) -> Result<(), Error<S::Error>> {
        trace!(recipient = %recipient.service_id_string(), "resetting session for address");

        let mut store = self.store.aci_protocol_store();

        // Archive all sessions with all receiver devices.
        // Note that the "get_sub_device_sessions" does not include the main device, therefore add it.
        // Note that deleting the session is not equivalent to archiving:
        // If we deleted the session, we would also delete the information on the list of devices the peer has, failing message sending.
        for device in store
            .get_sub_device_sessions(recipient)
            .await?
            .into_iter()
            .chain(vec![*DEFAULT_DEVICE_ID])
        {
            let address = recipient
                .aci()
                .expect("Recipient to be given as ACI")
                .to_protocol_address(device)
                .expect("Could not construct protocol address from recipient");
            if let Some(mut session) = store.load_session(&address).await? {
                session.archive_current_state()?;
                store.store_session(&address, &session).await?;
            }
        }

        // TODO: Signal Android also deletes entries in some sender_key_shared table; we don't have such a table yet.
        // Does not seem necessary though.

        // Send a null message.
        let message = NullMessage::generate(&mut rand::rng());
        self.send_message(*recipient, message, timestamp).await?;

        Ok(())
    }

    /// Records a finished call in the thread with the peer of `event` and tells our other
    /// devices about it, so their call logs agree. Returns the stored content.
    pub async fn send_call_event(
        &mut self,
        event: sync_message::CallEvent,
    ) -> Result<Content, Error<S::Error>> {
        let sync_message = SyncMessage {
            content: Some(SyncContent::CallEvent(event.clone())),
            ..SyncMessage::with_padding(&mut rand::rng())
        };
        self.new_message_sender()
            .await?
            .send_sync_message(sync_message.clone())
            .await?;

        let aci = self.state.data.service_ids.aci();
        // Filed under the start of the call.
        let timestamp = event
            .timestamp
            .and_then(|ts| chrono::Utc.timestamp_millis_opt(ts as i64).single())
            .unwrap_or_else(chrono::Utc::now);
        let content = Content {
            metadata: Metadata {
                sender: aci.into(),
                sender_device: self.state.device_id(),
                destination: aci.into(),
                server_guid: None,
                client_timestamp: timestamp,
                server_timestamp: timestamp,
                needs_receipt: false,
                unidentified_sender: false,
                was_plaintext: false,
                pni_verified: None,
            },
            body: ContentBody::SynchronizeMessage(sync_message),
        };

        save_message(
            &mut self.store,
            &self.state.jobs_wake,
            content.clone(),
            None,
        )
        .await?;
        Ok(content)
    }

    /// Fetches short-lived TURN credentials for 1:1 calls.
    pub async fn calling_relays(&self) -> Result<Vec<TurnServer>, Error<S::Error>> {
        Ok(self
            .identified_websocket(false)
            .await?
            .get_calling_relays()
            .await?)
    }

    fn credentials(&self) -> ServiceCredentials {
        self.state.credentials()
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
            self.new_service_cipher_aci(),
            aci_protocol_store,
            self.state.data.service_ids.aci,
            self.state.data.service_ids.pni,
            aci_identity_keypair,
            Some(pni_identity_keypair),
            self.state.device_id(),
        ))
    }

    fn new_service_cipher_aci(&self) -> ServiceCipher<S::AciStore> {
        ServiceCipher::new(
            self.store.aci_protocol_store(),
            self.state
                .service_configuration()
                .unidentified_sender_trust_roots,
            ProtocolAddress::new(
                self.state.data.service_ids.aci().service_id_string(),
                self.state.device_id(),
            ),
        )
    }

    fn new_service_cipher_pni(&self) -> ServiceCipher<S::PniStore> {
        ServiceCipher::new(
            self.store.pni_protocol_store(),
            self.state
                .service_configuration()
                .unidentified_sender_trust_roots,
            ProtocolAddress::new(
                self.state.data.service_ids.pni().service_id_string(),
                self.state.device_id(),
            ),
        )
    }

    /// Returns the title of a thread (contact or group).
    pub async fn thread_title(&self, thread: &Thread) -> Result<String, Error<S::Error>> {
        match thread {
            Thread::Contact(service_id) => {
                let contact = match self.store.contact_by_id(service_id).await {
                    Ok(contact) => contact,
                    Err(error) => {
                        info!(%error, service_id =% service_id.service_id_string(), "error getting contact by id");
                        None
                    }
                };
                Ok(match contact {
                    Some(contact) => contact.name,
                    None => service_id.service_id_string(),
                })
            }
            Thread::Group(id) => match self.store.group(*id).await? {
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
    pub async fn link_secondary(&mut self, secondary: Url) -> Result<(), Error<S::Error>> {
        // XXX: What happens if secondary device? Possible to use static typing to make this method call impossible in that case?
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }

        let credentials = self.credentials();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        account_manager
            .link_device(
                &mut rand::rng(),
                secondary,
                &self.store.aci_protocol_store(),
                &self.store.pni_protocol_store(),
                ProvisioningSecrets {
                    credentials,
                    account_entropy_pool: self
                        .account_entropy_pool()
                        .await?
                        .ok_or(Error::MissingKeyError("account_entropy_pool".into()))?,
                    ephemeral_backup_key: None,
                    media_root_backup_key: None,
                },
            )
            .await?;
        Ok(())
    }

    /// As a primary device, unlink a secondary device.
    pub async fn unlink_secondary(
        &self,
        device_id: impl TryInto<DeviceId>,
    ) -> Result<(), Error<S::Error>> {
        // secondary devices can only unlink themselves, see `unlink_self`
        if self.registration_type() != RegistrationType::Primary {
            return Err(Error::NotPrimaryDevice);
        }
        self.identified_websocket(false)
            .await?
            .unlink_device(device_id.try_into().map_err(|_| Error::InvalidDeviceId)?)
            .await?;
        Ok(())
    }

    /// As a primary device, list all the devices (including the current device).
    pub async fn devices(&self) -> Result<Vec<DeviceInfo>, Error<S::Error>> {
        let aci_protocol_store = self.store.aci_protocol_store();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );

        Ok(account_manager.linked_devices(&aci_protocol_store).await?)
    }

    /// Removes this linked device from the account, e.g. before linking again.
    pub async fn unlink_self(&self) -> Result<(), Error<S::Error>> {
        if self.registration_type() == RegistrationType::Primary {
            return Err(Error::NotSecondaryDevice);
        }
        self.identified_websocket(false)
            .await?
            .unlink_device(self.device_id())
            .await?;
        Ok(())
    }

    /// Update the name of this device.
    pub async fn update_device_name(&mut self, name: &str) -> Result<(), Error<S::Error>> {
        let aci = self.state.data.service_ids.aci;
        let aci_protocol_store = self.store.aci_protocol_store();
        let mut account_manager = AccountManager::new(
            self.identified_push_service(),
            self.identified_websocket(false).await?,
            Some(self.state.data.profile_key),
        );
        account_manager
            .update_device_name(
                self.device_id(),
                name,
                aci.into(),
                &aci_protocol_store,
                &mut rng(),
            )
            .await?;
        Ok(())
    }
}

/// Set the timestamp in any DataMessage so it matches its envelope's
fn ensure_data_message_timestamp(content_body: &mut ContentBody, timestamp: u64) {
    match content_body {
        ContentBody::DataMessage(message) => {
            message.timestamp = Some(timestamp);
        }
        ContentBody::EditMessage(EditMessage {
            data_message: Some(data_message),
            ..
        }) => {
            data_message.timestamp = Some(timestamp);
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    message: Some(data_message),
                    ..
                })),
            ..
        }) => {
            data_message.timestamp = Some(timestamp);
        }
        _ => (),
    }
}

async fn sync_groups_from_storage_service<S: Store>(
    store: &S,
    push_service: PushService,
    groups_manager: &mut GroupsManager<InMemoryCredentialsCache>,
) -> Result<(), Error<S::Error>> {
    const READ_CHUNK: usize = 100;

    let keys = AccountKeys::load(store)
        .await?
        .ok_or(Error::MissingKeyError("master_key".into()))?;
    let storage = StorageService::new(push_service, keys.storage_key()).await?;

    let manifest = storage.manifest().await?;
    let group_ids: Vec<Vec<u8>> = manifest
        .identifiers
        .iter()
        .filter(|id| id.r#type() == manifest_record::identifier::Type::Groupv2)
        .map(|id| id.raw.clone())
        .collect();
    debug!(
        count = group_ids.len(),
        "groups listed in the storage service"
    );

    let mut failed = None;
    for chunk in group_ids.chunks(READ_CHUNK) {
        let records = match storage
            .read_items(chunk.to_vec(), Some(&manifest.record_ikm))
            .await
        {
            Ok(records) => records,
            Err(error) => {
                warn!(%error, "failed to read group records from the storage service");
                failed = Some(error.into());
                continue;
            }
        };
        for record in records {
            let Some(storage_record::Record::GroupV2(record)) = record.record else {
                continue;
            };
            if let Err(error) = save_unknown_group(store, groups_manager, &record.master_key).await
            {
                warn!(%error, "failed to fetch group listed in the storage service");
                failed = Some(error);
            }
        }
    }
    // Synced again unless all of it was read: the failure puts the job off.
    failed.map_or(Ok(()), Err)
}

/// Incoming messages keep known groups current, so only unknown ones are fetched.
async fn save_unknown_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<InMemoryCredentialsCache>,
    master_key_bytes: &[u8],
) -> Result<(), Error<S::Error>> {
    let master_key: GroupMasterKeyBytes = master_key_bytes.try_into()?;
    if store.group(master_key).await?.is_some() || store.is_group_left(master_key).await? {
        return Ok(());
    }
    match groups_manager
        .fetch_encrypted_group(&mut rand::rng(), master_key_bytes)
        .await
    {
        Ok(encrypted_group) => {
            let group = decrypt_group(master_key_bytes, encrypted_group)?;
            store.save_group(master_key, group).await?;
        }
        // The group server refuses groups the account has left or was only invited to.
        Err(libsignal_service::prelude::ServiceError::Unauthorized) => {
            debug!("not a member of a group listed in the storage service");
            store.mark_group_left(master_key).await?;
        }
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

/// Fetches and saves the group unless it is stored at `revision` already. Fails if fetching does.
async fn update_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<InMemoryCredentialsCache>,
    master_key_bytes: &[u8],
    revision: &u32,
) -> Result<Option<Group>, Error<S::Error>> {
    let upsert_group = match store.group(master_key_bytes.try_into()?).await {
        Ok(Some(group)) => {
            debug!(group_name =% group.title, "loaded group from local db");
            group.revision < *revision
        }
        Ok(None) => true,
        Err(error) => {
            warn!(%error, "failed to retrieve group from local db");
            true
        }
    };

    if upsert_group {
        debug!("fetching and saving group");
        let encrypted_group = groups_manager
            .fetch_encrypted_group(&mut rand::rng(), master_key_bytes)
            .await?;
        let group = decrypt_group(master_key_bytes, encrypted_group)?;
        if let Err(error) = store.save_group(master_key_bytes.try_into()?, group).await {
            error!(%error, "failed to save group");
        }
    }

    Ok(store.group(master_key_bytes.try_into()?).await?)
}

/// As [`update_group`], with the stored group if fetching fails.
async fn upsert_group<S: Store>(
    store: &S,
    groups_manager: &mut GroupsManager<InMemoryCredentialsCache>,
    master_key_bytes: &[u8],
    revision: &u32,
) -> Result<Option<Group>, Error<S::Error>> {
    match update_group(store, groups_manager, master_key_bytes, revision).await {
        Err(Error::ServiceError(error)) => {
            warn!(error = %jobs::Causes(&error), "failed to fetch encrypted group");
            Ok(store.group(master_key_bytes.try_into()?).await?)
        }
        group => group,
    }
}

/// Download and decrypt a sticker manifest
async fn download_sticker_pack<C: ContentsStore>(
    mut store: C,
    mut unidentified_websocket: SignalWebSocket<websocket::Unidentified>,
    operation: &StickerPackOperation,
) -> Result<StickerPack, Error<C::ContentsStoreError>> {
    debug!("downloading sticker pack");
    let pack_key = operation.pack_key();
    let pack_id = operation.pack_id();
    let key = derive_key(pack_key)?;

    let mut ciphertext = Vec::new();

    let size_bytes = unidentified_websocket
        .get_sticker_pack_manifest(&hex::encode(pack_id))
        .await?
        .read_to_end(&mut ciphertext)
        .await?;

    trace!(size_bytes, "downloaded encrypted sticker pack manifest");

    decrypt_in_place(key, &mut ciphertext)?;

    let mut sticker_pack_manifest: StickerPackManifest =
        libsignal_service::proto::Pack::decode(ciphertext.as_slice())
            .map_err(ProvisioningError::from)?
            .into();

    for sticker in &mut sticker_pack_manifest.stickers {
        match download_sticker::<C>(&mut unidentified_websocket, pack_id, pack_key, sticker.id)
            .await
        {
            Ok(decrypted_sticker_bytes) => {
                debug!(id = sticker.id, "downloaded sticker");
                sticker.bytes = Some(decrypted_sticker_bytes);
            }
            Err(error) => error!(sticker.id, %error,"failed to download sticker"),
        }
    }

    let sticker_pack = StickerPack {
        id: pack_id.to_vec(),
        key: pack_key.to_vec(),
        manifest: sticker_pack_manifest,
    };

    // save everything in store
    store.add_sticker_pack(&sticker_pack).await?;

    Ok(sticker_pack)
}

/// Downloads and decrypts a single sticker
async fn download_sticker<C: ContentsStore>(
    unidentified_websocket: &mut SignalWebSocket<websocket::Unidentified>,
    pack_id: &[u8],
    pack_key: &[u8],
    sticker_id: u32,
) -> Result<Vec<u8>, Error<C::ContentsStoreError>> {
    let key = derive_key(pack_key)?;

    let mut sticker_stream = unidentified_websocket
        .get_sticker(&hex::encode(pack_id), sticker_id)
        .await?;

    let mut ciphertext = Vec::new();
    let size_bytes = sticker_stream.read_to_end(&mut ciphertext).await?;

    trace!(size_bytes, "downloaded encrypted sticker");

    decrypt_in_place(key, &mut ciphertext)?;

    Ok(ciphertext)
}

/// Save a message into the store, its sender's profile key first.
/// Note that `override_thread` can be used to specify the thread the message will be stored in.
/// This is required when storing outgoing messages, as in this case the appropriate storage place cannot be derived from the message itself.
async fn save_message<S: Store>(
    store: &mut S,
    jobs_wake: &tokio::sync::Notify,
    message: Content,
    override_thread: Option<Thread>,
) -> Result<(), Error<S::Error>> {
    // derive the thread from the message type
    let thread = override_thread.unwrap_or(Thread::try_from(&message)?);

    if let Some(job) = keep_profile_key(store, &message).await? {
        jobs::enqueue(store, jobs_wake, job).await;
    }

    // only save DataMessage and SynchronizeMessage (sent)
    let message = match message.body {
        ContentBody::DecryptionErrorMessage(e) => {
            warn!(error = ?e, "was asked to save a DecryptionErrorMessage; this should not happen");
            None
        }
        ContentBody::NullMessage(_) => Some(message),
        ContentBody::DataMessage(ref data_message)
        | ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    message: Some(ref data_message),
                    ..
                })),
            ..
        }) => {
            // Note: The expire timer fields of data messages are only for contacts.
            // Expire timers are handled for groups via upsert_group due to a revision change.
            if let Thread::Contact(_) = thread {
                let version = data_message.expire_timer_version.unwrap_or(1);
                store
                    .update_expire_timer(
                        &thread,
                        data_message.expire_timer.unwrap_or_default(),
                        version,
                    )
                    .await?;
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
                    if let Some(mut existing_msg) = store.message(&thread, *ts).await? {
                        existing_msg.metadata.sender = Aci::from(Uuid::nil()).into();
                        existing_msg.body = NullMessage::default().into();
                        store.save_message(&thread, existing_msg).await?;
                        debug!(%thread, ts, "message in thread deleted");
                        None
                    } else {
                        warn!(%thread, ts, "could not find message to delete in thread");
                        None
                    }
                }
                _ => Some(message),
            }
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::DeleteForMe(ref delete)),
            ..
        }) => {
            // TODO: Conversations, local-only deletes, attachments
            for d in delete.message_deletes.iter().flat_map(|m| &m.messages) {
                let sender = match &d.author {
                    Some(Author::AuthorServiceId(id)) => {
                        ServiceId::parse_from_service_id_string(id)
                    }
                    Some(Author::AuthorServiceIdBinary(id)) => {
                        ServiceId::parse_from_service_id_binary(id)
                    }
                    Some(Author::AuthorE164(_)) => None,
                    None => None,
                };
                let Some(sender) = sender else {
                    tracing::warn!("Could not parse author of delete-for-self message; ignoring.");
                    continue;
                };
                let Some(timestamp) = d.sent_timestamp else {
                    tracing::warn!("Timestamp of delete-for-self message not given; ignoring.");
                    continue;
                };
                let Ok(Some(thread)) = store
                    .thread_for_sender_and_timestamp(&sender, timestamp)
                    .await
                else {
                    tracing::warn!(
                        "Message referenced by delete-for-self message not found; ignoring."
                    );
                    continue;
                };
                // Note: Not marking the message as deleted, like when receiving deletion requests by others.
                // This matches the behavior of Signal Desktop, where the message completely disappears from the timeline.
                let result = store.delete_message(&thread, timestamp).await;
                if !result.is_ok_and(|d| d) {
                    tracing::warn!(
                        "Could not delete message referenced by delete-for-self message; ignoring."
                    );
                }
            }
            None
        }
        ContentBody::EditMessage(EditMessage {
            target_sent_timestamp: Some(_),
            data_message: Some(_),
        })
        | ContentBody::SynchronizeMessage(SyncMessage {
            content:
                Some(SyncContent::Sent(sync_message::Sent {
                    edit_message:
                        Some(EditMessage {
                            target_sent_timestamp: Some(_),
                            data_message: Some(_),
                        }),
                    ..
                })),
            ..
        }) => Some(message),
        // Call signaling is transient; calls are recorded by `CallEvent`s instead.
        ContentBody::CallMessage(_) => None,
        ContentBody::SynchronizeMessage(SyncMessage {
            content: Some(SyncContent::CallEvent(_)),
            ..
        }) => Some(message),
        ContentBody::SynchronizeMessage(msg) => {
            debug!(
                ?msg,
                "skipping saving sync message without interesting fields"
            );
            None
        }
        ContentBody::ReceiptMessage(_) => Some(message),
        ContentBody::TypingMessage(msg) => {
            debug!(?msg, "skipping saving typing message");
            None
        }
        ContentBody::StoryMessage(msg) => {
            debug!(?msg, "skipping story message");
            None
        }
        ContentBody::EditMessage(msg) => {
            debug!(?msg, "invalid edited");
            None
        }
    };

    if let Some(message) = message {
        store.save_message(&thread, message).await?;
    }

    Ok(())
}

/// Saves `aci` as a contact by the name of their `profile`.
async fn save_contact_from_profile<S: Store>(
    store: &mut S,
    aci: Aci,
    profile_key: ProfileKey,
    profile: Profile,
    expire_timer: u32,
    expire_timer_version: u32,
) -> Result<(), Error<<S as Store>::Error>> {
    let sender_uuid: Uuid = aci.into();
    let contact = Contact {
        uuid: sender_uuid,
        phone_number: None,
        name: profile
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
        expire_timer,
        expire_timer_version,
        inbox_position: 0,
        avatar: None,
        verified: Verified::default(),
    };

    info!(%sender_uuid, "saved contact on first sight");
    store.save_contact(&contact).await?;
    Ok(())
}

async fn set_account_attributes<S: Store>(
    account_manager: &mut AccountManager,
    store: &S,
    data: &RegistrationData,
) -> Result<(), Error<S::Error>> {
    trace!("setting account attributes");

    let pni_registration_id = data.pni_registration_id.ok_or(Error::RelinkNecessary)?;

    let name = if let Some(device_name) = data.device_name() {
        let aci_key_pair = store.aci_protocol_store().get_identity_key_pair().await?;
        let mut rng = rng();
        Some(encrypt_device_name(
            &mut rng,
            device_name,
            aci_key_pair.identity_key(),
        )?)
    } else {
        None
    };

    account_manager
        .set_account_attributes(AccountAttributes {
            fetches_messages: true,
            registration_id: data.registration_id,
            pni_registration_id,
            name,
            registration_lock: None,
            unidentified_access_key: Some(data.profile_key.derive_access_key().to_vec()),
            unrestricted_unidentified_access: false,
            capabilities: Some(DeviceCapabilities {
                storage: true,
                transfer: false,
                attachment_backfill: false,
                spqr: true,
                profiles_v2: false,
                username_change_sync_message: true,
            }),
            discoverable_by_phone_number: true,
            recovery_password: None,
            video: false,
            voice: false,
        })
        .await?;

    trace!("done setting account attributes");
    Ok(())
}

async fn register_pre_keys<S: Store>(
    store: &S,
    account_manager: &mut AccountManager,
) -> Result<(), Error<S::Error>> {
    trace!("registering pre keys");

    account_manager
        .update_pre_key_bundle(&mut store.aci_protocol_store(), ServiceIdKind::Aci, true)
        .await?;

    account_manager
        .update_pre_key_bundle(&mut store.pni_protocol_store(), ServiceIdKind::Pni, true)
        .await?;

    trace!("registered pre keys");
    Ok(())
}
