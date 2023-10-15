use std::{
    fmt,
    ops::RangeBounds,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use futures::{channel::mpsc, channel::oneshot, future, pin_mut, AsyncReadExt, Stream, StreamExt, stream};
use log::{debug, error, info, trace, warn};
use parking_lot::Mutex;
use rand::{
    distributions::{Alphanumeric, DistString},
    rngs::StdRng,
    RngCore, SeedableRng,
};
use serde::{Deserialize, Serialize};
use url::Url;

use libsignal_service::{proto::EditMessage, messagepipe::Incoming};
use libsignal_service::push_service::{RegistrationMethod, VerificationTransport};
use libsignal_service::{
    attachment_cipher::decrypt_in_place,
    cipher,
    configuration::{ServiceConfiguration, SignalServers, SignalingKey},
    content::{ContentBody, DataMessage, DataMessageFlags, Metadata, SyncMessage},
    groups_v2::{decrypt_group, Group, GroupsManager, InMemoryCredentialsCache},
    messagepipe::ServiceCredentials,
    models::Contact,
    prelude::{phonenumber::PhoneNumber, Content, ProfileKey, PushService, Uuid},
    proto::{
        data_message::Delete, sync_message, AttachmentPointer, GroupContextV2,
        NullMessage,
    },
    protocol::{KeyPair, PrivateKey, PublicKey, SenderCertificate},
    provisioning::{generate_registration_id, LinkingManager, SecondaryDeviceProvisioning},
    push_service::{
        AccountAttributes, DeviceCapabilities, DeviceId, ServiceError, ServiceIds, WhoAmIResponse,
        DEFAULT_DEVICE_ID,
    },
    receiver::MessageReceiver,
    sender::{AttachmentSpec, AttachmentUploadError},
    unidentified_access::UnidentifiedAccess,
    utils::{
        serde_optional_private_key, serde_optional_public_key, serde_private_key, serde_public_key,
        serde_signaling_key,
    },
    websocket::SignalWebSocket,
    AccountManager, Profile, ServiceAddress,
};
use libsignal_service_hyper::push_service::HyperPushService;

use crate::cache::CacheCell;
use crate::{serde::serde_profile_key, Thread};
use crate::{store::Store, Error};

type ServiceCipher<C> = cipher::ServiceCipher<C, StdRng>;
type MessageSender<C> = libsignal_service::prelude::MessageSender<HyperPushService, C, StdRng>;

#[derive(Clone)]
pub struct Manager<Store, State> {
    /// Implementation of a config-store to give to libsignal
    config_store: Store,
    /// Part of the manager which is persisted in the store.
    state: State,
    /// Random number generator
    rng: StdRng,
}

impl<Store, State: fmt::Debug> fmt::Debug for Manager<Store, State> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Manager")
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RegistrationOptions<'a> {
    pub signal_servers: SignalServers,
    pub phone_number: PhoneNumber,
    pub use_voice_call: bool,
    pub captcha: Option<&'a str>,
    pub force: bool,
}

pub struct Registration;
pub struct Linking;

pub struct Confirmation {
    signal_servers: SignalServers,
    phone_number: PhoneNumber,
    password: String,
    session_id: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Registered {
    #[serde(skip)]
    push_service_cache: CacheCell<HyperPushService>,
    #[serde(skip)]
    identified_websocket: Arc<Mutex<Option<SignalWebSocket>>>,
    #[serde(skip)]
    unidentified_websocket: Arc<Mutex<Option<SignalWebSocket>>>,
    #[serde(skip)]
    unidentified_sender_certificate: Option<SenderCertificate>,

    pub signal_servers: SignalServers,
    pub device_name: Option<String>,
    pub phone_number: PhoneNumber,
    #[serde(flatten)]
    pub service_ids: ServiceIds,
    password: String,
    #[serde(with = "serde_signaling_key")]
    signaling_key: SignalingKey,
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
    profile_key: ProfileKey,
}

pub struct Synced { inner: Registered }

impl fmt::Debug for Registered {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Registered")
            .field("websocket", &self.identified_websocket.lock().is_some())
            .finish_non_exhaustive()
    }
}

impl Registered {
    pub fn device_id(&self) -> u32 {
        self.device_id.unwrap_or(DEFAULT_DEVICE_ID)
    }
}

impl<C: Store> Manager<C, Registration> {
    /// Registers a new account with a phone number (and some options).
    ///
    /// The returned value is a [confirmation manager](Manager::confirm_verification_code) which you then
    /// have to use to send the confirmation code.
    ///
    /// ```no_run
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     use std::str::FromStr;
    ///
    ///     use presage::{
    ///         prelude::{phonenumber::PhoneNumber, SignalServers},
    ///         Manager, MigrationConflictStrategy, RegistrationOptions, SledStore,
    ///     };
    ///
    ///     let config_store =
    ///         SledStore::open("/tmp/presage-example", MigrationConflictStrategy::Drop)?;
    ///
    ///     let manager = Manager::register(
    ///         config_store,
    ///         RegistrationOptions {
    ///             signal_servers: SignalServers::Production,
    ///             phone_number: PhoneNumber::from_str("+16137827274")?,
    ///             use_voice_call: false,
    ///             captcha: None,
    ///             force: false,
    ///         },
    ///     )
    ///     .await?;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn register(
        mut config_store: C,
        registration_options: RegistrationOptions<'_>,
    ) -> Result<Manager<C, Confirmation>, Error<C::Error>> {
        let RegistrationOptions {
            signal_servers,
            phone_number,
            use_voice_call,
            captcha,
            force,
        } = registration_options;

        // check if we are already registered
        if !force && config_store.is_registered() {
            return Err(Error::AlreadyRegisteredError);
        }

        config_store.clear_registration()?;

        // generate a random alphanumeric 24 chars password
        let mut rng = StdRng::from_entropy();
        let password = Alphanumeric.sample_string(&mut rng, 24);

        let service_configuration: ServiceConfiguration = signal_servers.into();
        let mut push_service =
            HyperPushService::new(service_configuration, None, crate::USER_AGENT.to_string());

        trace!("creating registration verification session");

        let phone_number_string = phone_number.to_string();
        let mut session = push_service
            .create_verification_session(&phone_number_string, None, None, None)
            .await?;

        if !session.allowed_to_request_code {
            if session.captcha_required() {
                trace!("captcha required");
                if captcha.is_none() {
                    return Err(Error::CaptchaRequired);
                }
                session = push_service
                    .patch_verification_session(&session.id, None, None, None, captcha, None)
                    .await?
            }
            if session.push_challenge_required() {
                return Err(Error::PushChallengeRequired);
            }
        }

        if !session.allowed_to_request_code {
            return Err(Error::RequestingCodeForbidden(session));
        }

        trace!("requesting verification code");

        session = push_service
            .request_verification_code(
                &session.id,
                crate::USER_AGENT,
                if use_voice_call {
                    VerificationTransport::Voice
                } else {
                    VerificationTransport::Sms
                },
            )
            .await?;

        let manager = Manager {
            config_store,
            state: Confirmation {
                signal_servers,
                phone_number,
                password,
                session_id: session.id,
            },
            rng,
        };

        Ok(manager)
    }
}

impl<C: Store> Manager<C, Linking> {
    /// Links this client as a secondary device from the device used to register the account (usually a phone).
    /// The URL to present to the user will be sent in the channel given as the argument.
    ///
    /// ```no_run
    /// use futures::{channel::oneshot, future, StreamExt};
    /// use presage::{prelude::SignalServers, Manager, MigrationConflictStrategy, SledStore};
    ///
    /// #[tokio::main]
    /// async fn main() -> anyhow::Result<()> {
    ///     let config_store =
    ///         SledStore::open("/tmp/presage-example", MigrationConflictStrategy::Drop)?;
    ///
    ///     let (mut tx, mut rx) = oneshot::channel();
    ///     let (manager, err) = future::join(
    ///         Manager::link_secondary_device(
    ///             config_store,
    ///             SignalServers::Production,
    ///             "my-linked-client".into(),
    ///             tx,
    ///         ),
    ///         async move {
    ///             match rx.await {
    ///                 Ok(url) => println!("Show URL {} as QR code to user", url),
    ///                 Err(e) => println!("Error linking device: {}", e),
    ///             }
    ///         },
    ///     )
    ///     .await;
    ///
    ///     Ok(())
    /// }
    /// ```
    pub async fn link_secondary_device(
        mut config_store: C,
        signal_servers: SignalServers,
        device_name: String,
        provisioning_link_channel: oneshot::Sender<Url>,
    ) -> Result<Manager<C, Registered>, Error<C::Error>> {
        // clear the database: the moment we start the process, old API credentials are invalidated
        // and you won't be able to use this client anyways
        config_store.clear_registration()?;

        // generate a random alphanumeric 24 chars password
        let mut rng = StdRng::from_entropy();
        let password = Alphanumeric.sample_string(&mut rng, 24);

        // generate a 52 bytes signaling key
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        let service_configuration: ServiceConfiguration = signal_servers.into();
        let push_service =
            HyperPushService::new(service_configuration, None, crate::USER_AGENT.to_string());

        let mut linking_manager: LinkingManager<HyperPushService> =
            LinkingManager::new(push_service, password.clone());

        let (tx, mut rx) = mpsc::channel(1);

        let (wait_for_qrcode_scan, registration) = future::join(
            linking_manager.provision_secondary_device(&mut rng, signaling_key, tx),
            async move {
                if let Some(SecondaryDeviceProvisioning::Url(url)) = rx.next().await {
                    log::info!("generating qrcode from provisioning link: {}", &url);
                    if provisioning_link_channel.send(url).is_err() {
                        return Err(Error::LinkError);
                    }
                } else {
                    return Err(Error::LinkError);
                }

                if let Some(SecondaryDeviceProvisioning::NewDeviceRegistration {
                    phone_number,
                    device_id: DeviceId { device_id },
                    registration_id,
                    pni_registration_id,
                    profile_key,
                    service_ids,
                    aci_private_key,
                    aci_public_key,
                    pni_private_key,
                    pni_public_key,
                }) = rx.next().await
                {
                    log::info!("successfully registered device {}", &service_ids);
                    Ok(Registered {
                        push_service_cache: CacheCell::default(),
                        identified_websocket: Default::default(),
                        unidentified_websocket: Default::default(),
                        unidentified_sender_certificate: Default::default(),
                        signal_servers,
                        device_name: Some(device_name),
                        phone_number,
                        service_ids,
                        signaling_key,
                        password,
                        device_id: Some(device_id),
                        registration_id,
                        pni_registration_id: Some(pni_registration_id),
                        aci_public_key,
                        aci_private_key,
                        pni_public_key: Some(pni_public_key),
                        pni_private_key: Some(pni_private_key),
                        profile_key: ProfileKey::create(
                            profile_key.try_into().expect("32 bytes for profile key"),
                        ),
                    })
                } else {
                    Err(Error::NoProvisioningMessageReceived)
                }
            },
        )
        .await;

        wait_for_qrcode_scan?;

        let mut manager = Manager {
            rng,
            config_store,
            state: registration?,
        };

        manager.config_store.save_state(&manager.state)?;

        match (
            manager.register_pre_keys().await,
            manager.set_account_attributes().await,
            manager.sync_contacts().await,
        ) {
            (Err(e), _, _) | (_, Err(e), _) => {
                // clear the entire store on any error, there's no possible recovery here
                manager.config_store.clear_registration()?;
                Err(e)
            }
            (_, _, Err(e)) => {
                warn!("failed to synchronize contacts: {e}");
                Ok(manager)
            }
            _ => Ok(manager),
        }
    }
}

impl<C: Store> Manager<C, Confirmation> {
    /// Confirm a newly registered account using the code you
    /// received by SMS or phone call.
    ///
    /// Returns a [registered manager](Manager::load_registered) that you can use
    /// to send and receive messages.
    pub async fn confirm_verification_code(
        self,
        confirmation_code: impl AsRef<str>,
    ) -> Result<Manager<C, Registered>, Error<C::Error>> {
        trace!("confirming verification code");

        let registration_id = generate_registration_id(&mut StdRng::from_entropy());
        let pni_registration_id = generate_registration_id(&mut StdRng::from_entropy());

        let Confirmation {
            signal_servers,
            phone_number,
            password,
            session_id,
        } = self.state;

        let credentials = ServiceCredentials {
            uuid: None,
            phonenumber: phone_number.clone(),
            password: Some(password.clone()),
            signaling_key: None,
            device_id: None,
        };

        let service_configuration: ServiceConfiguration = signal_servers.into();
        let mut push_service = HyperPushService::new(
            service_configuration,
            Some(credentials),
            crate::USER_AGENT.to_string(),
        );

        let session = push_service
            .submit_verification_code(&session_id, confirmation_code.as_ref())
            .await?;

        trace!("verification code submitted");

        if !session.verified {
            return Err(Error::UnverifiedRegistrationSession);
        }

        let mut rng = StdRng::from_entropy();

        // generate a 52 bytes signaling key
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        let mut profile_key = [0u8; 32];
        rng.fill_bytes(&mut profile_key);

        let profile_key = ProfileKey::generate(profile_key);

        let skip_device_transfer = false;
        let registered = push_service
            .submit_registration_request(
                RegistrationMethod::SessionId(&session_id),
                AccountAttributes {
                    name: None,
                    signaling_key: Some(signaling_key.to_vec()),
                    registration_id,
                    pni_registration_id,
                    voice: false,
                    video: false,
                    fetches_messages: true,
                    pin: None,
                    registration_lock: None,
                    unidentified_access_key: Some(profile_key.derive_access_key().to_vec()),
                    unrestricted_unidentified_access: false, // TODO: make this configurable?
                    discoverable_by_phone_number: true,
                    capabilities: DeviceCapabilities {
                        gv2: true,
                        gv1_migration: true,
                        ..Default::default()
                    },
                },
                skip_device_transfer,
            )
            .await?;

        let aci_identity_key_pair = KeyPair::generate(&mut rng);
        let pni_identity_key_pair = KeyPair::generate(&mut rng);

        trace!("confirmed! (and registered)");

        let mut manager = Manager {
            rng,
            config_store: self.config_store,
            state: Registered {
                push_service_cache: CacheCell::default(),
                identified_websocket: Default::default(),
                unidentified_websocket: Default::default(),
                unidentified_sender_certificate: Default::default(),
                signal_servers: self.state.signal_servers,
                device_name: None,
                phone_number,
                service_ids: ServiceIds {
                    aci: registered.uuid,
                    pni: registered.pni,
                },
                password,
                signaling_key,
                device_id: None,
                registration_id,
                pni_registration_id: Some(pni_registration_id),
                aci_private_key: aci_identity_key_pair.private_key,
                aci_public_key: aci_identity_key_pair.public_key,
                pni_private_key: Some(pni_identity_key_pair.private_key),
                pni_public_key: Some(pni_identity_key_pair.public_key),
                profile_key,
            },
        };

        manager.config_store.save_state(&manager.state)?;

        if let Err(e) = manager.register_pre_keys().await {
            // clear the entire store on any error, there's no possible recovery here
            manager.config_store.clear_registration()?;
            Err(e)
        } else {
            Ok(manager)
        }
    }
}

pub enum SyncItem<C> {
    InProgress(Content),
    Finished(Manager<C, Synced>),
}

pub enum ReceivedMessage {
    Content(Content),
    EmptyQueue,
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

    pub async fn initial_sync(mut self) -> Result<impl Stream<Item = SyncItem<C>>, Error<C::Error>> {
        Ok(self.receive_messages_stream(true).await?.take_while(|received| {
            future::ready(match received {
                ReceivedMessage::Content(_) => true,
                ReceivedMessage::EmptyQueue => false,
            })
        }).map(|received| {
            match received {
                ReceivedMessage::Content(content) => SyncItem::InProgress(content),
                ReceivedMessage::EmptyQueue => unreachable!("logic error"),
            }
        }).chain(stream::once(async move {
            SyncItem::Finished(Manager {
            rng: self.rng,
            config_store: self.config_store,
           state: Synced { inner: self.state } 
        })})))
    } 

    async fn register_pre_keys(&mut self) -> Result<(), Error<C::Error>> {
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

    async fn set_account_attributes(&mut self) -> Result<(), Error<C::Error>> {
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
        mut messages: impl Stream<Item = ReceivedMessage> + Unpin,
    ) -> Result<(), Error<C::Error>> {
        let mut message_receiver = MessageReceiver::new(self.push_service()?);
        while let Some(ReceivedMessage::Content(Content { body, .. })) = messages.next().await {
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

    async fn sync_contacts(&mut self) -> Result<(), Error<C::Error>> {
        let messages = self.receive_messages_stream(true).await?;
        pin_mut!(messages);

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
        let sync_message = SyncMessage {
            request: Some(sync_message::Request {
                r#type: Some(sync_message::request::Type::Contacts as i32),
            }),
            ..Default::default()
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        // first request the sync
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
        let credentials = self.credentials()?.ok_or(Error::NotYetRegisteredError)?;
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
        include_internal_events: bool,
    ) -> Result<impl Stream<Item = ReceivedMessage>, Error<C::Error>> {
        struct StreamState<S, C> {
            encrypted_messages: S,
            service_cipher: ServiceCipher<C>,
            config_store: C,
            groups_manager: GroupsManager<HyperPushService, InMemoryCredentialsCache>,
            include_internal_events: bool,
        }

        let init = StreamState {
            encrypted_messages: Box::pin(self.receive_messages_encrypted().await?),
            service_cipher: self.new_service_cipher()?,
            config_store: self.config_store.clone(),
            groups_manager: self.groups_manager()?,
            include_internal_events,
        };

        Ok(futures::stream::unfold(init, |mut state| async move {
            loop {
                match state.encrypted_messages.next().await {
                    Some(Ok(Incoming::QueueEmpty)) => return Some((ReceivedMessage::EmptyQueue, state)),
                    Some(Ok(Incoming::Envelope(envelope))) => {
                        match state.service_cipher.open_envelope(envelope).await {
                            Ok(Some(content)) => {
                                // contacts synchronization sent from the primary device (happens after linking, or on demand)
                                if let ContentBody::SynchronizeMessage(SyncMessage {
                                    contacts: Some(_),
                                    ..
                                }) = &content.body
                                {
                                    if state.include_internal_events {
                                        return Some((ReceivedMessage::Content(content), state));
                                    } else {
                                        continue;
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

                                return Some((ReceivedMessage::Content(content), state));
                            }
                            Ok(None) => {
                                debug!("Empty envelope..., message will be skipped!")
                            }
                            Err(e) => {
                                error!("Error opening envelope: {:?}, message will be skipped!", e);
                            }
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
    /// This method will automatically update the [DataMessage::expiration_timer] if it is set to
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
    /// This method will automatically update the [DataMessage::expiration_timer] if it is set to
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

    fn credentials(&self) -> Result<Option<ServiceCredentials>, Error<C::Error>> {
        Ok(Some(ServiceCredentials {
            uuid: Some(self.state.service_ids.aci),
            phonenumber: self.state.phone_number.clone(),
            password: Some(self.state.password.clone()),
            signaling_key: Some(self.state.signaling_key),
            device_id: self.state.device_id,
        }))
    }

    /// Returns a clone of a cached push service.
    ///
    /// If no service is yet cached, it will create and cache one.
    fn push_service(&self) -> Result<HyperPushService, Error<C::Error>> {
        self.state.push_service_cache.get(|| {
            let credentials = self.credentials()?;
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

impl<C: Store> Manager<C, Synced> {
    /// Starts receiving and storing messages.
    ///
    /// Returns a [Stream] of messages to consume. Messages will also be stored by the implementation of the [MessageStore].
    pub async fn receive_messages(
        &mut self,
    ) -> Result<impl Stream<Item = ReceivedMessage>, Error<C::Error>> {
        let mut hacked_manager = Manager { config_store: self.config_store.clone(), rng: self.rng.clone(), state: self.state.inner.clone() };
        hacked_manager.receive_messages_stream(false).await
    }

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

#[cfg(test)]
mod tests {
    use libsignal_service::prelude::ProfileKey;
    use libsignal_service::protocol::KeyPair;
    use rand::RngCore;
    use serde_json::json;

    use crate::Registered;

    #[test]
    fn test_state_before_pni() {
        let mut rng = rand::thread_rng();
        let key_pair = KeyPair::generate(&mut rng);
        let mut profile_key = [0u8; 32];
        rng.fill_bytes(&mut profile_key);
        let profile_key = ProfileKey::generate(profile_key);
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        // this is before public_key and private_key were renamed to aci_public_key and aci_private_key
        // and pni_public_key + pni_private_key were added
        let previous_state = json!({
          "signal_servers": "Production",
          "device_name": "Test",
          "phone_number": {
            "code": {
              "value": 1,
              "source": "plus"
            },
            "national": {
              "value": 5550199,
              "zeros": 0
            },
            "extension": null,
            "carrier": null
          },
          "uuid": "ff9a89d9-8052-4af0-a91d-2a0dfa0c6b95",
          "password": "HelloWorldOfPasswords",
          "signaling_key": base64::encode(signaling_key),
          "device_id": 42,
          "registration_id": 64,
          "private_key": base64::encode(key_pair.private_key.serialize()),
          "public_key": base64::encode(key_pair.public_key.serialize()),
          "profile_key": base64::encode(profile_key.get_bytes()),
        });

        let state: Registered = serde_json::from_value(previous_state).expect("should deserialize");
        assert_eq!(state.aci_public_key, key_pair.public_key);
        assert!(state.aci_private_key == key_pair.private_key);
        assert!(state.pni_public_key.is_none());
    }
}
