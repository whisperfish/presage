use std::{convert::TryInto, time::UNIX_EPOCH};

use futures::{
    channel::mpsc::{channel, Sender},
    future, pin_mut, AsyncReadExt, SinkExt, Stream, StreamExt,
};
use image::Luma;
use log::{error, trace, warn};
use qrcode::QrCode;
use rand::{distributions::Alphanumeric, CryptoRng, Rng, RngCore};
use serde::{Deserialize, Serialize};

use libsignal_service::{
    attachment_cipher::decrypt_in_place,
    cipher,
    configuration::{ServiceConfiguration, SignalServers, SignalingKey},
    content::{ContentBody, DataMessage, Metadata},
    groups_v2::{GroupsManager, InMemoryCredentialsCache},
    messagepipe::ServiceCredentials,
    models::Contact,
    prelude::{
        phonenumber::PhoneNumber,
        protocol::{KeyPair, PrivateKey, PublicKey},
        Content, Envelope, GroupMasterKey, GroupSecretParams, PushService, Uuid,
    },
    proto::{sync_message, AttachmentPointer, SyncMessage},
    provisioning::{
        generate_registration_id, ConfirmCodeMessage, LinkingManager, ProvisioningManager,
        SecondaryDeviceProvisioning, VerificationCodeResponse,
    },
    push_service::{
        DeviceCapabilities, ProfileKey, ServiceError, WhoAmIResponse, DEFAULT_DEVICE_ID,
    },
    receiver::MessageReceiver,
    utils::{serde_private_key, serde_public_key, serde_signaling_key},
    AccountManager, Profile, ServiceAddress,
};

use libsignal_service_hyper::push_service::HyperPushService;

use crate::cache::CacheCell;
use crate::{config::ConfigStore, Error};

type ServiceCipher<C, R> = cipher::ServiceCipher<C, C, C, C, R>;
type MessageSender<C, R> =
    libsignal_service::prelude::MessageSender<HyperPushService, C, C, C, C, R>;

#[derive(Clone)]
pub struct Manager<C, R = rand::rngs::ThreadRng> {
    /// Persistant store
    config_store: C,
    /// Random generator
    csprng: R,
    /// Part of the manager which is persisted in the store.
    state: State,
    /// Part of the manager which is cached.
    ///
    /// The cache should be cleared when state changes.
    cache: Cache,
}

#[derive(Clone, Default)]
struct Cache {
    push_service: CacheCell<HyperPushService>,
}

impl Cache {
    fn clear(&self) {
        self.push_service.clear();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub enum State {
    New,
    Registration {
        signal_servers: SignalServers,
        phone_number: PhoneNumber,
        use_voice_call: bool,
        captcha: Option<String>,
    },
    Linking {
        signal_servers: SignalServers,
        #[serde(with = "serde_signaling_key")]
        signaling_key: SignalingKey,
        password: String,
    },
    Confirmation {
        signal_servers: SignalServers,
        phone_number: PhoneNumber,
        password: String,
    },
    Registered {
        signal_servers: SignalServers,
        phone_number: PhoneNumber,
        uuid: Uuid,
        password: String,
        #[serde(with = "serde_signaling_key")]
        signaling_key: SignalingKey,
        device_id: Option<u32>,
        registration_id: u32,
        #[serde(with = "serde_private_key")]
        private_key: PrivateKey,
        #[serde(with = "serde_public_key")]
        public_key: PublicKey,
        profile_key: ProfileKey,
    },
}

impl<C> Manager<C>
where
    C: ConfigStore,
{
    /// Creates a new manager from a store with a default random generator.
    pub fn with_store(store: C) -> Result<Self, Error> {
        Self::new(store, rand::thread_rng())
    }
}

impl<C, R> Manager<C, R>
where
    C: ConfigStore,
    R: Rng + CryptoRng + Clone,
{
    pub fn new(config_store: C, csprng: R) -> Result<Self, Error> {
        let state = config_store.state()?;
        Ok(Manager {
            config_store,
            csprng,
            state,
            cache: Default::default(),
        })
    }

    /// Sets the state and saves it into the store.
    ///
    /// The cache is also cleared.
    fn set_state(&mut self, state: State) -> Result<(), Error> {
        self.state = state;
        self.cache.clear();
        self.config_store.save(&self.state)
    }

    fn credentials(&self) -> Result<Option<ServiceCredentials>, Error> {
        match &self.state {
            State::New { .. } => Err(Error::NotYetRegisteredError),
            State::Registration { .. } => Ok(None),
            State::Linking { .. } => Ok(None),
            State::Confirmation {
                phone_number,
                password,
                ..
            } => Ok(Some(ServiceCredentials {
                uuid: None,
                phonenumber: phone_number.clone(),
                password: Some(password.clone()),
                signaling_key: None,
                device_id: None,
            })),
            State::Registered {
                phone_number,
                uuid,
                device_id,
                password,
                signaling_key,
                ..
            } => Ok(Some(ServiceCredentials {
                uuid: Some(*uuid),
                phonenumber: phone_number.clone(),
                password: Some(password.clone()),
                signaling_key: Some(*signaling_key),
                device_id: *device_id,
            })),
        }
    }

    /// Checks if the manager has a registered device.
    pub fn is_registered(&self) -> bool {
        matches!(&self.state, State::Registered { .. })
    }

    pub fn config_store(&self) -> &C {
        &self.config_store
    }

    pub fn uuid(&self) -> Uuid {
        match &self.state {
            State::Registered { uuid, .. } => *uuid,
            _ => Default::default(),
        }
    }

    pub fn phone_number(&self) -> Option<&PhoneNumber> {
        match &self.state {
            State::Registered { phone_number, .. } => Some(phone_number),
            _ => None,
        }
    }

    #[cfg(feature = "quirks")]
    pub fn dump_config(&mut self) -> Result<(), Error> {
        serde_json::to_writer_pretty(std::io::stderr(), &self.state)?;
        Ok(())
    }

    pub async fn register(
        &mut self,
        signal_servers: SignalServers,
        phone_number: PhoneNumber,
        use_voice_call: bool,
        captcha: Option<String>,
        force: bool,
    ) -> Result<(), Error> {
        // generate a random 24 bytes password
        let rng = rand::rngs::OsRng::default();
        let password: String = rng.sample_iter(&Alphanumeric).take(24).collect();

        if !force
            && matches!(
                self.state,
                State::Registration { .. } | State::Registered { .. }
            )
        {
            return Err(Error::AlreadyRegisteredError);
        }

        // re-initialize the state to new with specified servers & phone number
        self.set_state(State::Registration {
            signal_servers,
            phone_number: phone_number.clone(),
            use_voice_call,
            captcha: captcha.clone(),
        })?;

        let mut push_service = self.push_service()?;
        let mut provisioning_manager: ProvisioningManager<HyperPushService> =
            ProvisioningManager::new(&mut push_service, phone_number.clone(), password.clone());

        let verification_code_response = if use_voice_call {
            provisioning_manager
                .request_voice_verification_code(captcha.as_deref(), None)
                .await?
        } else {
            provisioning_manager
                .request_sms_verification_code(captcha.as_deref(), None)
                .await?
        };

        if let VerificationCodeResponse::CaptchaRequired = verification_code_response {
            return Err(Error::CaptchaRequired);
        }

        self.set_state(State::Confirmation {
            signal_servers,
            phone_number,
            password,
        })
    }

    pub async fn confirm_verification_code(&mut self, confirm_code: u32) -> Result<(), Error> {
        trace!("confirming verification code");
        let (signal_servers, phone_number, password) = match &self.state {
            State::Confirmation {
                signal_servers,
                phone_number,
                password,
            } => (*signal_servers, phone_number, password),
            State::Registered { .. } => return Err(Error::AlreadyRegisteredError),
            _ => return Err(Error::NotYetRegisteredError),
        };

        // see libsignal-protocol-c / signal_protocol_key_helper_generate_registration_id
        let registration_id = generate_registration_id(&mut self.csprng);
        trace!("registration_id: {}", registration_id);

        // let mut push_service = HyperPushService::new(
        //     (*signal_servers).into(),
        //     Some(ServiceCredentials {
        //         phonenumber: phone_number.clone(),
        //         password: Some(password.clone()),
        //         uuid: None,
        //         signaling_key: None,
        //         device_id: None,
        //     }),
        //     USER_AGENT,
        // );
        let mut push_service = self.push_service()?;
        let mut provisioning_manager: ProvisioningManager<HyperPushService> =
            ProvisioningManager::new(
                &mut push_service,
                phone_number.clone(),
                password.to_string(),
            );

        let mut rng = rand::rngs::OsRng::default();
        // generate a 52 bytes signaling key
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        let mut profile_key = [0u8; 32];
        rng.fill_bytes(&mut profile_key);
        let profile_key = ProfileKey(profile_key);

        let registered = provisioning_manager
            .confirm_verification_code(
                confirm_code,
                ConfirmCodeMessage::new(
                    signaling_key.to_vec(),
                    registration_id,
                    profile_key.derive_access_key(),
                ),
            )
            .await?;

        let identity_key_pair = KeyPair::generate(&mut self.csprng);

        let phone_number = phone_number.clone();
        let password = password.clone();
        self.set_state(State::Registered {
            signal_servers,
            phone_number,
            uuid: registered.uuid,
            password,
            signaling_key,
            device_id: None,
            registration_id,
            private_key: identity_key_pair.private_key,
            public_key: identity_key_pair.public_key,
            profile_key,
        })?;

        trace!("confirmed! (and registered)");

        self.register_pre_keys().await?;
        self.set_account_attributes().await?;

        Ok(())
    }

    pub async fn link_secondary_device(
        &mut self,
        signal_servers: SignalServers,
        device_name: String,
    ) -> Result<(), Error> {
        // generate a random 24 bytes password
        let mut rng = rand::rngs::OsRng::default();
        let password: String = rng.sample_iter(&Alphanumeric).take(24).collect();

        // generate a 52 bytes signaling key
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        self.set_state(State::Linking {
            signal_servers,
            password: password.clone(),
            signaling_key,
        })?;

        let push_service = self.push_service()?;
        let mut linking_manager: LinkingManager<HyperPushService> =
            LinkingManager::new(push_service, password.clone());

        let (tx, mut rx) = channel(1);

        let (fut1, fut2) = future::join(
            linking_manager.provision_secondary_device(
                &mut self.csprng,
                signaling_key,
                &device_name,
                tx,
            ),
            async move {
                while let Some(provisioning_step) = rx.next().await {
                    match provisioning_step {
                        SecondaryDeviceProvisioning::Url(url) => {
                            log::info!("generating qrcode from provisioning link: {}", &url);
                            let code =
                                QrCode::new(url.as_str()).expect("failed to generate qrcode");
                            let image = code.render::<Luma<u8>>().build();
                            let path = std::env::temp_dir().join("device-link.png");
                            image.save(&path).map_err(|e| {
                                log::error!("failed to generate qr code: {}", e);
                                Error::QrCodeError
                            })?;
                            opener::open(path).map_err(|e| {
                                log::error!("failed to open qr code: {}", e);
                                Error::QrCodeError
                            })?;
                        }
                        SecondaryDeviceProvisioning::NewDeviceRegistration {
                            phone_number,
                            device_id,
                            registration_id,
                            uuid,
                            private_key,
                            public_key,
                            profile_key,
                        } => {
                            log::info!("successfully registered device {}", &uuid);
                            return Ok((
                                phone_number,
                                device_id.device_id,
                                registration_id,
                                uuid,
                                private_key,
                                public_key,
                                profile_key,
                            ));
                        }
                    }
                }
                Err(Error::NoProvisioningMessageReceived)
            },
        )
        .await;

        let _ = fut1?;
        let (phone_number, device_id, registration_id, uuid, private_key, public_key, profile_key) =
            fut2?;

        self.set_state(State::Registered {
            signal_servers,
            phone_number,
            uuid,
            signaling_key,
            password,
            device_id: Some(device_id),
            registration_id,
            public_key,
            private_key,
            profile_key: ProfileKey(profile_key.try_into().expect("32 bytes for profile key")),
        })?;

        self.register_pre_keys().await?;
        self.set_account_attributes().await?;

        Ok(())
    }

    pub async fn whoami(&self) -> Result<WhoAmIResponse, Error> {
        Ok(self.push_service()?.whoami().await?)
    }

    pub async fn retrieve_profile(&self) -> Result<Profile, Error> {
        match &self.state {
            State::Registered {
                uuid, profile_key, ..
            } => self.retrieve_profile_by_uuid(*uuid, **profile_key).await,
            _ => return Err(Error::NotYetRegisteredError),
        }
    }

    pub async fn retrieve_profile_by_uuid(
        &self,
        uuid: Uuid,
        profile_key: [u8; 32],
    ) -> Result<Profile, Error> {
        let mut account_manager = AccountManager::new(self.push_service()?, Some(profile_key));
        Ok(account_manager.retrieve_profile(uuid).await?)
    }

    async fn register_pre_keys(&mut self) -> Result<(), Error> {
        let profile_key = match &self.state {
            State::Registered { profile_key, .. } => profile_key,
            _ => return Err(Error::NotYetRegisteredError),
        };

        let mut account_manager = AccountManager::new(self.push_service()?, Some(**profile_key));

        let (pre_keys_offset_id, next_signed_pre_key_id) = account_manager
            .update_pre_key_bundle(
                &self.config_store.clone(),
                &mut self.config_store.clone(),
                &mut self.config_store.clone(),
                &mut self.csprng,
                self.config_store.pre_keys_offset_id()?,
                self.config_store.next_signed_pre_key_id()?,
                true,
            )
            .await?;

        self.config_store
            .set_pre_keys_offset_id(pre_keys_offset_id)?;
        self.config_store
            .set_next_signed_pre_key_id(next_signed_pre_key_id)?;

        Ok(())
    }

    async fn set_account_attributes(&mut self) -> Result<(), Error> {
        let (profile_key, registration_id) = match &self.state {
            State::Registered {
                profile_key,
                registration_id,
                ..
            } => (profile_key, registration_id),
            _ => return Err(Error::NotYetRegisteredError),
        };
        let mut account_manager = AccountManager::new(self.push_service()?, Some(**profile_key));
        account_manager
            .set_account_attributes(
                None,
                *registration_id,
                false,
                false,
                true,
                None,
                None,
                None,
                false,
                true,
                DeviceCapabilities {
                    uuid: true,
                    gv2: true,
                    storage: false,
                    gv1_migration: true,
                },
            )
            .await?;
        Ok(())
    }

    pub async fn request_contacts_sync(&self) -> Result<(), Error> {
        let phone_number = match &self.state {
            State::Registered { phone_number, .. } => phone_number,
            _ => return Err(Error::NotYetRegisteredError),
        };

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

        self.send_message(phone_number.clone(), sync_message, timestamp)
            .await?;

        Ok(())
    }

    async fn receive_messages_encrypted_stream(
        &self,
    ) -> Result<impl Stream<Item = Result<Envelope, ServiceError>>, Error> {
        // TODO: error if we're primary registered device, as this is only for secondary devices

        let credentials = self.credentials()?.ok_or(Error::NotYetRegisteredError)?;
        let pipe = MessageReceiver::new(self.push_service()?)
            .create_message_pipe(credentials)
            .await?;
        Ok(pipe.stream())
    }

    pub async fn receive_messages_stream(&self) -> Result<impl Stream<Item = Content>, Error> {
        struct StreamState<S, C, R> {
            encrypted_messages: S,
            service_cipher: ServiceCipher<C, R>,
        }

        let init = StreamState {
            encrypted_messages: Box::pin(self.receive_messages_encrypted_stream().await?),
            service_cipher: self.new_service_cipher()?,
        };

        Ok(futures::stream::unfold(init, |mut state| async move {
            loop {
                match state.encrypted_messages.next().await {
                    Some(Ok(envelope)) => {
                        match state.service_cipher.open_envelope(envelope).await {
                            Ok(Some(content)) => return Some((content, state)),
                            Ok(None) => warn!("Empty envelope..., message will be skipped!"),
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

    pub async fn receive_messages(
        &self,
        mut tx: Sender<(Metadata, ContentBody)>,
    ) -> Result<(), Error> {
        let credentials = self.credentials()?.ok_or(Error::NotYetRegisteredError)?;

        let mut service_cipher = self.new_service_cipher()?;
        let mut receiver = MessageReceiver::new(self.push_service()?);

        let pipe = receiver.create_message_pipe(credentials).await.unwrap();
        let message_stream = pipe.stream();
        pin_mut!(message_stream);

        while let Some(step) = message_stream.next().await {
            match step {
                Ok(envelope) => {
                    let Content { body, metadata } =
                        match service_cipher.open_envelope(envelope).await {
                            Ok(Some(content)) => content,
                            Ok(None) => {
                                warn!("Empty envelope...");
                                continue;
                            }
                            Err(e) => {
                                error!("Error opening envelope: {:?}, message will be skipped!", e);
                                continue;
                            }
                        };

                    match &body {
                        ContentBody::SynchronizeMessage(SyncMessage {
                            contacts: Some(contacts),
                            ..
                        }) => {
                            // TODO: save contacts here, for now we just print them
                            let contacts: Result<Vec<Contact>, _> =
                                receiver.retrieve_contacts(contacts).await?.collect();
                            for c in contacts? {
                                log::info!("Contact {}", c.name);
                            }
                            // let _ = cdn_push_service.get_contacts(contacts).await;
                        }
                        _ => tx.send((metadata, body)).await.expect("tx channel error"),
                    };
                }
                Err(e) => {
                    error!("Error: {}", e);
                }
            }
        }

        Ok(())
    }

    pub async fn send_message(
        &self,
        recipient_addr: impl Into<ServiceAddress>,
        message: impl Into<ContentBody>,
        timestamp: u64,
    ) -> Result<(), Error> {
        let mut sender = self.new_message_sender()?;

        let online_only = false;
        sender
            .send_message(
                &recipient_addr.into(),
                None,
                message,
                timestamp,
                online_only,
            )
            .await?;

        Ok(())
    }

    pub async fn send_message_to_group(
        &self,
        recipients: impl IntoIterator<Item = ServiceAddress>,
        message: DataMessage,
        timestamp: u64,
    ) -> Result<(), Error> {
        let mut sender = self.new_message_sender()?;

        let recipients: Vec<_> = recipients.into_iter().collect();

        let online_only = false;
        let results = sender
            .send_message_to_group(recipients, None, message, timestamp, online_only)
            .await;

        // return first error if any
        results.into_iter().find(|res| res.is_err()).transpose()?;

        Ok(())
    }

    pub async fn clear_sessions(&self, recipient: &ServiceAddress) -> Result<(), Error> {
        self.config_store
            .delete_all_sessions(&recipient.identifier())
            .await?;
        Ok(())
    }

    pub async fn get_group_v2(
        &mut self,
        group_master_key: GroupMasterKey,
    ) -> Result<libsignal_service::proto::DecryptedGroup, Error> {
        let (signal_servers, _phone_number, uuid, _device_id) = match &self.state {
            State::Registered {
                signal_servers,
                phone_number,
                uuid,
                device_id,
                ..
            } => (signal_servers, phone_number, uuid, device_id),
            _ => return Err(Error::NotYetRegisteredError),
        };

        let service_configuration: ServiceConfiguration = (*signal_servers).into();
        let server_public_params = service_configuration.zkgroup_server_public_params;

        let mut groups_v2_credentials_cache = InMemoryCredentialsCache::default();
        let mut groups_v2_api = GroupsManager::new(
            self.push_service()?,
            &mut groups_v2_credentials_cache,
            server_public_params,
        );

        let group_secret_params = GroupSecretParams::derive_from_master_key(group_master_key);
        let authorization = groups_v2_api
            .get_authorization_for_today(*uuid, group_secret_params)
            .await?;

        Ok(groups_v2_api
            .get_group(group_secret_params, authorization)
            .await?)
    }

    pub async fn get_attachment(
        &self,
        attachment_pointer: &AttachmentPointer,
    ) -> Result<Vec<u8>, Error> {
        let mut service = self.push_service()?;
        let mut attachment_stream = service.get_attachment(&attachment_pointer).await?;

        // We need the whole file for the crypto to check out
        let mut ciphertext = Vec::new();
        let len = attachment_stream
            .read_to_end(&mut ciphertext)
            .await
            .expect("streamed attachment");

        trace!("downloaded encrypted attachment of {} bytes", len);

        let key: [u8; 64] = attachment_pointer.key().try_into()?;
        decrypt_in_place(key, &mut ciphertext)?;

        Ok(ciphertext)
    }

    /// Returns a clone of a cached push service.
    ///
    /// If no service is yet cached, it will create and cache one.
    fn push_service(&self) -> Result<HyperPushService, Error> {
        self.cache.push_service.get(|| {
            let signal_servers = match &self.state {
                State::Registration { signal_servers, .. }
                | State::Linking { signal_servers, .. }
                | State::Confirmation { signal_servers, .. }
                | State::Registered { signal_servers, .. } => signal_servers,
                _ => return Err(Error::NotYetRegisteredError),
            };

            let credentials = self.credentials()?;
            let service_configuration: ServiceConfiguration = (*signal_servers).into();

            Ok(HyperPushService::new(
                service_configuration,
                credentials,
                crate::USER_AGENT.to_string(),
            ))
        })
    }

    /// Creates a new message sender.
    fn new_message_sender(&self) -> Result<MessageSender<C, R>, Error> {
        let (phone_number, uuid, device_id) = match &self.state {
            State::Registered {
                phone_number,
                uuid,
                device_id,
                ..
            } => (phone_number, uuid, device_id),
            _ => return Err(Error::NotYetRegisteredError),
        };

        let local_addr = ServiceAddress {
            uuid: Some(*uuid),
            phonenumber: Some(phone_number.clone()),
            relay: None,
        };

        Ok(MessageSender::new(
            self.push_service()?,
            self.new_service_cipher()?,
            self.csprng.clone(),
            self.config_store.clone(),
            self.config_store.clone(),
            local_addr,
            device_id.unwrap_or(DEFAULT_DEVICE_ID),
        ))
    }

    /// Creates a new service cipher.
    fn new_service_cipher(&self) -> Result<ServiceCipher<C, R>, Error> {
        let signal_servers = match &self.state {
            State::Registered { signal_servers, .. } => signal_servers,
            _ => return Err(Error::NotYetRegisteredError),
        };

        let service_configuration: ServiceConfiguration = (*signal_servers).into();
        let certificate_validator = service_configuration.credentials_validator()?;
        let service_cipher = ServiceCipher::new(
            self.config_store.clone(),
            self.config_store.clone(),
            self.config_store.clone(),
            self.config_store.clone(),
            self.csprng.clone(),
            certificate_validator,
        );

        Ok(service_cipher)
    }
}
