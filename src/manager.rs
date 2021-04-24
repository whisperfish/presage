use std::{convert::TryInto, path::PathBuf, time::UNIX_EPOCH};

use futures::{
    channel::mpsc::{channel, Sender},
    future, pin_mut, SinkExt, StreamExt,
};
use image::Luma;
use log::{error, info, trace, warn};
use prost::bytes::Bytes;
use qrcode::QrCode;
use rand::{distributions::Alphanumeric, Rng, RngCore};

use libsignal_protocol::{
    keys::{PrivateKey, PublicKey},
    stores::IdentityKeyStore,
    stores::PreKeyStore,
    stores::SessionStore,
    stores::SignedPreKeyStore,
    Context, StoreContext,
};
use libsignal_service::{
    cipher::ServiceCipher,
    configuration::{ServiceConfiguration, SignalServers, SignalingKey},
    content::{ContentBody, DataMessage, Metadata},
    groups_v2::{GroupsManager, InMemoryCredentialsCache},
    messagepipe::ServiceCredentials,
    models::Contact,
    prelude::{
        phonenumber::PhoneNumber, Content, GroupMasterKey, GroupSecretParams, MessageSender,
        PushService, Uuid,
    },
    proto::{sync_message, SyncMessage},
    provisioning::{
        ConfirmCodeMessage, LinkingManager, ProvisioningManager, SecondaryDeviceProvisioning,
        VerificationCodeResponse,
    },
    push_service::{ProfileKey, WhoAmIResponse, DEFAULT_DEVICE_ID},
    receiver::MessageReceiver,
    AccountManager, ServiceAddress,
};

use libsignal_service_hyper::push_service::HyperPushService;

use crate::{config::ConfigStore, Error};

#[derive(Clone)]
pub struct Manager<
    C: Clone
        + ConfigStore
        + PreKeyStore
        + SignedPreKeyStore
        + SessionStore
        + IdentityKeyStore
        + Send
        + 'static,
> {
    pub config_store: C,
    state: State,
    context: Context,
    store_context: StoreContext,
}

#[derive(Debug, Clone)]
pub enum State {
    New,
    Registration {
        signal_servers: SignalServers,
        phone_number: PhoneNumber,
        password: String,
    },
    Registered {
        signal_servers: SignalServers,
        phone_number: PhoneNumber,
        uuid: Uuid,
        password: String,
        signaling_key: SignalingKey,
        device_id: Option<i32>,
        registration_id: u32,
        private_key: PrivateKey,
        public_key: PublicKey,
        profile_key: [u8; 32],
    },
}

impl<C> Manager<C>
where
    C: Clone
        + ConfigStore
        + PreKeyStore
        + SignedPreKeyStore
        + SessionStore
        + IdentityKeyStore
        + Send
        + 'static,
{
    pub fn with_config_store(config_store: C, context: Context) -> Result<Self, Error> {
        let store_context = libsignal_protocol::store_context(
            &context,
            config_store.clone(),
            config_store.clone(),
            config_store.clone(),
            config_store.clone(),
        )?;
        let state = config_store.state(&context)?;
        Ok(Manager {
            config_store,
            state,
            context,
            store_context,
        })
    }

    fn save(&self) -> Result<(), Error> {
        trace!("saving configuration");
        self.config_store.save(&self.state)
    }

    fn credentials(&self) -> Result<Option<ServiceCredentials>, Error> {
        match &self.state {
            State::New => Err(Error::NotYetRegisteredError),
            State::Registration { .. } => Ok(None),
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

    pub async fn register(
        &mut self,
        signal_servers: SignalServers,
        phone_number: PhoneNumber,
        use_voice_call: bool,
        captcha: Option<&str>,
    ) -> Result<(), Error> {
        // generate a random 24 bytes password
        let rng = rand::rngs::OsRng::default();
        let password: String = rng.sample_iter(&Alphanumeric).take(24).collect();

        let cfg: ServiceConfiguration = signal_servers.into();
        let mut provisioning_manager: ProvisioningManager<HyperPushService> =
            ProvisioningManager::new(
                cfg,
                crate::USER_AGENT.to_string(),
                phone_number.clone(),
                password.clone(),
            );

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

        self.state = State::Registration {
            signal_servers,
            phone_number,
            password,
        };

        self.save()?;
        Ok(())
    }

    pub async fn confirm_verification_code(&mut self, confirm_code: u32) -> Result<(), Error> {
        trace!("confirming verification code");
        let (signal_servers, phone_number, password) = match &self.state {
            State::New => return Err(Error::NotYetRegisteredError),
            State::Registration {
                signal_servers,
                phone_number,
                password,
            } => (signal_servers, phone_number, password),
            State::Registered { .. } => return Err(Error::AlreadyRegisteredError),
        };

        let registration_id = libsignal_protocol::generate_registration_id(&self.context, 0)?;
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
        let cfg: ServiceConfiguration = (*signal_servers).into();
        let mut provisioning_manager: ProvisioningManager<HyperPushService> =
            ProvisioningManager::new(
                cfg,
                crate::USER_AGENT.to_string(),
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

        let identity_key_pair = libsignal_protocol::generate_identity_key_pair(&self.context)?;

        self.state = State::Registered {
            signal_servers: *signal_servers,
            phone_number: phone_number.clone(),
            uuid: registered.uuid,
            password: password.clone(),
            signaling_key,
            device_id: None,
            registration_id,
            private_key: identity_key_pair.private(),
            public_key: identity_key_pair.public(),
            profile_key: profile_key.0,
        };

        trace!("confirmed! (and registered)");

        self.save()?;

        self.register_pre_keys().await?;

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

        let mut linking_manager: LinkingManager<HyperPushService> = LinkingManager::new(
            signal_servers,
            crate::USER_AGENT.to_string(),
            password.clone(),
        );

        let (tx, mut rx) = channel(1);

        let (fut1, fut2) = future::join(
            linking_manager.provision_secondary_device(
                &self.context,
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

        self.state = State::Registered {
            signal_servers,
            phone_number,
            uuid,
            signaling_key,
            password,
            device_id: Some(device_id),
            registration_id,
            public_key,
            private_key,
            profile_key: profile_key.try_into().unwrap(),
        };

        self.save()?;
        self.register_pre_keys().await?;
        Ok(())
    }

    pub async fn whoami(&self) -> Result<WhoAmIResponse, Error> {
        // TODO: also factor this
        let signal_servers = match &self.state {
            State::New | State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered { signal_servers, .. } => signal_servers,
        };

        let credentials = self.credentials()?;
        let service_configuration: ServiceConfiguration = (*signal_servers).into();

        let mut push_service = HyperPushService::new(
            service_configuration,
            credentials.clone(),
            crate::USER_AGENT.to_string(),
        );

        Ok(push_service.whoami().await?)
    }

    pub async fn register_pre_keys(&self) -> Result<(), Error> {
        let (signal_servers, profile_key) = match &self.state {
            State::New | State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered {
                signal_servers,
                profile_key,
                ..
            } => (signal_servers, profile_key),
        };

        let cfg: ServiceConfiguration = (*signal_servers).into();
        let push_service =
            HyperPushService::new(cfg, self.credentials()?, crate::USER_AGENT.to_string());

        let mut account_manager = AccountManager::new(
            self.context.clone(),
            push_service,
            Some(profile_key.clone()),
        );

        let (pre_keys_offset_id, next_signed_pre_key_id) = account_manager
            .update_pre_key_bundle(
                self.store_context.clone(),
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

    pub async fn request_contacts_sync(&self) -> Result<(), Error> {
        let phone_number = match &self.state {
            State::New | State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered { phone_number, .. } => phone_number,
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

    pub async fn receive_messages(
        &self,
        mut tx: Sender<(Metadata, ContentBody)>,
    ) -> Result<(), Error> {
        let (signal_servers, phone_number, uuid) = match &self.state {
            State::New | State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered {
                signal_servers,
                phone_number,
                uuid,
                ..
            } => (signal_servers, phone_number, uuid),
        };

        // TODO: error if we're primary registered device, as this is only for secondary devices

        let credentials = self.credentials()?;
        let service_configuration: ServiceConfiguration = (*signal_servers).into();
        let certificate_validator = service_configuration.credentials_validator(&self.context)?;

        let local_addr = ServiceAddress {
            uuid: Some(uuid.clone()),
            phonenumber: Some(phone_number.clone()),
            relay: None,
        };

        let mut service_cipher = ServiceCipher::from_context(
            self.context.clone(),
            self.store_context.clone(),
            local_addr,
            certificate_validator,
        );

        let push_service = HyperPushService::new(
            service_configuration.clone(),
            credentials.clone(),
            crate::USER_AGENT.to_string(),
        );

        let mut receiver = MessageReceiver::new(push_service);

        let pipe = receiver
            .create_message_pipe(credentials.unwrap())
            .await
            .unwrap();
        let message_stream = pipe.stream();
        pin_mut!(message_stream);

        while let Some(step) = message_stream.next().await {
            match step {
                Ok(envelope) => {
                    let Content { body, metadata } = match service_cipher.open_envelope(envelope) {
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
        let mut sender = self.get_sender()?;

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
        let mut sender = self.get_sender()?;

        let recipients: Vec<_> = recipients.into_iter().collect();

        let online_only = false;
        let results = sender
            .send_message_to_group(recipients, None, message, timestamp, online_only)
            .await;

        // return first error if any
        results.into_iter().find(|res| res.is_err()).transpose()?;

        Ok(())
    }

    fn get_sender(&self) -> Result<MessageSender<HyperPushService>, Error> {
        let (signal_servers, phone_number, uuid, device_id) = match &self.state {
            State::New | State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered {
                signal_servers,
                phone_number,
                uuid,
                device_id,
                ..
            } => (signal_servers, phone_number, uuid, device_id),
        };

        let credentials = self.credentials()?;
        let service_configuration: ServiceConfiguration = (*signal_servers).into();

        let certificate_validator = service_configuration.credentials_validator(&self.context)?;
        let push_service = HyperPushService::new(
            service_configuration,
            credentials,
            crate::USER_AGENT.to_string(),
        );

        let local_addr = ServiceAddress {
            uuid: Some(uuid.clone()),
            phonenumber: Some(phone_number.clone()),
            relay: None,
        };

        let service_cipher = ServiceCipher::from_context(
            self.context.clone(),
            self.store_context.clone(),
            local_addr,
            certificate_validator,
        );

        Ok(MessageSender::new(
            push_service,
            service_cipher,
            device_id.unwrap_or(DEFAULT_DEVICE_ID),
        ))
    }

    pub fn clear_sessions(&self, recipient: &ServiceAddress) -> Result<(), Error> {
        self.config_store
            .delete_all_sessions(&recipient.identifier().as_bytes())?;
        Ok(())
    }

    pub async fn get_group_v2(
        &mut self,
        group_master_key: GroupMasterKey,
    ) -> Result<libsignal_service::proto::DecryptedGroup, Error> {
        let (signal_servers, _phone_number, uuid, _device_id) = match &self.state {
            State::New | State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered {
                signal_servers,
                phone_number,
                uuid,
                device_id,
                ..
            } => (signal_servers, phone_number, uuid, device_id),
        };

        let credentials = self.credentials()?;

        let service_configuration: ServiceConfiguration = (*signal_servers).into();
        let server_public_params = service_configuration.zkgroup_server_public_params.clone();

        let push_service = HyperPushService::new(
            service_configuration,
            credentials,
            crate::USER_AGENT.to_string(),
        );

        let mut groups_v2_credentials_cache = InMemoryCredentialsCache::default();
        let mut groups_v2_api = GroupsManager::new(
            push_service,
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
}
