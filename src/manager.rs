use std::time::UNIX_EPOCH;

use futures::{
    channel::mpsc::{channel, Sender},
    future, pin_mut, SinkExt, StreamExt,
};
use image::Luma;
use log::{error, trace, warn};
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
    configuration::ServiceConfiguration,
    configuration::SignalServers,
    configuration::SignalingKey,
    content::Metadata,
    content::{ContentBody, DataMessage, Reaction, SyncMessage, sync_message},
    messagepipe::Credentials,
    prelude::Content,
    prelude::{MessageSender, PushService},
    push_service::{ConfirmCodeMessage, ProfileKey, DEFAULT_DEVICE_ID},
    receiver::MessageReceiver,
    AccountManager, ServiceAddress, USER_AGENT,
};
use libsignal_service_actix::{
    provisioning::provision_secondary_device,
    provisioning::SecondaryDeviceProvisioning, push_service::AwcPushService,
};

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
        phone_number: String,
        password: String,
    },
    Registered {
        signal_servers: SignalServers,
        phone_number: String,
        uuid: String,
        password: String,
        signaling_key: SignalingKey,
        device_id: Option<i32>,
        registration_id: u32,
        private_key: PrivateKey,
        public_key: PublicKey,
        profile_key: Vec<u8>,
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
    pub fn with_config_store(
        config_store: C,
        context: Context,
    ) -> Result<Self, Error> {
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

    fn credentials(&self) -> Result<Option<Credentials>, Error> {
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
            } => {
                let uuid = if let Some(device_id) = device_id {
                    trace!(
                        "using credentials with UUID {} and device_id {}",
                        uuid,
                        device_id
                    );
                    format!("{}.{}", uuid, device_id)
                } else {
                    trace!("using credentials with UUID {} only", uuid);
                    uuid.to_string()
                };

                Ok(Some(Credentials {
                    uuid: Some(uuid),
                    e164: phone_number.clone(),
                    password: Some(password.clone()),
                    signaling_key: Some(signaling_key.clone()),
                }))
            }
        }
    }

    pub async fn register(
        &mut self,
        signal_servers: SignalServers,
        phone_number: String,
        use_voice_call: bool,
    ) -> Result<(), Error> {
        // generate a random 24 bytes password
        let rng = rand::rngs::OsRng::default();
        let password: String =
            rng.sample_iter(&Alphanumeric).take(24).collect();

        let mut push_service = AwcPushService::new(
            signal_servers.into(),
            Some(Credentials {
                e164: phone_number.clone(),
                password: Some(password.clone()),
                uuid: None,
                signaling_key: None,
            }),
            USER_AGENT,
        );

        if use_voice_call {
            push_service
                .request_voice_verification_code(&phone_number)
                .await?;
        } else {
            push_service
                .request_sms_verification_code(&phone_number)
                .await?;
        }

        self.state = State::Registration {
            signal_servers,
            phone_number,
            password,
        };

        self.save()?;
        Ok(())
    }

    pub async fn confirm_verification_code(
        &mut self,
        confirm_code: u32,
    ) -> Result<(), Error> {
        trace!("confirming verification code");
        let (signal_servers, phone_number, password) = match &self.state {
            State::New => return Err(Error::NotYetRegisteredError),
            State::Registration {
                signal_servers,
                phone_number,
                password,
            } => (signal_servers, phone_number, password),
            State::Registered { .. } => {
                return Err(Error::AlreadyRegisteredError)
            }
        };

        let registration_id =
            libsignal_protocol::generate_registration_id(&self.context, 0)?;
        trace!("registration_id: {}", registration_id);

        let mut push_service = AwcPushService::new(
            (*signal_servers).into(),
            Some(Credentials {
                e164: phone_number.clone(),
                password: Some(password.clone()),
                uuid: None,
                signaling_key: None,
            }),
            USER_AGENT,
        );

        let mut rng = rand::rngs::OsRng::default();
        // generate a 52 bytes signaling key
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        let mut profile_key = [0u8; 32];
        rng.fill_bytes(&mut profile_key);
        let profile_key = ProfileKey(profile_key.to_vec());

        let registered = push_service
            .confirm_verification_code(
                confirm_code,
                ConfirmCodeMessage::new(
                    signaling_key.to_vec(),
                    registration_id,
                    profile_key.derive_access_key(),
                ),
            )
            .await?;

        let identity_key_pair =
            libsignal_protocol::generate_identity_key_pair(&self.context)?;

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
        let password: String =
            rng.sample_iter(&Alphanumeric).take(24).collect();

        // generate a 52 bytes signaling key
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        let (tx, mut rx) = channel(1);

        let (fut1, fut2) = future::join(
            provision_secondary_device(
                &self.context,
                &signal_servers.into(),
                &signaling_key,
                &password,
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
        let (
            phone_number,
            device_id,
            registration_id,
            uuid,
            private_key,
            public_key,
            profile_key,
        ) = fut2?;

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
            profile_key,
        };

        self.save()?;
        self.register_pre_keys().await?;
        Ok(())
    }

    pub async fn register_pre_keys(&self) -> Result<(), Error> {
        let signal_servers = match &self.state {
            State::New | State::Registration { .. } => {
                return Err(Error::NotYetRegisteredError)
            }
            State::Registered { signal_servers, .. } => signal_servers,
        };

        let push_service = AwcPushService::new(
            (*signal_servers).into(),
            self.credentials()?,
            USER_AGENT,
        );

        let mut account_manager =
            AccountManager::new(self.context.clone(), push_service);

        let (pre_keys_offset_id, next_signed_pre_key_id) = account_manager
            .update_pre_key_bundle(
                self.store_context.clone(),
                self.config_store.pre_keys_offset_id()?,
                self.config_store.next_signed_pre_key_id()?,
            )
            .await?;

        self.config_store
            .set_pre_keys_offset_id(pre_keys_offset_id)?;
        self.config_store
            .set_next_signed_pre_key_id(next_signed_pre_key_id)?;

        Ok(())
    }

    pub async fn receive_messages(
        &self,
        mut tx: Sender<(Metadata, ContentBody)>,
    ) -> Result<(), Error> {
        let (signal_servers, phone_number, uuid) = match &self.state {
            State::New | State::Registration { .. } => {
                return Err(Error::NotYetRegisteredError)
            }
            State::Registered {
                signal_servers,
                phone_number,
                uuid,
                ..
            } => (signal_servers, phone_number, uuid),
        };

        let credentials = self.credentials()?;
        let service_configuration: ServiceConfiguration =
            (*signal_servers).into();
        let certificate_validator =
            service_configuration.credentials_validator(&self.context)?;

        let local_addr = ServiceAddress {
            uuid: Some(uuid.clone()),
            e164: Some(phone_number.clone()),
            relay: None,
        };

        let mut service_cipher = ServiceCipher::from_context(
            self.context.clone(),
            self.store_context.clone(),
            local_addr,
            certificate_validator,
        );

        let push_service = AwcPushService::new(
            service_configuration,
            credentials.clone(),
            USER_AGENT,
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
                    let Content { body, metadata } = match service_cipher
                        .open_envelope(envelope)
                    {
                        Ok(Some(content)) => content,
                        Ok(None) => {
                            warn!("Empty envelope...");
                            continue;
                        }
                        Err(e) => {
                            error!("Error opening envelope: {}, message will be skipped!", e);
                            continue;
                        }
                    };

                    tx.send((metadata, body)).await.expect("tx channel error");
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
        recipient_phone_numbers: Vec<String>,
        data_message: impl Into<ContentBody>,
    ) -> Result<(), Error> {
        let (signal_servers, phone_number, uuid, device_id) = match &self.state
        {
            State::New | State::Registration { .. } => {
                return Err(Error::NotYetRegisteredError)
            }
            State::Registered {
                signal_servers,
                phone_number,
                uuid,
                device_id,
                ..
            } => (signal_servers, phone_number, uuid, device_id),
        };

        let credentials = self.credentials()?;
        let service_configuration: ServiceConfiguration =
            (*signal_servers).into();

        let certificate_validator =
            service_configuration.credentials_validator(&self.context)?;
        let push_service = AwcPushService::new(
            service_configuration,
            credentials.clone(),
            USER_AGENT,
        );

        let local_addr = ServiceAddress {
            uuid: Some(uuid.clone()),
            e164: Some(phone_number.clone()),
            relay: None,
        };

        let service_cipher = ServiceCipher::from_context(
            self.context.clone(),
            self.store_context.clone(),
            local_addr,
            certificate_validator,
        );

        let mut sender = MessageSender::new(
            push_service,
            service_cipher,
            device_id.unwrap_or(DEFAULT_DEVICE_ID),
        );

        let recipient_addr = ServiceAddress {
            uuid: None,
            e164: Some(recipient_phone_number.clone()),
            relay: None,
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        let data_message = ContentBody::DataMessage(DataMessage {
            body: Some(message),
            timestamp: Some(timestamp),
            ..Default::default()
        });

        let reaction_data_message = ContentBody::DataMessage(DataMessage {
            reaction: Some(Reaction {
                emoji: Some("🚀".to_string()),
                remove: Some(false),
                target_author_uuid: Some(uuid.clone()),
                target_sent_timestamp: Some(timestamp),
            }),
            ..Default::default()
        });

        sender
            .send_message(&recipient_addr, None, data_message, timestamp, true)
            .await?;

        sender
            .send_message(
                &recipient_addr,
                None,
                reaction_data_message,
                timestamp,
                true,
            )
            .await?;
        Ok(())
    }

    pub fn clear_sessions(
        &self,
        recipient: &ServiceAddress,
    ) -> Result<(), Error> {
        self.config_store
            .delete_all_sessions(&recipient.identifier().as_bytes())?;
        Ok(())
    }
}
