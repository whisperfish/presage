use std::time::{SystemTime, UNIX_EPOCH};

use futures::{
    channel::mpsc::{channel, Sender},
    future, pin_mut, SinkExt, StreamExt,
};
use image::Luma;
use libsignal_protocol::{
    keys::{IdentityKeyPair, PrivateKey, PublicKey},
    stores::IdentityKeyStore,
    stores::PreKeyStore,
    stores::SessionStore,
    stores::SignedPreKeyStore,
    Context, Serializable,
};
use libsignal_service::{
    cipher::ServiceCipher,
    configuration::ServiceConfiguration,
    configuration::SignalingKey,
    content::Metadata,
    content::{ContentBody, DataMessage},
    messagepipe::Credentials,
    pre_keys::PreKeyEntity,
    pre_keys::PreKeyState,
    prelude::Content,
    prelude::{MessageSender, PushService},
    push_service::{ConfirmCodeMessage, ProfileKey, DEFAULT_DEVICE_ID},
    receiver::MessageReceiver,
    ServiceAddress, USER_AGENT,
};
use libsignal_service_actix::{
    provisioning::provision_secondary_device, provisioning::SecondaryDeviceProvisioning,
    push_service::AwcPushService,
};
use log::{error, trace, warn};
use qrcode::QrCode;
use rand::{distributions::Alphanumeric, Rng, RngCore};

use crate::{config::ConfigStore, Error};

#[derive(Clone)]
pub struct Manager<
    C: Clone
        + ConfigStore
        + PreKeyStore
        + SignedPreKeyStore
        + SessionStore
        + IdentityKeyStore
        + 'static,
> {
    config_store: C,
    state: State,
}

#[derive(Debug, Clone)]
pub enum State {
    Registration {
        phone_number: String,
        password: String,
    },
    Registered {
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
        + 'static,
{
    pub fn with_config_store(config_store: C, context: &Context) -> Result<Self, Error> {
        let state = config_store.state(context)?;
        Ok(Manager {
            config_store,
            state,
        })
    }

    fn save(&self) -> Result<(), Error> {
        trace!("saving configuration");
        self.config_store.save(&self.state)
    }

    fn identity_key_pair(&self) -> Result<IdentityKeyPair, Error> {
        let (public_key, private_key) = match &self.state {
            State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered {
                public_key,
                private_key,
                ..
            } => (public_key, private_key),
        };
        Ok(IdentityKeyPair::new(public_key, private_key)?)
    }

    fn credentials(&self) -> Result<Option<Credentials>, Error> {
        match &self.state {
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
        config_store: C,
        service_configuration: ServiceConfiguration,
        phone_number: String,
        use_voice_call: bool,
    ) -> Result<Manager<C>, Error> {
        // generate a random 24 bytes password
        let rng = rand::rngs::OsRng::default();
        let password: String = rng.sample_iter(&Alphanumeric).take(24).collect();

        let mut push_service = AwcPushService::new(
            service_configuration.clone(),
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

        let manager = Manager {
            config_store,
            state: State::Registration {
                phone_number,
                password,
            },
        };

        manager.save()?;
        Ok(manager)
    }

    pub async fn confirm_verification_code(
        &mut self,
        ctx: &Context,
        service_configuration: &ServiceConfiguration,
        confirm_code: u32,
    ) -> Result<(), Error> {
        trace!("confirming verification code");
        let (phone_number, password) = match &self.state {
            State::Registration {
                phone_number,
                password,
            } => (phone_number, password),
            _ => return Err(Error::AlreadyRegisteredError),
        };

        let registration_id = libsignal_protocol::generate_registration_id(&ctx, 0)?;
        trace!("registration_id: {}", registration_id);

        let mut push_service = AwcPushService::new(
            service_configuration.clone(),
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
                    profile_key.derive_access_key().unwrap(),
                ),
            )
            .await?;

        let identity_key_pair = libsignal_protocol::generate_identity_key_pair(ctx)?;

        self.state = State::Registered {
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
        Ok(())
    }

    pub async fn link_secondary_device(
        ctx: &Context,
        config_store: C,
        service_configuration: &ServiceConfiguration,
        device_name: String,
    ) -> Result<Manager<C>, Error> {
        // generate a random 24 bytes password
        let mut rng = rand::rngs::OsRng::default();
        let password: String = rng.sample_iter(&Alphanumeric).take(24).collect();

        // generate a 52 bytes signaling key
        let mut signaling_key = [0u8; 52];
        rng.fill_bytes(&mut signaling_key);

        let (tx, mut rx) = channel(1);

        let (fut1, fut2) = future::join(
            provision_secondary_device(
                &ctx,
                service_configuration,
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
        let (phone_number, device_id, registration_id, uuid, private_key, public_key, profile_key) =
            fut2?;

        let manager = Manager {
            config_store,
            state: State::Registered {
                phone_number,
                uuid,
                signaling_key,
                password,
                device_id: Some(device_id),
                registration_id,
                public_key,
                private_key,
                profile_key,
            },
        };

        manager.save()?;
        Ok(manager)
    }

    pub async fn register_pre_keys(
        &self,
        context: &Context,
        service_configuration: &ServiceConfiguration,
    ) -> Result<(), Error> {
        let public_key = match &self.state {
            State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered { public_key, .. } => public_key,
        };

        let mut pre_keys_offset_id = self.config_store.pre_keys_offset_id()?;
        let mut next_signed_pre_key_id = self.config_store.next_signed_pre_key_id()?;

        const PRE_KEYS_COUNT: u32 = 100;

        let pre_keys =
            libsignal_protocol::generate_pre_keys(&context, pre_keys_offset_id, PRE_KEYS_COUNT)?;
        let identity_key_pair = self.identity_key_pair()?;
        let signed_pre_key = libsignal_protocol::generate_signed_pre_key(
            &context,
            &identity_key_pair,
            next_signed_pre_key_id,
            SystemTime::now(),
        )?;
        SignedPreKeyStore::store(
            &self.config_store,
            next_signed_pre_key_id,
            signed_pre_key.serialize()?.as_slice(),
        )?;
        next_signed_pre_key_id += 1;

        let mut push_service = AwcPushService::new(
            service_configuration.clone(),
            self.credentials()?,
            USER_AGENT,
        );

        let mut pre_key_entities = vec![];
        for pre_key in pre_keys {
            PreKeyStore::store(
                &self.config_store,
                pre_keys_offset_id,
                pre_key.serialize()?.as_slice(),
            )?;
            pre_key_entities.push(PreKeyEntity::from(pre_key));
            pre_keys_offset_id += 1;
        }

        let pre_key_state = PreKeyState {
            pre_keys: pre_key_entities,
            signed_pre_key: signed_pre_key.into(),
            identity_key: public_key.clone(),
        };

        push_service.register_pre_keys(pre_key_state).await?;

        self.config_store
            .set_pre_keys_offset_id(pre_keys_offset_id)?;
        self.config_store
            .set_next_signed_pre_key_id(next_signed_pre_key_id)?;

        Ok(())
    }

    pub async fn receive_messages(
        &self,
        context: Context,
        service_configuration: &ServiceConfiguration,
        mut tx: Sender<(Metadata, ContentBody)>,
    ) -> Result<(), Error> {
        let (phone_number, uuid) = match &self.state {
            State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered {
                phone_number, uuid, ..
            } => (phone_number, uuid),
        };

        let credentials = self.credentials()?;

        let push_service = AwcPushService::new(
            service_configuration.clone(),
            credentials.clone(),
            USER_AGENT,
        );

        let store_context = libsignal_protocol::store_context(
            &context,
            // Storage is a pointer-to-shared-storage
            self.config_store.clone(),
            self.config_store.clone(),
            self.config_store.clone(),
            self.config_store.clone(),
        )
        .expect("initialized storage");

        let local_addr = ServiceAddress {
            uuid: Some(uuid.clone()),
            e164: phone_number.clone(),
            relay: None,
        };

        let mut service_cipher = ServiceCipher::from_context(context, local_addr, store_context);

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
        context: Context,
        service_configuration: &ServiceConfiguration,
        recipient_phone_number: String,
        message: String,
    ) -> Result<(), Error> {
        let (phone_number, uuid, device_id) = match &self.state {
            State::Registration { .. } => return Err(Error::NotYetRegisteredError),
            State::Registered {
                phone_number,
                uuid,
                device_id,
                ..
            } => (phone_number, uuid, device_id),
        };

        let credentials = self.credentials()?;

        let push_service = AwcPushService::new(
            service_configuration.clone(),
            credentials.clone(),
            USER_AGENT,
        );

        let store_context = libsignal_protocol::store_context(
            &context,
            // Storage is a pointer-to-shared-storage
            self.config_store.clone(),
            self.config_store.clone(),
            self.config_store.clone(),
            self.config_store.clone(),
        )
        .expect("initialized storage");

        let local_addr = ServiceAddress {
            uuid: Some(uuid.clone()),
            e164: phone_number.clone(),
            relay: None,
        };

        let service_cipher = ServiceCipher::from_context(context, local_addr, store_context);

        let mut sender = MessageSender::new(
            push_service,
            self.config_store.clone(),
            service_cipher,
            device_id.unwrap_or(DEFAULT_DEVICE_ID),
        );

        let recipient_addr = ServiceAddress {
            uuid: None,
            e164: recipient_phone_number.clone(),
            relay: None,
        };

        let timestamp = std::time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;

        let data_message = ContentBody::DataMessage(DataMessage {
            attachments: vec![],
            body: Some(message),
            body_ranges: vec![],
            contact: vec![],
            delete: None,
            expire_timer: None,
            flags: None,
            group: None,
            group_v2: None,
            is_view_once: None,
            preview: vec![],
            profile_key: None,
            quote: None,
            reaction: None,
            sticker: None,
            timestamp: Some(timestamp),
            required_protocol_version: None,
        });

        println!("Sending {:?}", data_message);
        sender
            .send_message(recipient_addr, data_message, timestamp, false)
            .await?;
        Ok(())
    }
}
