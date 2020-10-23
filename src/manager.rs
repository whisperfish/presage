use std::{
    ops::Deref,
    sync::{Arc, Mutex},
    time::Duration,
    time::SystemTime,
};

use futures::{SinkExt, StreamExt, channel::mpsc::{Sender, channel}, future, pin_mut};
use image::Luma;
use libsignal_protocol::{
    keys::{IdentityKeyPair, PrivateKey, PublicKey},
    stores::IdentityKeyStore,
    stores::PreKeyStore,
    stores::SessionStore,
    stores::SignedPreKeyStore,
    Address, Context, InternalError, Serializable,
};
use libsignal_service::{ServiceAddress, USER_AGENT, cipher::ServiceCipher, configuration::ServiceConfiguration, configuration::SignalingKey, content::ContentBody, messagepipe::Credentials, pre_keys::PreKeyEntity, pre_keys::PreKeyState, prelude::Content, content::Metadata, prelude::PushService, push_service::{ConfirmCodeMessage, ProfileKey}, receiver::MessageReceiver};
use libsignal_service_actix::{
    provisioning::provision_secondary_device, provisioning::SecondaryDeviceProvisioning,
    push_service::AwcPushService,
};
use log::trace;
use qrcode::QrCode;
use rand::{distributions::Alphanumeric, Rng, RngCore};

use crate::{config::ConfigStore, Error};

#[derive(Clone)]
pub struct Manager<C: Clone + ConfigStore + PreKeyStore + SignedPreKeyStore + SessionStore> {
    config_store: Arc<Mutex<C>>,
    state: State,
}

#[derive(Clone)]
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
        device_id: Option<u32>,
        private_key: PrivateKey,
        public_key: PublicKey,
        profile_key: Vec<u8>,
    },
}

impl<C> Manager<C>
where
    C: Clone + ConfigStore + PreKeyStore + SignedPreKeyStore + SessionStore + 'static,
{
    pub fn with_config_store(config_store: C, context: &Context) -> Result<Self, Error> {
        let state = config_store.state(context)?;
        Ok(Manager {
            config_store: Arc::new(Mutex::new(config_store)),
            state,
        })
    }

    fn save(&self) -> Result<(), Error> {
        self.config_store
            .lock()
            .expect("poisoned mutex")
            .save(&self.state)
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
                    format!("{}.{}", uuid, device_id)
                } else {
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
            config_store: Arc::new(Mutex::new(config_store)),
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
            private_key: identity_key_pair.private(),
            public_key: identity_key_pair.public(),
            profile_key: profile_key.0,
        };

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
                            uuid,
                            private_key,
                            public_key,
                            profile_key,
                        } => {
                            log::info!("successfully registered device {}", &uuid);
                            return Ok((
                                phone_number,
                                device_id.device_id,
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
        let (phone_number, device_id, uuid, private_key, public_key, profile_key) = fut2?;

        let manager = Manager {
            config_store: Arc::new(Mutex::new(config_store)),
            state: State::Registered {
                phone_number,
                uuid,
                signaling_key,
                password,
                device_id: Some(device_id),
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

        const PRE_KEYS_COUNT: u32 = 100;
        let pre_keys = libsignal_protocol::generate_pre_keys(&context, 0, PRE_KEYS_COUNT)?;
        let identity_key_pair = self.identity_key_pair()?;
        let signed_pre_key = libsignal_protocol::generate_signed_pre_key(
            &context,
            &identity_key_pair,
            0,
            SystemTime::now(),
        )?;

        let mut push_service = AwcPushService::new(
            service_configuration.clone(),
            self.credentials()?,
            USER_AGENT,
        );

        let config_store = self.config_store.lock().expect("poisoned mutex");
        let next_signed_pre_key_id = config_store.next_signed_pre_key_id()?;

        SignedPreKeyStore::store(
            &*config_store,
            next_signed_pre_key_id,
            signed_pre_key.serialize()?.as_slice(),
        )?;

        config_store.incr("next_signed_pre_key_id")?;
        let mut pre_key_entities = vec![];
        for pre_key in pre_keys {
            config_store.incr("pre_key_id_offset")?;
            PreKeyStore::store(
                &*config_store,
                pre_key.id(),
                pre_key.serialize()?.as_slice(),
            )?;
            pre_key_entities.push(PreKeyEntity::from(pre_key))
        }

        let pre_key_state = PreKeyState {
            pre_keys: pre_key_entities,
            signed_pre_key: signed_pre_key.into(),
            identity_key: public_key.clone(),
        };

        push_service.register_pre_keys(pre_key_state).await?;

        self.save()?;
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

        let config_store = self.config_store.lock().expect("poisoned mutex");

        let store_context = libsignal_protocol::store_context(
            &context,
            // Storage is a pointer-to-shared-storage
            config_store.deref().clone(),
            config_store.deref().clone(),
            config_store.deref().clone(),
            self.clone(),
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
            .create_message_pipe(credentials.ok_or(Error::MissingKeyError)?)
            .await
            .unwrap();
        let message_stream = pipe.stream();
        pin_mut!(message_stream);

        while let Some(step) = message_stream.next().await {
            match step {
                Ok(envelope) => {
                    let Content {
                        body,
                        metadata,
                    } = match service_cipher.open_envelope(envelope) {
                        Ok(Some(content)) => content,
                        Ok(None) => {
                            log::warn!("Empty envelope...");
                            continue;
                        }
                        Err(e) => {
                            log::error!("Error opening envelope: {:?}, message will be skipped!", e);
                            continue;
                        }
                    };

                    tx.send((metadata, body)).await.expect("tx channel error");
                }
                Err(e) => {
                    eprintln!("Error: {}", e);
                }
            }
        }

        Ok(())
    }

    pub fn identity_key_pair(&self) -> Result<IdentityKeyPair, Error> {
        todo!()
        // Ok(IdentityKeyPair::new(&self.public_key, &self.private_key)?)
    }

    fn identity_key(&self, addr: &Address) -> Option<String> {
        let addr_str = addr.as_str().unwrap();
        let recipient_id = if addr_str.starts_with('+') {
            // strip the prefix + from e164, as is done in Go (cfr. the `func recID`).
            &addr_str[1..]
        } else {
            return None;
            // addr_str
        };

        Some(format!("identity-remote-{}", recipient_id,))
    }
}

impl<C> IdentityKeyStore for Manager<C>
where
    C: Clone + ConfigStore + PreKeyStore + SignedPreKeyStore + SessionStore + 'static,
{
    fn identity_key_pair(
        &self,
    ) -> Result<(libsignal_protocol::Buffer, libsignal_protocol::Buffer), libsignal_protocol::Error>
    {
        match &self.state {
            State::Registered {
                public_key,
                private_key,
                ..
            } => Ok((public_key.serialize()?, private_key.serialize()?)),
            _ => Err(libsignal_protocol::Error::Unknown {
                reason: "no device registered yet!".to_string(),
            }),
        }
    }

    fn local_registration_id(&self) -> Result<u32, libsignal_protocol::Error> {
        match &self.state {
            State::Registered { device_id, .. } => {
                Ok(device_id.ok_or(libsignal_protocol::Error::Unknown {
                    reason: "device_id should be present after registration".to_string(),
                })?)
            }
            _ => Err(libsignal_protocol::Error::Unknown {
                reason: "no device registered yet!".to_string(),
            }),
        }
    }

    fn is_trusted_identity(
        &self,
        address: libsignal_protocol::Address,
        identity_key: &[u8],
    ) -> Result<bool, libsignal_protocol::Error> {
        if let Some(key) = self.identity_key(&address) {
            // check contents with key
            let contents = self
                .config_store
                .lock()
                .expect("poisoned mutex")
                .get(key)
                .map_err(|e| {
                    log::error!("failed to read identity for {:?}: {}", address, e);
                    InternalError::Unknown
                })?
                .expect("could not fetch identity");
            Ok(contents == identity_key)
        } else {
            log::warn!("Trying trusted identity with uuid, currently unsupported.");
            Err(InternalError::InvalidArgument.into())
        }
    }

    fn save_identity(
        &self,
        address: libsignal_protocol::Address,
        identity_key: &[u8],
    ) -> Result<(), libsignal_protocol::Error> {
        if let Some(key) = self.identity_key(&address) {
            self.config_store
                .lock()
                .expect("poisoned mutex")
                .insert(key, identity_key)
                .map_err(|e| {
                    log::error!("error saving identity for {:?}: {}", address, e);
                    InternalError::Unknown
                })?;
            Ok(())
        } else {
            log::warn!("Trying to save trusted identity with uuid, currently unsupported.");
            Err(InternalError::InvalidArgument.into())
        }
    }
}
