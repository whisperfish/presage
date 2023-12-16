use std::time::SystemTime;

use futures::channel::{mpsc, oneshot};
use futures::{future, StreamExt};
use libsignal_service::configuration::{Endpoint, ServiceConfiguration, SignalServers};
use libsignal_service::encrypt_device_name_base64;
use libsignal_service::pre_keys::{KyberPreKeyEntity, SignedPreKey};
use libsignal_service::prelude::Uuid;
use libsignal_service::protocol::{
    kem, GenericSignedPreKey, KeyPair, KyberPreKeyRecord, ServiceIdKind, SignedPreKeyRecord,
};
use libsignal_service::provisioning::{LinkingManager, SecondaryDeviceProvisioning};
use libsignal_service::push_service::{HttpAuth, HttpAuthOverride, PushService};
use libsignal_service::zkgroup::profiles::ProfileKey;
use libsignal_service_hyper::push_service::HyperPushService;
use log::info;
use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::manager::registered::RegistrationData;
use crate::store::Store;
use crate::{Error, Manager};

use super::Registered;

/// Manager state where it is possible to link a new secondary device
pub struct Linking;

impl<S: Store> Manager<S, Linking> {
    /// Links this client as a secondary device from the device used to register the account (usually a phone).
    /// The URL to present to the user will be sent in the channel given as the argument.
    ///
    /// ```no_run
    /// use futures::{channel::oneshot, future, StreamExt};
    /// use presage::libsignal_service::configuration::SignalServers;
    /// use presage::Manager;
    /// use presage_store_sled::{MigrationConflictStrategy, OnNewIdentity, SledStore};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let store =
    ///         SledStore::open("/tmp/presage-example", MigrationConflictStrategy::Drop, OnNewIdentity::Trust)?;
    ///
    ///     let (mut tx, mut rx) = oneshot::channel();
    ///     let (manager, err) = future::join(
    ///         Manager::link_secondary_device(
    ///             store,
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
        mut store: S,
        signal_servers: SignalServers,
        device_name: String,
        provisioning_link_channel: oneshot::Sender<Url>,
    ) -> Result<Manager<S, Registered>, Error<S::Error>> {
        // clear the database: the moment we start the process, old API credentials are invalidated
        // and you won't be able to use this client anyways
        store.clear_registration()?;

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
            LinkingManager::new(push_service.clone(), password.clone());

        let (tx, mut rx) = mpsc::channel(1);

        let (wait_for_qrcode_scan, registration_data) = future::join(
            linking_manager.provision_secondary_device(
                &mut rng,
                device_name.clone(),
                signaling_key,
                tx,
            ),
            async move {
                if let Some(SecondaryDeviceProvisioning::Url(url)) = rx.next().await {
                    info!("generating qrcode from provisioning link: {}", &url);
                    if provisioning_link_channel.send(url).is_err() {
                        return Err(Error::LinkError);
                    }
                } else {
                    return Err(Error::LinkError);
                }
                rx.next().await.ok_or(Error::NoProvisioningMessageReceived)
            },
        )
        .await;

        wait_for_qrcode_scan?;

        let registration_data = registration_data?;

        let mut manager = Manager {
            store,
            state: Linking,
            rng,
        };

        let data = match manager
            .link_device(
                registration_data,
                push_service,
                signal_servers,
                signaling_key,
                device_name,
                password,
            )
            .await
        {
            Ok(data) => {
                info!("successfully registered device {}", &data.service_ids);
                manager.store.save_registration_data(&data)?;
                data
            }
            Err(e) => {
                // clear the entire store on any error, there's no possible recovery here
                manager.store.clear_registration()?;
                return Err(e);
            }
        };

        Ok(Manager {
            rng: manager.rng,
            store: manager.store,
            state: Registered::with_data(data),
        })
    }

    async fn link_device(
        &mut self,
        data: SecondaryDeviceProvisioning,
        mut push_service: impl PushService + Clone,
        signal_servers: SignalServers,
        signaling_key: [u8; 52],
        device_name: String,
        password: String,
    ) -> Result<RegistrationData, Error<S::Error>> {
        let SecondaryDeviceProvisioning::NewDeviceRegistration {
            phone_number,
            provisioning_code,
            registration_id,
            pni_registration_id,
            mut service_ids,
            aci_private_key,
            aci_public_key,
            pni_private_key,
            pni_public_key,
            profile_key,
        } = data
        else {
            return Err(Error::LinkError); // logic error
        };

        let aci_key_pair = KeyPair::new(aci_public_key, aci_private_key);
        let pni_key_pair = KeyPair::new(pni_public_key, pni_private_key);

        let aci_pq_last_resort_pre_key = self
            .generate_last_resort_kyber_key(ServiceIdKind::Aci, &aci_key_pair)
            .await;
        let pni_pq_last_resort_pre_key = self
            .generate_last_resort_kyber_key(ServiceIdKind::Pni, &pni_key_pair)
            .await;
        let aci_signed_pre_key = self
            .generate_signed_pre_key(ServiceIdKind::Aci, &aci_key_pair)
            .await;
        let pni_signed_pre_key = self
            .generate_signed_pre_key(ServiceIdKind::Pni, &pni_key_pair)
            .await;

        #[derive(Debug, Serialize)]
        #[serde(rename_all = "camelCase")]
        struct LinkRequest {
            verification_code: String,
            account_attributes: AccountAttributes,
            aci_signed_pre_key: SignedPreKey,
            pni_signed_pre_key: SignedPreKey,
            aci_pq_last_resort_pre_key: KyberPreKeyEntity,
            pni_pq_last_resort_pre_key: KyberPreKeyEntity,
        }

        #[derive(Debug, Serialize)]
        #[serde(rename_all = "camelCase")]
        struct AccountAttributes {
            fetches_messages: bool,
            name: String,
            registration_id: u32,
            pni_registration_id: u32,
            capabilities: Capabilities,
        }

        #[derive(Debug, Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Capabilities {
            pni: bool,
        }

        let encrypted_device_name =
            encrypt_device_name_base64(&mut self.rng, &device_name, &aci_public_key).unwrap();
        let profile_key = ProfileKey::create(profile_key.as_slice().try_into().unwrap());
        let request = LinkRequest {
            verification_code: provisioning_code,
            account_attributes: AccountAttributes {
                registration_id,
                pni_registration_id,
                fetches_messages: true,
                capabilities: Capabilities { pni: true },
                name: encrypted_device_name,
            },
            aci_signed_pre_key: aci_signed_pre_key.try_into().unwrap(),
            pni_signed_pre_key: pni_signed_pre_key.try_into().unwrap(),
            aci_pq_last_resort_pre_key: aci_pq_last_resort_pre_key.try_into().unwrap(),
            pni_pq_last_resort_pre_key: pni_pq_last_resort_pre_key.try_into().unwrap(),
        };

        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct LinkResponse {
            uuid: Uuid,
            pni: Uuid,
            device_id: u32,
        }

        let LinkResponse {
            uuid,
            pni,
            device_id,
        } = dbg!(
            push_service
                .put_json(
                    Endpoint::Service,
                    "v1/devices/link",
                    &[],
                    HttpAuthOverride::Identified(HttpAuth {
                        username: phone_number.to_string(),
                        password: password.clone(),
                    }),
                    &request,
                )
                .await?
        );

        service_ids.aci = uuid;
        service_ids.pni = pni;

        Ok(RegistrationData {
            signal_servers,
            device_name: Some(device_name),
            phone_number,
            service_ids,
            password,
            signaling_key,
            device_id: Some(device_id),
            registration_id,
            pni_registration_id: Some(pni_registration_id),
            aci_private_key,
            aci_public_key,
            pni_private_key: Some(pni_private_key),
            pni_public_key: Some(pni_public_key),
            profile_key,
        })
    }

    async fn generate_last_resort_kyber_key(
        &mut self,
        _service_id_kind: ServiceIdKind,
        identity_key: &KeyPair,
    ) -> KyberPreKeyRecord {
        let id = self.store.next_pq_pre_key_id().unwrap();
        let id = id.max(1); // TODO: Hack, keys start with 1

        let record = KyberPreKeyRecord::generate(
            kem::KeyType::Kyber1024,
            id.into(),
            &identity_key.private_key,
        )
        .unwrap();

        self.store
            .save_kyber_pre_key(id.into(), &record)
            .await
            .unwrap();
        self.store.set_next_pq_pre_key_id(id + 1).unwrap();

        record
    }

    async fn generate_signed_pre_key(
        &mut self,
        _service_id_kind: ServiceIdKind,
        identity_key: &KeyPair,
    ) -> SignedPreKeyRecord {
        let id = self.store.next_signed_pre_key_id().unwrap();
        let id = id.max(1); // TODO: Hack, keys start with 1

        let key_pair = KeyPair::generate(&mut self.rng);
        let signature = identity_key
            .private_key
            .calculate_signature(&key_pair.public_key.serialize(), &mut self.rng)
            .unwrap();

        let unix_time = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let record = SignedPreKeyRecord::new(id.into(), unix_time, &key_pair, &signature);

        self.store
            .save_signed_pre_key(id.into(), &record)
            .await
            .unwrap();
        self.store.set_next_signed_pre_key_id(id + 1).unwrap();

        record
    }
}
