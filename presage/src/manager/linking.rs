use futures::channel::{mpsc, oneshot};
use futures::{future, StreamExt};
use libsignal_service::configuration::{ServiceConfiguration, SignalServers};
use libsignal_service::protocol::IdentityKeyPair;
use libsignal_service::provisioning::{
    link_device, NewDeviceRegistration, SecondaryDeviceProvisioning,
};
use libsignal_service_hyper::push_service::HyperPushService;
use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};
use tracing::info;
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

        let (tx, mut rx) = mpsc::channel(1);

        let (wait_for_qrcode_scan, registration_data) = future::join(
            link_device(
                &mut store.aci_protocol_store(),
                &mut store.pni_protocol_store(),
                &mut rng,
                push_service,
                &password,
                &device_name,
                tx,
            ),
            async move {
                if let Some(SecondaryDeviceProvisioning::Url(url)) = rx.next().await {
                    info!("generating qrcode from provisioning link: {}", &url);
                    if provisioning_link_channel.send(url).is_err() {
                        return Err(Error::LinkingError);
                    }
                } else {
                    return Err(Error::LinkingError);
                }
                if let Some(SecondaryDeviceProvisioning::NewDeviceRegistration(data)) =
                    rx.next().await
                {
                    Ok(data)
                } else {
                    Err(Error::NoProvisioningMessageReceived)
                }
            },
        )
        .await;

        wait_for_qrcode_scan?;

        match registration_data {
            Ok(NewDeviceRegistration {
                phone_number,
                device_id,
                registration_id,
                pni_registration_id,
                service_ids,
                aci_private_key,
                aci_public_key,
                pni_private_key,
                pni_public_key,
                profile_key,
            }) => {
                let registration_data = RegistrationData {
                    signal_servers,
                    device_name: Some(device_name),
                    phone_number,
                    service_ids,
                    password,
                    signaling_key,
                    device_id: Some(device_id.into()),
                    registration_id,
                    pni_registration_id: Some(pni_registration_id),
                    profile_key,
                };

                store.set_aci_identity_key_pair(IdentityKeyPair::new(
                    aci_public_key,
                    aci_private_key,
                ))?;
                store.set_pni_identity_key_pair(IdentityKeyPair::new(
                    pni_public_key,
                    pni_private_key,
                ))?;

                store.save_registration_data(&registration_data)?;
                info!(
                    "successfully registered device {}",
                    &registration_data.service_ids
                );

                let mut manager = Manager {
                    rng,
                    store: store.clone(),
                    state: Registered::with_data(registration_data),
                };

                // Register pre-keys with the server. If this fails, this can lead to issues
                // receiving, in that case clear the registration and propagate the error.
                if let Err(e) = manager.register_pre_keys().await {
                    store.clear_registration()?;
                    Err(e)
                } else {
                    Ok(manager)
                }
            }
            Err(e) => {
                store.clear_registration()?;
                Err(e)
            }
        }
    }
}
