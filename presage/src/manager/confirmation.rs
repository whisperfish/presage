use libsignal_service::configuration::{ServiceConfiguration, SignalServers};
use libsignal_service::messagepipe::ServiceCredentials;
use libsignal_service::prelude::phonenumber::PhoneNumber;
use libsignal_service::protocol::IdentityKeyPair;
use libsignal_service::provisioning::generate_registration_id;
use libsignal_service::push_service::{
    AccountAttributes, DeviceActivationRequest, DeviceCapabilities, PushService,
    RegistrationMethod, ServiceIds,
};
use libsignal_service::zkgroup::profiles::ProfileKey;
use libsignal_service_hyper::push_service::HyperPushService;
use log::trace;
use rand::rngs::StdRng;
use rand::{RngCore, SeedableRng};

use crate::manager::registered::RegistrationData;
use crate::store::Store;
use crate::{Error, Manager};

use super::Registered;

/// Manager state after a successful registration of new main device
///
/// In this state, the user has to confirm the new registration via a validation code.
pub struct Confirmation {
    pub(crate) signal_servers: SignalServers,
    pub(crate) phone_number: PhoneNumber,
    pub(crate) password: String,
    pub(crate) session_id: String,
}

impl<S: Store> Manager<S, Confirmation> {
    /// Confirm a newly registered account using the code you
    /// received by SMS or phone call.
    ///
    /// Returns a [registered manager](Manager::load_registered) that you can use
    /// to send and receive messages.
    pub async fn confirm_verification_code(
        mut self,
        confirmation_code: impl AsRef<str>,
    ) -> Result<Manager<S, Registered>, Error<S::Error>> {
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
            aci: None,
            pni: None,
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

        let aci_identity_key_pair = IdentityKeyPair::generate(&mut rng);
        let pni_identity_key_pair = IdentityKeyPair::generate(&mut rng);

        let (_aci_pre_keys, aci_signed_pre_key, _aci_pq_pre_keys, aci_pq_last_resort_pre_key) =
            libsignal_service::pre_keys::replenish_pre_keys(
                &mut self.store,
                &aci_identity_key_pair,
                &mut rng,
                true,
                0,
                0,
            )
            .await?;

        let aci_pq_last_resort_pre_key =
            aci_pq_last_resort_pre_key.expect("requested last resort key");
        assert!(_aci_pre_keys.is_empty());
        assert!(_aci_pq_pre_keys.is_empty());

        let (_pni_pre_keys, pni_signed_pre_key, _pni_pq_pre_keys, pni_pq_last_resort_pre_key) =
            libsignal_service::pre_keys::replenish_pre_keys(
                &mut self.store,
                &pni_identity_key_pair,
                &mut rng,
                true,
                0,
                0,
            )
            .await?;

        let pni_pq_last_resort_pre_key =
            pni_pq_last_resort_pre_key.expect("requested last resort key");
        assert!(_pni_pre_keys.is_empty());
        assert!(_pni_pq_pre_keys.is_empty());

        let skip_device_transfer = false;

        let device_activation_request = DeviceActivationRequest {
            aci_signed_pre_key: aci_signed_pre_key.try_into()?,
            pni_signed_pre_key: pni_signed_pre_key.try_into()?,
            aci_pq_last_resort_pre_key: aci_pq_last_resort_pre_key.try_into()?,
            pni_pq_last_resort_pre_key: pni_pq_last_resort_pre_key.try_into()?,
        };

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
                        pni: true,
                        sender_key: true,
                        ..Default::default()
                    },
                },
                skip_device_transfer,
                aci_identity_key_pair.identity_key(),
                pni_identity_key_pair.identity_key(),
                device_activation_request,
            )
            .await?;

        trace!("confirmed! (and registered)");

        let mut manager = Manager {
            rng,
            store: self.store,
            state: Registered::with_data(RegistrationData {
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
                aci_private_key: *aci_identity_key_pair.private_key(),
                aci_identity_key: *aci_identity_key_pair.identity_key(),
                pni_private_key: Some(*pni_identity_key_pair.private_key()),
                pni_identity_key: Some(*pni_identity_key_pair.identity_key()),
                profile_key,
            }),
        };

        manager.store.save_registration_data(&manager.state.data)?;

        if let Err(e) = manager.register_pre_keys().await {
            // clear the entire store on any error, there's no possible recovery here
            manager.store.clear_registration()?;
            Err(e)
        } else {
            Ok(manager)
        }
    }
}
