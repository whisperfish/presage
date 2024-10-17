use libsignal_service::configuration::{ServiceConfiguration, SignalServers};
use libsignal_service::messagepipe::ServiceCredentials;
use libsignal_service::prelude::phonenumber::PhoneNumber;
use libsignal_service::protocol::IdentityKeyPair;
use libsignal_service::provisioning::generate_registration_id;
use libsignal_service::push_service::{
    AccountAttributes, DeviceCapabilities, PushService, RegistrationMethod, ServiceIds,
    VerifyAccountResponse,
};
use libsignal_service::zkgroup::profiles::ProfileKey;
use libsignal_service::AccountManager;
use libsignal_service_hyper::push_service::HyperPushService;
use rand::RngCore;
use tracing::trace;

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

        let registration_id = generate_registration_id(&mut self.rng);
        let pni_registration_id = generate_registration_id(&mut self.rng);

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
        let mut identified_push_service = HyperPushService::new(
            service_configuration,
            Some(credentials),
            crate::USER_AGENT.to_string(),
        );

        let session = identified_push_service
            .submit_verification_code(&session_id, confirmation_code.as_ref())
            .await?;

        trace!("verification code submitted");

        if !session.verified {
            return Err(Error::UnverifiedRegistrationSession);
        }

        // generate a 52 bytes signaling key
        let mut signaling_key = [0u8; 52];
        self.rng.fill_bytes(&mut signaling_key);

        // generate a 32 bytes profile key
        let mut profile_key = [0u8; 32];
        self.rng.fill_bytes(&mut profile_key);
        let profile_key = ProfileKey::generate(profile_key);

        // generate new identity keys used in `register_account` and below
        self.store
            .set_aci_identity_key_pair(IdentityKeyPair::generate(&mut self.rng))?;
        self.store
            .set_pni_identity_key_pair(IdentityKeyPair::generate(&mut self.rng))?;

        let skip_device_transfer = true;
        let mut account_manager = AccountManager::new(identified_push_service, Some(profile_key));

        let VerifyAccountResponse {
            aci,
            pni,
            storage_capable: _,
            number: _,
        } = account_manager
            .register_account(
                &mut self.rng,
                RegistrationMethod::SessionId(&session.id),
                AccountAttributes {
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
                    name: None,
                    capabilities: DeviceCapabilities::default(),
                },
                &mut self.store.aci_protocol_store(),
                &mut self.store.pni_protocol_store(),
                skip_device_transfer,
            )
            .await?;

        trace!("confirmed! (and registered)");

        let mut manager = Manager {
            rng: self.rng,
            store: self.store,
            state: Registered::with_data(RegistrationData {
                signal_servers: self.state.signal_servers,
                device_name: None,
                phone_number,
                service_ids: ServiceIds { aci, pni },
                password,
                signaling_key,
                device_id: None,
                registration_id,
                pni_registration_id: Some(pni_registration_id),
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
