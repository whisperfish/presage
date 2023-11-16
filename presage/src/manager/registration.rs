use libsignal_service::configuration::{ServiceConfiguration, SignalServers};
use libsignal_service::prelude::phonenumber::PhoneNumber;
use libsignal_service::push_service::{PushService, VerificationTransport};
use libsignal_service_hyper::push_service::HyperPushService;
use log::trace;
use rand::distributions::{Alphanumeric, DistString};
use rand::rngs::StdRng;
use rand::SeedableRng;

use crate::store::Store;
use crate::{Error, Manager};

use super::Confirmation;

/// Options when registering a new main device
#[derive(Debug)]
pub struct RegistrationOptions<'a> {
    pub signal_servers: SignalServers,
    pub phone_number: PhoneNumber,
    pub use_voice_call: bool,
    pub captcha: Option<&'a str>,
    pub force: bool,
}

/// Manager state where it is possible to register a new main device
pub struct Registration;

impl<C: Store> Manager<C, Registration> {
    /// Registers a new account with a phone number (and some options).
    ///
    /// The returned value is a [confirmation manager](Manager::confirm_verification_code) which you then
    /// have to use to send the confirmation code.
    ///
    /// ```no_run
    /// use std::str::FromStr;
    ///
    /// use presage::libsignal_service::{
    ///     configuration::SignalServers, prelude::phonenumber::PhoneNumber,
    /// };
    /// use presage::manager::RegistrationOptions;
    /// use presage::Manager;
    /// use presage_store_sled::{MigrationConflictStrategy, SledStore};
    ///
    /// #[tokio::main]
    /// async fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///     let store =
    ///         SledStore::open("/tmp/presage-example", MigrationConflictStrategy::Drop)?;
    ///
    ///     let manager = Manager::register(
    ///         store,
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
        mut store: C,
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
        if !force && store.is_registered() {
            return Err(Error::AlreadyRegisteredError);
        }

        store.clear_registration()?;

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
            store,
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
