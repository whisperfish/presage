//! How presage names the client to Signal's servers: its user agent and the user's languages.

use std::sync::OnceLock;

use libsignal_service::configuration::{ServiceCredentials, SignalServers};
use libsignal_service::push_service::PushService;
use reqwest::header::HeaderValue;
use tracing::warn;

/// What every request and websocket of this process says about the client.
#[derive(Clone, Debug)]
pub struct ClientIdentity {
    /// `User-Agent`, `presage-rs-<version>` by default. Signal's apps say what they are and on
    /// what (`Signal-Android/8.32.1 Android/34`).
    pub user_agent: String,
    /// `Accept-Language`: the languages the user reads, as Signal's apps send them
    /// (`de-DE;q=1, de;q=0.75, en;q=0.5`), for the server's localized text. None by default.
    pub accept_language: Option<String>,
}

impl Default for ClientIdentity {
    fn default() -> Self {
        Self {
            user_agent: crate::USER_AGENT.to_owned(),
            accept_language: None,
        }
    }
}

static IDENTITY: OnceLock<ClientIdentity> = OnceLock::new();

/// Sets the [`ClientIdentity`] of every [`Manager`](crate::Manager) in this process. It is set
/// once, before the first manager talks to the servers; until then, or if it never is, it is
/// [`ClientIdentity::default`]. Gives `identity` back if one is set already.
pub fn set_client_identity(identity: ClientIdentity) -> Result<(), ClientIdentity> {
    IDENTITY.set(identity)
}

/// A push service that names the client as [`set_client_identity`] says: what a client's own
/// requests take, so they say what presage's do.
pub fn push_service(
    servers: SignalServers,
    credentials: Option<ServiceCredentials>,
) -> PushService {
    let identity = IDENTITY.get_or_init(ClientIdentity::default);
    let user_agent = &identity.user_agent;
    match identity
        .accept_language
        .as_deref()
        .map(HeaderValue::from_str)
    {
        Some(Ok(languages)) => {
            PushService::with_accept_language(servers, credentials, user_agent, languages)
        }
        Some(Err(error)) => {
            warn!(%error, "the Accept-Language isn't a header's value; left out");
            PushService::new(servers, credentials, user_agent)
        }
        None => PushService::new(servers, credentials, user_agent),
    }
}
