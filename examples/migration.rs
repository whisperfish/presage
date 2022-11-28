use std::path::{PathBuf, Path};

use clap::Parser;
use libsignal_service::{
    prelude::{
        protocol::{PrivateKey, PublicKey},
        SignalingKey,
    },
    push_service::ProfileKey,
    utils::{serde_private_key, serde_public_key, serde_signaling_key},
};
use presage::{
    prelude::{PhoneNumber, SignalServers, Uuid}, Manager, SledStore,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize)]
pub enum OldState {
    New,
    Registration {
        signal_servers: SignalServers,
        phone_number: PhoneNumber,
        use_voice_call: bool,
    },
    Linking {
        signal_servers: SignalServers,
        #[serde(with = "serde_signaling_key")]
        signaling_key: SignalingKey,
        password: String,
    },
    Confirmation {
        signal_servers: SignalServers,
        phone_number: PhoneNumber,
        password: String,
    },
    Registered {
        signal_servers: SignalServers,
        device_name: Option<String>,
        phone_number: PhoneNumber,
        uuid: Uuid,
        password: String,
        #[serde(with = "serde_signaling_key")]
        signaling_key: SignalingKey,
        device_id: Option<u32>,
        registration_id: u32,
        #[serde(with = "serde_private_key")]
        private_key: PrivateKey,
        #[serde(with = "serde_public_key")]
        public_key: PublicKey,
        profile_key: ProfileKey,
    },
}

#[derive(Serialize)]
pub struct NewState {
    pub signal_servers: SignalServers,
    pub device_name: Option<String>,
    pub phone_number: PhoneNumber,
    pub uuid: Uuid,
    password: String,
    #[serde(with = "serde_signaling_key")]
    signaling_key: SignalingKey,
    pub device_id: Option<u32>,
    pub(crate) registration_id: u32,
    #[serde(with = "serde_private_key")]
    pub(crate) private_key: PrivateKey,
    #[serde(with = "serde_public_key")]
    pub(crate) public_key: PublicKey,
    profile_key: ProfileKey,
}

impl Into<NewState> for OldState {
    fn into(self) -> NewState {
        match self {
            OldState::Registered {
                signal_servers,
                device_name,
                phone_number,
                uuid,
                password,
                signaling_key,
                device_id,
                registration_id,
                private_key,
                public_key,
                profile_key,
            } => NewState {
                signal_servers,
                device_name,
                phone_number,
                uuid,
                password,
                signaling_key,
                device_id,
                registration_id,
                private_key,
                public_key,
                profile_key,
            },
            _ => unimplemented!("this only supports trying to migrate registered clients"),
        }
    }
}

#[derive(Parser)]
#[clap(about = "a basic signal CLI to try things out")]
struct Args {
    #[clap(long = "db-path", short = 'd')]
    db_path: PathBuf,
}

fn convert(db_path: &Path) -> anyhow::Result<()> {
    let db = sled::open(db_path)?;

    let data = db.get("state")?.unwrap();
    let old_state: OldState = serde_json::from_slice(&data)?;
    let new_state: NewState = old_state.into();

    db.insert("registration", serde_json::to_vec(&new_state)?)?;

    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    convert(&args.db_path)?;

    let config_store = SledStore::open(&args.db_path, presage::MigrationConflictStrategy::Raise)?;
    let mut manager = Manager::load_registered(config_store)?;

    manager.register_pre_keys().await?;
    manager.set_account_attributes().await?;
    manager.request_contacts_sync().await?;

    Ok(())
}
