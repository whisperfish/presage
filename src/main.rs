use std::{path::PathBuf, time::UNIX_EPOCH};

use anyhow::bail;
use directories::ProjectDirs;
use futures::{channel::mpsc::channel, future, StreamExt};
use log::debug;
use presage::{config::SledConfigStore, prelude::sync_message::Sent, Error, Manager};

use structopt::StructOpt;

use libsignal_protocol::{crypto::DefaultCrypto, Context};
use libsignal_service::{
    configuration::SignalServers,
    content::{ContentBody, DataMessage, GroupContext, GroupContextV2, GroupType, SyncMessage},
    ServiceAddress,
};

#[derive(StructOpt)]
#[structopt(about = "a basic signal CLI to try things out")]
struct Args {
    #[structopt(long = "db-path", short = "d")]
    db_path: Option<PathBuf>,

    #[structopt(flatten)]
    subcommand: Subcommand,
}

#[derive(StructOpt)]
enum Subcommand {
    #[structopt(about = "register a primary device using a phone number")]
    Register {
        #[structopt(long = "servers", short = "s", default_value = "staging")]
        servers: SignalServers,
        #[structopt(long, help = "Phone Number to register with in E.164 format")]
        phone_number: String,
        #[structopt(long)]
        use_voice_call: bool,
    },
    #[structopt(
        about = "generate a QR code to scan with Signal for iOS or Android to provision a secondary device on the same phone number"
    )]
    LinkDevice {
        #[structopt(long, short = "s", default_value = "staging")]
        servers: SignalServers,
        #[structopt(
            long,
            short = "n",
            help = "Name of the device to register in the primary client"
        )]
        device_name: String,
    },
    #[structopt(about = "verify the code you got from the SMS or voice-call when you registered")]
    Verify {
        #[structopt(long, short = "c", help = "SMS / Voice-call confirmation code")]
        confirmation_code: u32,
    },
    #[structopt(about = "receives all pending messages and saves them to disk")]
    Receive,
    #[structopt(about = "sends a message")]
    Send {
        #[structopt(long, short = "n", help = "Phone number of the recipient")]
        phone_number: String,
        #[structopt(long, short = "m", help = "Contents of the message to send")]
        message: String,
    },
    #[structopt(about = "sends a message to group")]
    SendToGroup {
        #[structopt(
            long,
            short = "n",
            min_values = 1,
            required = true,
            help = "Phone number of the recipient"
        )]
        phone_number: Vec<String>,
        #[structopt(long, short = "m", help = "Contents of the message to send")]
        message: String,
        #[structopt(long, short = "g", help = "ID of the legacy group (hex string)")]
        group_id: Option<String>,
        #[structopt(long, short = "k", help = "Master Key of the V2 group (hex string)")]
        master_key: Option<String>,
    },
    Config {
        #[structopt(flatten)]
        command: ConfigSubcommand,
    },
}

#[derive(StructOpt)]
enum ConfigSubcommand {
    Print,
    ClearSessions {
        #[structopt(long = "recipient")]
        recipient: String,
    },
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", format!("{}=debug", env!("CARGO_PKG_NAME")));
    }
    env_logger::builder().init();

    let args = Args::from_args();

    let db_path = match args.db_path {
        Some(path) => path,
        None => {
            let dir: PathBuf = ProjectDirs::from("org", "libsignal-service-rs", "signal-bot-rs")
                .unwrap()
                .config_dir()
                .into();
            std::fs::create_dir_all(&dir)?;
            dir
        }
    };

    debug!("opening config database from {}", db_path.display());
    let config_store = SledConfigStore::new(db_path)?;
    let signal_context = Context::new(DefaultCrypto::default())?;

    let mut manager = Manager::with_config_store(config_store, signal_context)?;

    match args.subcommand {
        Subcommand::Config { command } => match command {
            ConfigSubcommand::Print => println!("{:?}", manager.config_store.keys()),
            ConfigSubcommand::ClearSessions { recipient } => {
                let address = ServiceAddress {
                    uuid: None,
                    e164: Some(recipient),
                    relay: None,
                };
                manager.clear_sessions(&address)?;
            }
        },
        Subcommand::Register {
            servers,
            phone_number,
            use_voice_call,
        } => {
            manager
                .register(servers, phone_number, use_voice_call)
                .await?;
        }
        Subcommand::LinkDevice {
            servers,
            device_name,
        } => {
            manager
                .link_secondary_device(servers, device_name.clone())
                .await?;
        }
        Subcommand::Verify { confirmation_code } => {
            manager.confirm_verification_code(confirmation_code).await?;
        }
        Subcommand::Receive => {
            let (tx, mut rx) = channel(1);

            let (receiver, printer) = future::join(manager.receive_messages(tx), async move {
                while let Some((metadata, body)) = rx.next().await {
                    match body {
                        ContentBody::DataMessage(message)
                        | ContentBody::SynchronizeMessage(SyncMessage {
                            sent:
                                Some(Sent {
                                    message: Some(message),
                                    ..
                                }),
                            ..
                        }) => {
                            if let Some(quote) = &message.quote {
                                println!(
                                    "Quote from {:?}: > {:?} / {}",
                                    metadata.sender,
                                    quote,
                                    message.body().to_string(),
                                );
                            } else if let Some(reaction) = message.reaction {
                                println!(
                                    "Reaction to message sent at {:?}: {:?}",
                                    reaction.target_sent_timestamp, reaction.emoji,
                                )
                            } else if let Some(body) = message.body {
                                println!("Message from {:?}: {}", metadata.sender, body)
                            }
                        }
                        ContentBody::SynchronizeMessage(m) => {
                            eprintln!("Unhandled sync message: {:?}", m);
                        }
                        ContentBody::TypingMessage(_) => {
                            println!("{:?} is typing", metadata.sender);
                        }
                        ContentBody::CallMessage(_) => {
                            println!("{:?} is calling!", metadata.sender);
                        }
                        ContentBody::ReceiptMessage(_) => {
                            println!("Got read receipt from: {:?}", metadata.sender);
                        }
                    }
                }
                Err(Error::MessagePipeInterruptedError)
            })
            .await;

            let (_, _) = (receiver?, printer?);
        }
        Subcommand::Send {
            phone_number,
            message,
        } => {
            let timestamp = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64;

            let message = ContentBody::DataMessage(DataMessage {
                body: Some(message),
                timestamp: Some(timestamp),
                ..Default::default()
            });

            manager
                .send_message(phone_number, message, timestamp)
                .await?;
        }
        Subcommand::SendToGroup {
            phone_number,
            message,
            group_id,
            master_key,
        } => {
            match (group_id.as_ref(), master_key.as_ref()) {
                (Some(_), Some(_)) => bail!("Options --group-id and --master-key are exclusive"),
                (None, None) => bail!("Either --group-id or --master-key is required"),
                _ => (),
            }

            let group_id = group_id.map(hex::decode).transpose()?;
            let master_key = master_key.map(hex::decode).transpose()?;

            let timestamp = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64;

            let data_message = DataMessage {
                body: Some(message),
                timestamp: Some(timestamp),
                group: group_id.map(|id| GroupContext {
                    id: Some(id),
                    r#type: Some(GroupType::Deliver.into()),
                    ..Default::default()
                }),
                group_v2: master_key.map(|key| GroupContextV2 {
                    master_key: Some(key),
                    revision: Some(0),
                    ..Default::default()
                }),
                ..Default::default()
            };

            manager
                .send_message_to_group(phone_number, data_message, timestamp)
                .await?;
        }
    };
    Ok(())
}
