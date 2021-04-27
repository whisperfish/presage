use std::{convert::TryInto, path::PathBuf, time::UNIX_EPOCH};

use anyhow::bail;
use directories::ProjectDirs;
use futures::{channel::mpsc::channel, future, StreamExt};
use log::debug;
use presage::{config::SledConfigStore, prelude::sync_message::Sent, Error, Manager};

use structopt::StructOpt;

use libsignal_service::{
    configuration::SignalServers,
    content::{ContentBody, DataMessage, GroupContext, GroupContextV2, GroupType, SyncMessage},
    prelude::{phonenumber::PhoneNumber, GroupMasterKey},
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
        phone_number: PhoneNumber,
        #[structopt(long)]
        use_voice_call: bool,
        #[structopt(
            long = "captcha",
            help = "Captcha obtained from https://signalcaptchas.org/registration/generate.html"
        )]
        captcha: Option<String>,
    },
    #[structopt(about = "Unregister from Signal")]
    Unregister,
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
    #[structopt(about = "Get information on the registered user")]
    Whoami,
    #[structopt(about = "Sets a name, status and avatar")]
    UpdateProfile,
    #[structopt(about = "Check if a user is registered on Signal")]
    GetUserStatus,
    #[structopt(about = "Update the account attributes")]
    UpdateAccount,
    #[structopt(about = "Block the provided contacts or groups")]
    Block,
    #[structopt(about = "Unblock the provided contacts or groups")]
    Unblock,
    #[structopt(about = "Update the details of a contact")]
    UpdateContact,
    #[structopt(about = "Receives all pending messages and saves them to disk")]
    Receive,
    #[structopt(about = "List group memberships")]
    ListGroups,
    #[structopt(about = "sends a message")]
    Send {
        #[structopt(long, short = "n", help = "Phone number of the recipient")]
        phone_number: PhoneNumber,
        #[structopt(long, short = "m", help = "Contents of the message to send")]
        message: String,
    },
    #[structopt(about = "sends a message to group")]
    SendToGroup {
        #[structopt(
            long = "phone-number",
            short = "n",
            min_values = 1,
            required = true,
            help = "Phone number of the recipient"
        )]
        recipients: Vec<PhoneNumber>,
        #[structopt(long, short = "m", help = "Contents of the message to send")]
        message: String,
        #[structopt(long, short = "g", help = "ID of the legacy group (hex string)")]
        group_id: Option<String>,
        #[structopt(long, short = "k", help = "Master Key of the V2 group (hex string)")]
        master_key: Option<String>,
    },
    #[cfg(feature = "quirks")]
    RequestSyncContacts,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", format!("{}=debug", env!("CARGO_PKG_NAME")));
    }
    env_logger::builder().init();

    let args = Args::from_args();

    let db_path = args.db_path.unwrap_or_else(|| {
        ProjectDirs::from("org", "libsignal-service-rs", "signal-bot-rs")
            .unwrap()
            .config_dir()
            .into()
    });
    debug!("opening config database from {}", db_path.display());
    let config_store = SledConfigStore::new(db_path)?;

    let csprng = rand::thread_rng();
    let mut manager = Manager::with_config_store(config_store, csprng)?;

    match args.subcommand {
        Subcommand::Register {
            servers,
            phone_number,
            use_voice_call,
            captcha,
        } => {
            manager
                .register(servers, phone_number, use_voice_call, captcha.as_deref())
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

            let (receiver, printer) =
                future::join(manager.clone().receive_messages(tx), async move {
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
                                } else {
                                    println!("Message from {:?}: {:?}", metadata, message);
                                    // fetch the groups v2 info here, just for testing purposes
                                    if let Some(group_v2) = message.group_v2 {
                                        let _master_key = GroupMasterKey::new(
                                            group_v2.master_key.unwrap().try_into().unwrap(),
                                        );
                                        // let group = manager.get_group_v2(master_key).await;
                                        // println!("Group v2: {:?}", group);
                                    }
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
            recipients,
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
                .send_message_to_group(
                    recipients.into_iter().map(Into::into),
                    data_message,
                    timestamp,
                )
                .await?;
        }
        Subcommand::Unregister => unimplemented!(),
        Subcommand::UpdateProfile => unimplemented!(),
        Subcommand::GetUserStatus => unimplemented!(),
        Subcommand::UpdateAccount => unimplemented!(),
        Subcommand::Block => unimplemented!(),
        Subcommand::Unblock => unimplemented!(),
        Subcommand::UpdateContact => unimplemented!(),
        Subcommand::ListGroups => unimplemented!(),
        Subcommand::Whoami => {
            println!("{:?}", &manager.whoami().await?)
        }
        #[cfg(feature = "quirks")]
        Subcommand::RequestSyncContacts => {
            manager.request_contacts_sync().await?;
        }
    };
    Ok(())
}
