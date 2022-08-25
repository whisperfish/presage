use std::{path::PathBuf, time::UNIX_EPOCH};

use anyhow::Context as _;
use chrono::Local;
use directories::ProjectDirs;
use env_logger::Env;
use futures::{channel::oneshot, future, pin_mut, StreamExt};
use log::{debug, info};
use presage::{
    prelude::{
        content::{Content, ContentBody, DataMessage, GroupContextV2, SyncMessage},
        proto::sync_message::Sent,
        Contact, GroupMasterKey, SignalServers,
    },
    prelude::{phonenumber::PhoneNumber, ServiceAddress, Uuid},
    ConfigStore, Manager, Registered, RegistrationOptions, SecretVolatileConfigStore,
    SledConfigStore,
};
use structopt::StructOpt;
use tempfile::Builder;
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, BufReader},
};
use url::Url;

#[derive(StructOpt)]
#[structopt(about = "a basic signal CLI to try things out")]
struct Args {
    #[structopt(long = "db-path", short = "d", group = "store")]
    db_path: Option<PathBuf>,

    #[structopt(long = "volatile", group = "store")]
    volatile: bool,

    #[structopt(flatten)]
    subcommand: Subcommand,
}

#[derive(StructOpt)]
enum Subcommand {
    #[structopt(about = "Register using a phone number")]
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
        captcha: Url,
        #[structopt(long, help = "Force to register again if already registered")]
        force: bool,
    },
    #[structopt(about = "Unregister from Signal")]
    Unregister,
    #[structopt(
        about = "Generate a QR code to scan with Signal for iOS or Android to link this client as secondary device"
    )]
    LinkDevice {
        /// Possible values: staging, production
        #[structopt(long, short = "s", default_value = "production")]
        servers: SignalServers,
        #[structopt(
            long,
            short = "n",
            help = "Name of the device to register in the primary client"
        )]
        device_name: String,
        #[structopt(
            long,
            short = "f",
            help = "Command to execute after linking the device. (Send or Receive)"
        )]
        follow_up_command: String,
    },
    #[structopt(about = "Get information on the registered user")]
    Whoami,
    #[structopt(about = "Retrieve the user profile")]
    RetrieveProfile,
    #[structopt(about = "Set a name, status and avatar")]
    UpdateProfile,
    #[structopt(about = "Check if a user is registered on Signal")]
    GetUserStatus,
    #[structopt(about = "Block contacts or groups")]
    Block,
    #[structopt(about = "Unblock contacts or groups")]
    Unblock,
    #[structopt(about = "Update the details of a contact")]
    UpdateContact,
    #[structopt(about = "Receive all pending messages and saves them to disk")]
    Receive,
    #[structopt(about = "List group memberships")]
    ListGroups,
    #[structopt(about = "List contacts")]
    ListContacts,
    #[structopt(about = "Find a contact in the embedded DB")]
    FindContact {
        #[structopt(long, short = "u", help = "contact UUID")]
        uuid: Option<Uuid>,
        #[structopt(long, short = "name", help = "contact name")]
        name: Option<String>,
    },
    #[structopt(about = "Send a message")]
    Send {
        #[structopt(long, short = "u", help = "uuid of the recipient")]
        uuid: Uuid,
        #[structopt(long, short = "m", help = "Contents of the message to send")]
        message: String,
    },
    #[structopt(about = "Send a message to group")]
    SendToGroup {
        #[structopt(long, short = "m", help = "Contents of the message to send")]
        message: String,
        #[structopt(long, short = "k", help = "Master Key of the V2 group (hex string)")]
        master_key: String,
    },
    #[cfg(feature = "quirks")]
    RequestSyncContacts,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::from_env(
        Env::default().default_filter_or(format!("{}=info", env!("CARGO_PKG_NAME"))),
    )
    .init();

    let args = Args::from_args();

    if args.volatile {
        run(args.subcommand, SecretVolatileConfigStore::default()).await
    } else {
        let db_path = args.db_path.unwrap_or_else(|| {
            ProjectDirs::from("org", "whisperfish", "presage")
                .unwrap()
                .config_dir()
                .into()
        });
        debug!("opening config database from {}", db_path.display());
        let config_store = SledConfigStore::new(db_path)?;
        run(args.subcommand, config_store).await
    }
}

async fn send<C: ConfigStore>(
    msg: &str,
    uuid: &Uuid,
    manager: &Manager<C, Registered>,
) -> anyhow::Result<()> {
    let timestamp = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    let message = ContentBody::DataMessage(DataMessage {
        body: Some(msg.to_string()),
        timestamp: Some(timestamp),
        ..Default::default()
    });

    manager.send_message(*uuid, message, timestamp).await?;
    Ok(())
}

async fn receive<C: ConfigStore>(manager: &Manager<C, Registered>) -> anyhow::Result<()> {
    let attachments_tmp_dir = Builder::new().prefix("presage-attachments").tempdir()?;
    info!(
        "attachments will be stored in {}",
        attachments_tmp_dir.path().display()
    );

    let messages = manager
        .clone()
        .receive_messages()
        .await
        .context("failed to initialize messages stream")?;
    pin_mut!(messages);
    while let Some(Content { metadata, body }) = messages.next().await {
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
                        message.body(),
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
                        let master_key_bytes: [u8; 32] =
                            group_v2.master_key.clone().unwrap().try_into().unwrap();
                        let master_key = GroupMasterKey::new(master_key_bytes);
                        let group = manager.get_group_v2(master_key).await?;
                        let group_changes = manager.decrypt_group_context(group_v2)?;
                        println!("Group v2: {:?}", group.title);
                        println!("Group change: {:?}", group_changes);
                        println!("Group Master Key: {:?}", hex::encode(master_key_bytes));
                    }
                }

                for attachment_pointer in message.attachments {
                    let attachment_data = manager.get_attachment(&attachment_pointer).await?;
                    let extensions = mime_guess::get_mime_extensions_str(
                        attachment_pointer
                            .content_type
                            .as_deref()
                            .unwrap_or("application/octet-stream"),
                    );
                    let extension = extensions.and_then(|e| e.first()).unwrap_or(&"bin");
                    let file_path = attachments_tmp_dir.path().join(format!(
                        "presage-{}.{}",
                        Local::now().format("%Y-%m-%d-%H-%M-%s"),
                        extension
                    ));
                    fs::write(&file_path, &attachment_data).await?;
                    info!(
                        "saved received attachment from {} to {}",
                        metadata.sender,
                        file_path.display()
                    );
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
    Ok(())
}

async fn run<C: ConfigStore>(subcommand: Subcommand, config_store: C) -> anyhow::Result<()> {
    match subcommand {
        Subcommand::Register {
            servers,
            phone_number,
            use_voice_call,
            captcha,
            force,
        } => {
            let manager = Manager::register(
                config_store,
                RegistrationOptions {
                    signal_servers: servers,
                    phone_number,
                    use_voice_call,
                    captcha: Some(captcha.host_str().unwrap()),
                    force,
                },
            )
            .await?;

            // ask for confirmation code here
            let stdin = io::stdin();
            let reader = BufReader::new(stdin);
            if let Some(line) = reader.lines().next_line().await? {
                let confirmation_code = line.parse()?;
                manager.confirm_verification_code(confirmation_code).await?;
            }
        }
        Subcommand::LinkDevice {
            servers,
            device_name,
            follow_up_command,
        } => {
            let (provisioning_link_tx, provisioning_link_rx) = oneshot::channel();
            let manager = future::join(
                Manager::link_secondary_device(
                    config_store,
                    servers,
                    device_name.clone(),
                    provisioning_link_tx,
                ),
                async move {
                    match provisioning_link_rx.await {
                        Ok(url) => {
                            qr2term::print_qr(url.to_string()).expect("failed to render qrcode")
                        }
                        Err(e) => log::error!("Error linking device: {e}"),
                    }
                },
            )
            .await;

            match manager {
                (Ok(manager), _) => {
                    let uuid = manager.whoami().await.unwrap().uuid;
                    println!("{:?}", uuid);

                    match follow_up_command.as_ref() {
                        "Send" => {
                            send("Hello World", &uuid, &manager).await?;
                        }
                        "Receive" => {
                            receive(&manager).await?;
                        }
                        _ => {}
                    };
                }
                (Err(err), _) => {
                    println!("{:?}", err);
                }
            };
        }
        Subcommand::Receive => {
            let manager = Manager::load_registered(config_store)?;
            receive(&manager).await?;
        }
        Subcommand::Send { uuid, message } => {
            let manager = Manager::load_registered(config_store)?;
            send(&message, &uuid, &manager).await?;
        }
        Subcommand::SendToGroup {
            message,
            master_key,
        } => {
            let manager = Manager::load_registered(config_store)?;

            let master_key = hex::decode(master_key)?;

            let timestamp = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64;

            let data_message = DataMessage {
                body: Some(message),
                timestamp: Some(timestamp),
                group_v2: Some(GroupContextV2 {
                    master_key: Some(master_key.clone()),
                    revision: Some(0),
                    ..Default::default()
                }),
                ..Default::default()
            };

            let group = manager
                .get_group_v2(GroupMasterKey::new(
                    master_key.try_into().expect("MasterKey to be 32 bytes"),
                ))
                .await?;

            manager
                .send_message_to_group(
                    group.members.into_iter().map(|m| m.uuid).map(Into::into),
                    data_message,
                    timestamp,
                )
                .await?;
        }
        Subcommand::Unregister => unimplemented!(),
        Subcommand::RetrieveProfile => {
            let manager = Manager::load_registered(config_store)?;
            let profile = manager.retrieve_profile().await?;
            println!("{:#?}", profile);
        }
        Subcommand::UpdateProfile => unimplemented!(),
        Subcommand::GetUserStatus => unimplemented!(),
        Subcommand::Block => unimplemented!(),
        Subcommand::Unblock => unimplemented!(),
        Subcommand::UpdateContact => unimplemented!(),
        Subcommand::ListGroups => unimplemented!(),
        Subcommand::ListContacts => {
            let manager = Manager::load_registered(config_store)?;
            for contact in manager.get_contacts()? {
                if let Contact {
                    name,
                    address:
                        ServiceAddress {
                            uuid: Some(uuid),
                            phonenumber: Some(phonenumber),
                            ..
                        },
                    ..
                } = contact
                {
                    println!("{} / {} / {}", uuid, name, phonenumber);
                }
            }
        }
        Subcommand::Whoami => {
            let manager = Manager::load_registered(config_store)?;
            println!("{:?}", &manager.whoami().await?)
        }
        Subcommand::FindContact { uuid, ref name } => {
            let manager = Manager::load_registered(config_store)?;
            for contact in manager
                .get_contacts()?
                .filter(|c| c.address.uuid == uuid)
                .filter(|c| name.as_ref().map_or(true, |n| c.name.contains(n)))
            {
                println!("{}: {}", contact.name, contact.address);
            }
        }
        #[cfg(feature = "quirks")]
        Subcommand::RequestSyncContacts => {
            let manager = Manager::load_registered(config_store)?;
            manager.request_contacts_sync().await?;
        }
    };
    Ok(())
}
