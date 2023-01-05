use core::fmt;
use std::{path::PathBuf, time::UNIX_EPOCH};

use anyhow::{anyhow, bail, Context as _};
use chrono::Local;
use clap::{ArgGroup, Parser, Subcommand};
use directories::ProjectDirs;
use env_logger::Env;
use futures::{channel::oneshot, future, pin_mut, StreamExt};
use libsignal_service::profile_name::ProfileName;
use libsignal_service::{groups_v2::Group, push_service::ProfileKey};
use log::{debug, info};
use presage::{
    prelude::{
        content::{Content, ContentBody, DataMessage, GroupContextV2, SyncMessage},
        proto::sync_message::Sent,
        Contact, GroupMasterKey, SignalServers,
    },
    prelude::{phonenumber::PhoneNumber, ServiceAddress, Uuid},
    Manager, MessageStore, MigrationConflictStrategy, Registered, RegistrationOptions, SledStore,
    Store, Thread,
};
use tempfile::Builder;
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, BufReader},
};
use url::Url;

#[derive(Parser)]
#[clap(about = "a basic signal CLI to try things out")]
struct Args {
    #[clap(long = "db-path", short = 'd', group = "store")]
    db_path: Option<PathBuf>,

    #[clap(
        help = "passphrase to encrypt the local storage",
        long = "passphrase",
        short = 'p',
        group = "store"
    )]
    passphrase: Option<String>,

    #[clap(subcommand)]
    subcommand: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[clap(about = "Register using a phone number")]
    Register {
        #[clap(long = "servers", short = 's', default_value = "staging")]
        servers: SignalServers,
        #[clap(long, help = "Phone Number to register with in E.164 format")]
        phone_number: PhoneNumber,
        #[clap(long)]
        use_voice_call: bool,
        #[clap(
            long = "captcha",
            help = "Captcha obtained from https://signalcaptchas.org/registration/generate.html"
        )]
        captcha: Url,
        #[clap(long, help = "Force to register again if already registered")]
        force: bool,
    },
    #[clap(about = "Unregister from Signal")]
    Unregister,
    #[clap(
        about = "Generate a QR code to scan with Signal for iOS or Android to link this client as secondary device"
    )]
    LinkDevice {
        /// Possible values: staging, production
        #[clap(long, short = 's', default_value = "production")]
        servers: SignalServers,
        #[clap(
            long,
            short = 'n',
            help = "Name of the device to register in the primary client"
        )]
        device_name: String,
    },
    #[clap(about = "Get information on the registered user")]
    Whoami,
    #[clap(about = "Retrieve the user profile")]
    RetrieveProfile {
        /// Id of the user to retrieve the profile. When omitted, retrieves the registered user
        /// profile.
        #[clap(long)]
        uuid: Option<Uuid>,
        /// Base64-encoded profile key of user to be able to access their profile
        #[clap(long, value_parser = parse_base64_profile_key)]
        profile_key: Option<ProfileKey>,
    },
    #[clap(about = "Set a name, status and avatar")]
    UpdateProfile,
    #[clap(about = "Check if a user is registered on Signal")]
    GetUserStatus,
    #[clap(about = "Block contacts or groups")]
    Block,
    #[clap(about = "Unblock contacts or groups")]
    Unblock,
    #[clap(about = "Update the details of a contact")]
    UpdateContact,
    #[clap(about = "Receive all pending messages and saves them to disk")]
    Receive,
    /// Get information about a group
    GetGroup {
        #[clap(long, short = 'k', value_parser = parse_base64_master_key)]
        group_master_key: GroupMasterKey,
    },
    #[clap(about = "List group memberships")]
    ListGroups,
    #[clap(about = "List contacts")]
    ListContacts,
    #[clap(
        about = "List messages",
        group(
            ArgGroup::new("list-messages")
                .required(true)
                .args(&["recipient-uuid", "group-master-key"]),
        )
    )]
    ListMessages {
        #[clap(long, short = 'u', help = "recipient UUID")]
        recipient_uuid: Option<Uuid>,
        #[clap(
            long,
            short = 'k',
            help = "Master Key of the V2 group (hex string)",
            value_parser = parse_master_key,
        )]
        group_master_key: Option<[u8; 32]>,
    },
    #[clap(about = "Find a contact in the embedded DB")]
    FindContact {
        #[clap(long, short = 'u', help = "contact UUID")]
        uuid: Option<Uuid>,
        #[clap(long, short = 'n', help = "contact name")]
        name: Option<String>,
    },
    #[clap(about = "Send a message")]
    Send {
        #[clap(long, short = 'u', help = "uuid of the recipient")]
        uuid: Uuid,
        #[clap(long, short = 'm', help = "Contents of the message to send")]
        message: String,
    },
    #[clap(about = "Send a message to group")]
    SendToGroup {
        #[clap(long, short = 'm', help = "Contents of the message to send")]
        message: String,
        #[clap(long, short = 'k', help = "Master Key of the V2 group (hex string)", value_parser = parse_master_key)]
        master_key: [u8; 32],
    },
    #[clap(about = "Update contacts from the signal server, where the contacts have no name")]
    UpdateContactsFromProfile,
    #[cfg(feature = "quirks")]
    RequestSyncContacts,
}

fn parse_master_key(value: &str) -> anyhow::Result<[u8; 32]> {
    let master_key_bytes = hex::decode(value)?;
    master_key_bytes
        .try_into()
        .map_err(|_| anyhow::format_err!("master key should be 32 bytes long"))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::from_env(
        Env::default().default_filter_or(format!("{}=info", env!("CARGO_PKG_NAME"))),
    )
    .init();

    let args = Args::parse();

    let db_path = args.db_path.unwrap_or_else(|| {
        ProjectDirs::from("org", "whisperfish", "presage")
            .unwrap()
            .config_dir()
            .into()
    });
    debug!("opening config database from {}", db_path.display());
    let config_store = SledStore::open_with_passphrase(
        db_path,
        args.passphrase,
        MigrationConflictStrategy::BackupAndDrop,
    )?;
    run(args.subcommand, config_store).await
}

async fn send<C: Store>(
    msg: &str,
    uuid: &Uuid,
    manager: &mut Manager<C, Registered>,
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

async fn receive<C: Store + MessageStore>(
    manager: &mut Manager<C, Registered>,
) -> anyhow::Result<()> {
    let attachments_tmp_dir = Builder::new().prefix("presage-attachments").tempdir()?;
    info!(
        "attachments will be stored in {}",
        attachments_tmp_dir.path().display()
    );

    let messages = manager
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
                        println!("Group master key: {:?}", hex::encode(&master_key_bytes));
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

async fn run<C: Store + MessageStore>(subcommand: Cmd, config_store: C) -> anyhow::Result<()> {
    match subcommand {
        Cmd::Register {
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
        Cmd::LinkDevice {
            servers,
            device_name,
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
                }
                (Err(err), _) => {
                    println!("{:?}", err);
                }
            };
        }
        Cmd::Receive => {
            let mut manager = Manager::load_registered(config_store)?;
            receive(&mut manager).await?;
        }
        Cmd::Send { uuid, message } => {
            let mut manager = Manager::load_registered(config_store)?;
            send(&message, &uuid, &mut manager).await?;
        }
        Cmd::SendToGroup {
            message,
            master_key,
        } => {
            let mut manager = Manager::load_registered(config_store)?;

            let timestamp = std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("Time went backwards")
                .as_millis() as u64;

            let data_message = DataMessage {
                body: Some(message),
                timestamp: Some(timestamp),
                group_v2: Some(GroupContextV2 {
                    master_key: Some(master_key.to_vec()),
                    revision: Some(0),
                    ..Default::default()
                }),
                ..Default::default()
            };

            let group = manager
                .get_group_v2(GroupMasterKey::new(master_key))
                .await?;

            manager
                .send_message_to_group(
                    group.members.into_iter().map(|m| m.uuid).map(Into::into),
                    data_message,
                    timestamp,
                )
                .await?;
        }
        Cmd::Unregister => unimplemented!(),
        Cmd::RetrieveProfile { uuid, profile_key } => {
            let manager = Manager::load_registered(config_store)?;
            let profile = match (uuid, profile_key) {
                (None, None) => manager.retrieve_profile().await?,
                (None, Some(_)) => bail!("profile key without provided user uuid"),
                (Some(_), None) => bail!("user uuid without provided profile key"),
                (Some(uuid), Some(profile_key)) => {
                    manager
                        .retrieve_profile_by_uuid(uuid, profile_key.0)
                        .await?
                }
            };
            println!("{profile:#?}");
        }
        Cmd::UpdateProfile => unimplemented!(),
        Cmd::GetUserStatus => unimplemented!(),
        Cmd::Block => unimplemented!(),
        Cmd::Unblock => unimplemented!(),
        Cmd::UpdateContact => unimplemented!(),
        Cmd::ListGroups => unimplemented!(),
        Cmd::UpdateContactsFromProfile => {
            let mut manager = Manager::load_registered(config_store)?;
            for contact in manager.get_contacts()? {
                let mut contact = contact?;
                if contact.name.is_empty() {
                    let k = contact.profile_key.to_vec();
                    let profile_key: [u8; 32] = match k.try_into() {
                        Ok(key) => key,
                        Err(_) => continue,
                    };
                    let profile = manager
                        .retrieve_profile_by_uuid(
                            contact.address.uuid.unwrap_or(Uuid::nil()),
                            profile_key,
                        )
                        .await?;
                    let name = profile.name.unwrap_or(ProfileName {
                        given_name: match contact.address.phonenumber {
                            Some(_) => "".to_string(),
                            None => continue,
                        },
                        family_name: None,
                    });
                    contact.name = name.to_string();
                    match manager.save_contact(contact) {
                        Ok(_) => {}
                        Err(e) => {
                            println!("Error saving contact: {:?}", e);
                        }
                    };
                    println!("Updating contact: {:?}", name);
                }
            }
        }
        Cmd::ListContacts => {
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
                } = contact?
                {
                    println!("{} / {} / {}", uuid, name, phonenumber);
                }
            }
        }
        Cmd::Whoami => {
            let manager = Manager::load_registered(config_store)?;
            println!("{:?}", &manager.whoami().await?)
        }
        Cmd::FindContact { uuid, ref name } => {
            let manager = Manager::load_registered(config_store)?;
            for contact in manager
                .get_contacts()?
                .filter_map(Result::ok)
                .filter(|c| c.address.uuid == uuid)
                .filter(|c| name.as_ref().map_or(true, |n| c.name.contains(n)))
            {
                println!("{contact:#?}");
            }
        }
        #[cfg(feature = "quirks")]
        Cmd::RequestSyncContacts => {
            let mut manager = Manager::load_registered(config_store)?;
            manager.request_contacts_sync().await?;
        }
        Cmd::ListMessages {
            group_master_key,
            recipient_uuid,
        } => {
            let thread = match (group_master_key, recipient_uuid) {
                (Some(master_key), _) => Thread::Group(master_key),
                (_, Some(uuid)) => Thread::Contact(uuid),
                _ => unreachable!(),
            };
            let iter = config_store.messages(&thread, None)?;
            for msg in iter.filter_map(Result::ok) {
                println!("{}: {:?}", msg.metadata.sender.identifier(), msg);
            }
        }
        Cmd::GetGroup { group_master_key } => {
            let manager = Manager::load_registered(config_store)?;
            let group = manager.get_group_v2(group_master_key).await?;
            println!("{:#?}", DebugGroup(&group));
            for member in &group.members {
                let profile_key = base64::encode(&member.profile_key.bytes);
                println!("{member:#?} => profile_key = {profile_key}",);
            }
        }
    };
    Ok(())
}

fn parse_base64_master_key(s: &str) -> anyhow::Result<GroupMasterKey> {
    let bytes = base64::decode(s)?
        .try_into()
        .map_err(|_| anyhow!("group master key of invalid length"))?;
    Ok(GroupMasterKey::new(bytes))
}

fn parse_base64_profile_key(s: &str) -> anyhow::Result<ProfileKey> {
    let bytes = base64::decode(s)?
        .try_into()
        .map_err(|_| anyhow!("profile key of invalid length"))?;
    Ok(ProfileKey(bytes))
}

struct DebugGroup<'a>(&'a Group);

impl fmt::Debug for DebugGroup<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let group = &self.0;
        f.debug_struct("Group")
            .field("title", &group.title)
            .field("avatar", &group.avatar)
            .field("version", &group.version)
            .field("description", &group.description)
            .finish()
    }
}
