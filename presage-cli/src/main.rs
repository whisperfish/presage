use core::fmt;
use std::convert::TryInto;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use anyhow::{anyhow, bail, Context as _};
use chrono::Local;
use clap::{ArgGroup, Parser, Subcommand};
use directories::ProjectDirs;
use env_logger::Env;
use futures::StreamExt;
use futures::{channel::oneshot, future, pin_mut};
use log::{debug, error, info};
use notify_rust::Notification;
use presage::libsignal_service::content::Reaction;
use presage::libsignal_service::proto::data_message::Quote;
use presage::libsignal_service::proto::sync_message::Sent;
use presage::libsignal_service::{groups_v2::Group, prelude::ProfileKey};
use presage::prelude::SyncMessage;
use presage::{
    prelude::{
        content::{Content, ContentBody, DataMessage, GroupContextV2},
        Contact, SignalServers,
    },
    prelude::{phonenumber::PhoneNumber, Uuid},
    GroupMasterKeyBytes, Manager, Registered, RegistrationOptions, Store, Thread,
};
use presage_store_sled::MigrationConflictStrategy;
use presage_store_sled::SledStore;
use tempfile::Builder;
use tokio::task;
use tokio::time::sleep;
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
        uuid: Uuid,
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
    Receive {
        #[clap(long = "notifications", short = 'n')]
        notifications: bool,
    },
    #[clap(about = "List groups")]
    ListGroups,
    #[clap(about = "List contacts")]
    ListContacts,
    #[clap(
        about = "List messages",
        group(
            ArgGroup::new("list-messages")
                .required(true)
                .args(&["recipient_uuid", "group_master_key"])
        )
    )]
    ListMessages {
        #[clap(long, short = 'u', help = "recipient UUID")]
        recipient_uuid: Option<Uuid>,
        #[clap(
            long,
            short = 'k',
            help = "Master Key of the V2 group (hex string)",
            value_parser = parse_group_master_key,
        )]
        group_master_key: Option<GroupMasterKeyBytes>,
        #[clap(long, help = "start from the following date (UNIX timestamp)")]
        from: Option<u64>,
    },
    #[clap(about = "Get a single contact by UUID")]
    GetContact { uuid: Uuid },
    #[clap(about = "Find a contact in the embedded DB")]
    FindContact {
        #[clap(long, short = 'u', help = "contact UUID")]
        uuid: Option<Uuid>,
        #[clap(long, short = 'p', help = "contact phone number")]
        phone_number: Option<PhoneNumber>,
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
        #[clap(long, short = 'k', help = "Master Key of the V2 group (hex string)", value_parser = parse_group_master_key)]
        master_key: GroupMasterKeyBytes,
    },
    #[cfg(feature = "quirks")]
    RequestSyncContacts,
}

fn parse_group_master_key(value: &str) -> anyhow::Result<GroupMasterKeyBytes> {
    let master_key_bytes = hex::decode(value)?;
    master_key_bytes
        .try_into()
        .map_err(|_| anyhow::format_err!("master key should be 32 bytes long"))
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    env_logger::from_env(
        Env::default().default_filter_or(format!("{}=warn", env!("CARGO_PKG_NAME"))),
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
        MigrationConflictStrategy::Raise,
    )?;
    run(args.subcommand, config_store).await
}

async fn send<C: Store + 'static>(
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

    let local = task::LocalSet::new();

    local
        .run_until(async move {
            let mut receiving_manager = manager.clone();
            task::spawn_local(async move {
                if let Err(e) = receive(&mut receiving_manager, false).await {
                    error!("error while receiving stuff: {e}");
                }
            });

            sleep(Duration::from_secs(5)).await;

            manager
                .send_message(*uuid, message, timestamp)
                .await
                .unwrap();

            sleep(Duration::from_secs(5)).await;
        })
        .await;

    Ok(())
}

// Note to developers, this is a good example of a function you can use as a source of inspiration
// to process incoming messages.
async fn process_incoming_message<C: Store>(
    manager: &mut Manager<C, Registered>,
    attachments_tmp_dir: &Path,
    notifications: bool,
    content: &Content,
) {
    print_message(manager, notifications, content);

    let sender = content.metadata.sender.uuid;
    if let ContentBody::DataMessage(DataMessage { attachments, .. }) = &content.body {
        for attachment_pointer in attachments {
            let Ok(attachment_data) = manager.get_attachment(attachment_pointer).await else {
                log::warn!("failed to fetch attachment");
                continue;
            };

            let extensions = mime_guess::get_mime_extensions_str(
                attachment_pointer
                    .content_type
                    .as_deref()
                    .unwrap_or("application/octet-stream"),
            );
            let extension = extensions.and_then(|e| e.first()).unwrap_or(&"bin");
            let filename = attachment_pointer
                .file_name
                .clone()
                .unwrap_or_else(|| Local::now().format("%Y-%m-%d-%H-%M-%s").to_string());
            let file_path = attachments_tmp_dir.join(format!("presage-{filename}.{extension}",));
            match fs::write(&file_path, &attachment_data).await {
                Ok(_) => info!("saved attachment from {sender} to {}", file_path.display()),
                Err(error) => error!(
                    "failed to write attachment from {sender} to {}: {error}",
                    file_path.display()
                ),
            }
        }
    }
}

fn print_message<C: Store>(
    manager: &Manager<C, Registered>,
    notifications: bool,
    content: &Content,
) {
    let Ok(thread) = Thread::try_from(content) else {
        log::warn!("failed to derive thread from content");
        return;
    };

    let format_data_message = |thread: &Thread, data_message: &DataMessage| match data_message {
        DataMessage {
            quote:
                Some(Quote {
                    text: Some(quoted_text),
                    ..
                }),
            body: Some(body),
            ..
        } => Some(format!("Answer to message \"{quoted_text}\": {body}")),
        DataMessage {
            reaction:
                Some(Reaction {
                    target_sent_timestamp: Some(timestamp),
                    emoji: Some(emoji),
                    ..
                }),
            ..
        } => {
            let Ok(Some(message)) = manager.message(thread, *timestamp) else {
                log::warn!("no message in {thread} sent at {timestamp}");
                return None;
            };

            let ContentBody::DataMessage(DataMessage { body: Some(body), .. }) = message.body else {
                log::warn!("message reacted to has no body");
                return None;
            };

            Some(format!("Reacted with {emoji} to message: \"{body}\""))
        }
        DataMessage {
            body: Some(body), ..
        } => Some(body.to_string()),
        _ => Some("Empty data message".to_string()),
    };

    let format_contact = |uuid| {
        manager
            .contact_by_id(uuid)
            .ok()
            .flatten()
            .filter(|c| !c.name.is_empty())
            .map(|c| format!("{}: {}", c.name, uuid))
            .unwrap_or_else(|| uuid.to_string())
    };

    let format_group = |key| {
        manager
            .group(key)
            .ok()
            .flatten()
            .map(|g| g.title)
            .unwrap_or_else(|| "<missing group>".to_string())
    };

    enum Msg<'a> {
        Received(&'a Thread, String),
        Sent(&'a Thread, String),
    }

    if let Some(msg) = match &content.body {
        ContentBody::NullMessage(_) => Some(Msg::Received(
            &thread,
            "Null message (for example deleted)".to_string(),
        )),
        ContentBody::DataMessage(data_message) => {
            format_data_message(&thread, data_message).map(|body| Msg::Received(&thread, body))
        }
        ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(Sent {
                    message: Some(data_message),
                    ..
                }),
            ..
        }) => format_data_message(&thread, data_message).map(|body| Msg::Sent(&thread, body)),
        ContentBody::CallMessage(_) => Some(Msg::Received(&thread, "is calling!".into())),
        ContentBody::TypingMessage(_) => Some(Msg::Received(&thread, "is typing...".into())),
        c => {
            log::warn!("unsupported message {c:?}");
            None
        }
    } {
        let ts = content.metadata.timestamp;
        let (prefix, body) = match msg {
            Msg::Received(Thread::Contact(sender), body) => {
                let contact = format_contact(sender);
                (format!("From {contact} @ {ts}: "), body)
            }
            Msg::Sent(Thread::Contact(recipient), body) => {
                let contact = format_contact(recipient);
                (format!("To {contact} @ {ts}"), body)
            }
            Msg::Received(Thread::Group(key), body) => {
                let sender = format_contact(&content.metadata.sender.uuid);
                let group = format_group(key);
                (format!("From {sender} to group {group} @ {ts}: "), body)
            }
            Msg::Sent(Thread::Group(key), body) => {
                let group = format_group(key);
                (format!("To group {group} @ {ts}"), body)
            }
        };

        println!("{prefix} / {body}");

        if notifications {
            if let Err(e) = Notification::new()
                .summary(&prefix)
                .body(&body)
                .icon("presage")
                .show()
            {
                log::error!("failed to display desktop notification: {e}");
            }
        }
    }
}

async fn receive<C: Store>(
    manager: &mut Manager<C, Registered>,
    notifications: bool,
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

    while let Some(content) = messages.next().await {
        process_incoming_message(manager, attachments_tmp_dir.path(), notifications, &content)
            .await;
    }

    Ok(())
}

async fn run<C: Store + 'static>(subcommand: Cmd, config_store: C) -> anyhow::Result<()> {
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
            if let Some(confirmation_code) = reader.lines().next_line().await? {
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
                    println!("{uuid:?}");
                }
                (Err(err), _) => {
                    println!("{err:?}");
                }
            }
        }
        Cmd::Receive { notifications } => {
            let mut manager = Manager::load_registered(config_store).await?;
            receive(&mut manager, notifications).await?;
        }
        Cmd::Send { uuid, message } => {
            let mut manager = Manager::load_registered(config_store).await?;
            send(&message, &uuid, &mut manager).await?;
        }
        Cmd::SendToGroup {
            message,
            master_key,
        } => {
            let mut manager = Manager::load_registered(config_store).await?;

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

            manager
                .send_message_to_group(&master_key, data_message, timestamp)
                .await?;
        }
        Cmd::Unregister => unimplemented!(),
        Cmd::RetrieveProfile {
            uuid,
            mut profile_key,
        } => {
            let mut manager = Manager::load_registered(config_store).await?;
            if profile_key.is_none() {
                for contact in manager
                    .contacts()?
                    .filter_map(Result::ok)
                    .filter(|c| c.uuid == uuid)
                {
                    let profilek:[u8;32] = match(contact.profile_key).try_into() {
                    Ok(profilek) => profilek,
                    Err(_) => bail!("Profile key is not 32 bytes or empty for uuid: {:?} and no alternative profile key was provided", uuid),
                };
                    profile_key = Some(ProfileKey::create(profilek));
                }
            } else {
                println!("Retrieving profile for: {uuid:?} with profile_key");
            }
            let profile = match profile_key {
                None => manager.retrieve_profile().await?,
                Some(profile_key) => manager.retrieve_profile_by_uuid(uuid, profile_key).await?,
            };
            println!("{profile:#?}");
        }
        Cmd::UpdateProfile => unimplemented!(),
        Cmd::GetUserStatus => unimplemented!(),
        Cmd::Block => unimplemented!(),
        Cmd::Unblock => unimplemented!(),
        Cmd::UpdateContact => unimplemented!(),
        Cmd::ListGroups => {
            let manager = Manager::load_registered(config_store).await?;
            for group in manager.groups()? {
                match group {
                    Ok((
                        group_master_key,
                        Group {
                            title,
                            description,
                            revision,
                            members,
                            ..
                        },
                    )) => {
                        let key = hex::encode(group_master_key);
                        println!(
                            "{key} {title}: {description:?} / revision {revision} / {} members",
                            members.len()
                        );
                    }
                    Err(error) => {
                        error!("Error: failed to deserialize group, {error}");
                    }
                };
            }
        }
        Cmd::ListContacts => {
            let manager = Manager::load_registered(config_store).await?;
            for Contact {
                name,
                uuid,
                phone_number,
                ..
            } in manager.contacts()?.flatten()
            {
                println!("{uuid} / {phone_number:?} / {name}");
            }
        }
        Cmd::Whoami => {
            let manager = Manager::load_registered(config_store).await?;
            println!("{:?}", &manager.whoami().await?);
        }
        Cmd::GetContact { ref uuid } => {
            let manager = Manager::load_registered(config_store).await?;
            match manager.contact_by_id(uuid)? {
                Some(contact) => println!("{contact:#?}"),
                None => eprintln!("Could not find contact for {uuid}"),
            }
        }
        Cmd::FindContact {
            uuid,
            phone_number,
            ref name,
        } => {
            let manager = Manager::load_registered(config_store).await?;
            for contact in manager
                .contacts()?
                .filter_map(Result::ok)
                .filter(|c| uuid.map_or_else(|| true, |u| c.uuid == u))
                .filter(|c| c.phone_number == phone_number)
                .filter(|c| name.as_ref().map_or(true, |n| c.name.contains(n)))
            {
                println!("{contact:#?}");
            }
        }
        #[cfg(feature = "quirks")]
        Cmd::RequestSyncContacts => {
            let mut manager = Manager::load_registered(config_store).await?;
            manager.request_contacts_sync().await?;
        }
        Cmd::ListMessages {
            group_master_key,
            recipient_uuid,
            from,
        } => {
            let manager = Manager::load_registered(config_store).await?;
            let thread = match (group_master_key, recipient_uuid) {
                (Some(master_key), _) => Thread::Group(master_key),
                (_, Some(uuid)) => Thread::Contact(uuid),
                _ => unreachable!(),
            };
            for msg in manager
                .messages(&thread, from.unwrap_or(0)..)?
                .filter_map(Result::ok)
            {
                print_message(&manager, false, &msg);
            }
        }
    }
    Ok(())
}

fn parse_base64_profile_key(s: &str) -> anyhow::Result<ProfileKey> {
    let bytes = base64::decode(s)?
        .try_into()
        .map_err(|_| anyhow!("profile key of invalid length"))?;
    Ok(ProfileKey::create(bytes))
}

struct DebugGroup<'a>(&'a Group);

impl fmt::Debug for DebugGroup<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let group = &self.0;
        f.debug_struct("Group")
            .field("title", &group.title)
            .field("avatar", &group.avatar)
            .field("revision", &group.revision)
            .field("description", &group.description)
            .finish()
    }
}
