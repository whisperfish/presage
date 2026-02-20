use std::convert::TryInto;
use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;
use std::time::UNIX_EPOCH;

use anyhow::{anyhow, bail, Context as _};
use base64::prelude::*;
use chrono::Local;
use clap::{ArgGroup, Parser, Subcommand};
use directories::ProjectDirs;
use futures::StreamExt;
use futures::{channel::oneshot, future, pin_mut};
use mime_guess::mime::APPLICATION_OCTET_STREAM;
use notify_rust::Notification;
use presage::libsignal_service::configuration::SignalServers;
use presage::libsignal_service::content::Reaction;
use presage::libsignal_service::pre_keys::PreKeysStore;
use presage::libsignal_service::prelude::phonenumber::PhoneNumber;
use presage::libsignal_service::prelude::ProfileKey;
use presage::libsignal_service::prelude::Uuid;
use presage::libsignal_service::proto::data_message::Quote;
use presage::libsignal_service::proto::sync_message::Sent;
use presage::libsignal_service::protocol::ServiceId;
use presage::libsignal_service::sender::AttachmentSpec;
use presage::libsignal_service::zkgroup::GroupMasterKeyBytes;
use presage::model::contacts::Contact;
use presage::model::groups::Group;
use presage::model::identity::OnNewIdentity;
use presage::model::messages::Received;
use presage::proto::receipt_message;
use presage::proto::EditMessage;
use presage::proto::ReceiptMessage;
use presage::proto::SyncMessage;
use presage::store::ContentExt;
use presage::{
    libsignal_service::content::{Content, ContentBody, DataMessage, GroupContextV2},
    manager::{Registered, RegistrationOptions},
    store::{Store, Thread},
    Manager,
};
use presage_store_sqlite::SqliteStore;
use tempfile::Builder;
use tempfile::TempDir;
use tokio::{
    fs,
    io::{self, AsyncBufReadExt, BufReader},
};
use tracing::warn;
use tracing::{debug, error, info};
use url::Url;

#[derive(Parser)]
#[clap(about = "a basic signal CLI to try things out")]
struct Args {
    #[clap(long = "sqlite-db-path", group = "db")]
    sqlite_db_path: Option<String>,

    #[clap(
        help = "passphrase to encrypt the local storage",
        long = "passphrase",
        short = 'p'
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
    #[clap(about = "Create QR code (URL) and wait until this device is linked as new secondary")]
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
    #[clap(
        about = "Add a new secondary device to this (primary) device via URL (see link-device)"
    )]
    AddDevice {
        #[clap(
            long,
            short = 'u',
            help = "The URL (that is represented as QR code) created by the secondary device (see link-device)"
        )]
        url: Url,
    },
    #[clap(about = "Unlink device by device id")]
    UnlinkDevice {
        #[clap(long, short = 'd', help = "Device id")]
        device_id: u32,
    },
    #[clap(about = "List all linked devices")]
    ListDevices,
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
    #[clap(about = "Receive all pending messages and saves them to disk")]
    Sync {
        #[clap(long = "notifications", short = 'n')]
        notifications: bool,
        #[clap(
            long,
            short = 'q',
            help = "Exit after processing the messages in the queue (similar to the syncing of Signal Desktop)"
        )]
        stop_after_empty_queue: bool,
    },
    #[clap(about = "List groups")]
    ListGroups {
        /// Name filter to only list groups which name contains this string
        #[clap(long)]
        name_filter: Option<String>,
        /// Display the entire group metadata
        #[clap(long, short = 'v')]
        verbose: bool,
    },
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
    #[clap(about = "List downloaded sticker packs")]
    ListStickerPacks,
    #[clap(about = "Get a single contact by UUID")]
    GetContact {
        uuid: Uuid,
    },
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
        #[clap(long = "attach", help = "Path to a file to attach, can be repeated")]
        attachment_filepath: Vec<PathBuf>,
    },
    #[clap(about = "Send a message to group")]
    SendToGroup {
        #[clap(long, short = 'm', help = "Contents of the message to send")]
        message: String,
        #[clap(long, short = 'k', help = "Master Key of the V2 group (hex string)", value_parser = parse_group_master_key)]
        master_key: GroupMasterKeyBytes,
        #[clap(long = "attach", help = "Path to a file to attach, can be repeated")]
        attachment_filepath: Vec<PathBuf>,
    },
    SyncContacts,
    #[clap(about = "Print various statistics useful for debugging")]
    Stats,
}

enum Recipient {
    Contact(Uuid),
    Group(GroupMasterKeyBytes),
}

fn parse_group_master_key(value: &str) -> anyhow::Result<GroupMasterKeyBytes> {
    let master_key_bytes = hex::decode(value)?;
    master_key_bytes
        .try_into()
        .map_err(|_| anyhow::format_err!("master key should be 32 bytes long"))
}

fn attachments_tmp_dir() -> anyhow::Result<TempDir> {
    let attachments_tmp_dir = Builder::new().prefix("presage-attachments").tempdir()?;
    info!(
        path =% attachments_tmp_dir.path().display(),
        "attachments will be stored"
    );
    Ok(attachments_tmp_dir)
}

fn init() -> Args {
    let filter = tracing_subscriber::EnvFilter::builder()
        .with_default_directive(tracing::metadata::LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .init();
    Args::parse()
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> anyhow::Result<()> {
    let args = init();

    let sqlite_db_path = args.sqlite_db_path.unwrap_or_else(|| {
        ProjectDirs::from("org", "whisperfish", "presage")
            .unwrap()
            .config_dir()
            .join("cli.db3")
            .display()
            .to_string()
    });

    debug!(sqlite_db_path, "opening config database");
    let config_store = SqliteStore::open_with_passphrase(
        &sqlite_db_path,
        args.passphrase.as_deref(),
        OnNewIdentity::Trust,
    )
    .await?;

    let local = tokio::task::LocalSet::new();
    local.run_until(run(args.subcommand, config_store)).await
}

async fn send<S: Store>(
    manager: &mut Manager<S, Registered>,
    recipient: Recipient,
    msg: impl Into<ContentBody>,
) -> anyhow::Result<()> {
    let attachments_tmp_dir = attachments_tmp_dir()?;

    let timestamp = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64;

    let mut content_body = msg.into();
    if let ContentBody::DataMessage(d) = &mut content_body {
        d.timestamp = Some(timestamp);
    }

    let messages = manager
        .receive_messages()
        .await
        .context("failed to initialize messages stream")?;
    pin_mut!(messages);

    println!("synchronizing messages since last time");

    while let Some(content) = messages.next().await {
        match content {
            Received::QueueEmpty => break,
            Received::Contacts => continue,
            Received::Content(content) => {
                process_incoming_message(manager, attachments_tmp_dir.path(), false, &content).await
            }
        }
    }

    println!("done synchronizing, sending your message now!");

    match recipient {
        Recipient::Contact(uuid) => {
            info!(recipient =% uuid, "sending message to contact");
            manager
                .send_message(ServiceId::Aci(uuid.into()), content_body, timestamp)
                .await
                .expect("failed to send message");
        }
        Recipient::Group(master_key) => {
            info!("sending message to group");
            manager
                .send_message_to_group(&master_key, content_body, timestamp)
                .await
                .expect("failed to send message");
        }
    }

    tokio::time::timeout(Duration::from_secs(60), async move {
        while let Some(msg) = messages.next().await {
            if let Received::Contacts = msg {
                println!("got contacts sync!");
                break;
            }
        }
    })
    .await?;

    Ok(())
}

// Note to developers, this is a good example of a function you can use as a source of inspiration
// to process incoming messages.
async fn process_incoming_message<S: Store>(
    manager: &mut Manager<S, Registered>,
    attachments_tmp_dir: &Path,
    notifications: bool,
    content: &Content,
) {
    print_message(manager, notifications, content).await;

    let sender = content.metadata.sender.raw_uuid();
    if let ContentBody::DataMessage(DataMessage { attachments, .. }) = &content.body {
        for attachment_pointer in attachments {
            let Ok(attachment_data) = manager.get_attachment(attachment_pointer).await else {
                warn!("failed to fetch attachment");
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
                Ok(_) => info!(%sender, file_path =% file_path.display(), "saved attachment"),
                Err(error) => error!(
                    %sender,
                    file_path =% file_path.display(),
                    %error,
                    "failed to write attachment"
                ),
            }
        }
    }
}

async fn print_message<S: Store>(
    manager: &Manager<S, Registered>,
    notifications: bool,
    content: &Content,
) {
    let Ok(thread) = Thread::try_from(content) else {
        warn!("failed to derive thread from content");
        return;
    };

    async fn format_data_message<S: Store>(
        thread: &Thread,
        data_message: &DataMessage,
        manager: &Manager<S, Registered>,
    ) -> Option<String> {
        // Create display of link previews, if available
        let mut preview_appendix: String = "".to_string();
        if !data_message.preview.is_empty() {
            preview_appendix = "\nLink previews:".to_string();
            for (i, preview) in data_message.preview.iter().enumerate() {
                preview_appendix += &format!(
                    "\n(link #{}) url: {}; title: {}; description: {}; date: {}; ",
                    i + 1,
                    preview.url.as_deref().unwrap_or("None"),
                    preview.title.as_deref().unwrap_or("None"),
                    preview.description.as_deref().unwrap_or("None"),
                    preview
                        .date
                        .map(|x| x.to_string())
                        .unwrap_or("None".to_string()),
                )
            }
        }

        match data_message {
            DataMessage {
                quote:
                    Some(Quote {
                        text: Some(quoted_text),
                        ..
                    }),
                body: Some(body),
                ..
            } => Some(format!(
                "Answer to message \"{quoted_text}\": {body}{preview_appendix}"
            )),
            DataMessage {
                reaction:
                    Some(Reaction {
                        target_sent_timestamp: Some(ts),
                        emoji: Some(emoji),
                        ..
                    }),
                ..
            } => {
                let Ok(Some(message)) = manager.store().message(thread, *ts).await else {
                    warn!(%thread, sent_at = ts, "no message found in thread");
                    return None;
                };

                let ContentBody::DataMessage(DataMessage {
                    body: Some(body), ..
                }) = message.body
                else {
                    warn!("message reacted to has no body");
                    return None;
                };

                Some(format!("Reacted with {emoji} to message: \"{body}\""))
            }
            DataMessage {
                body: Some(body), ..
            } => Some(format!("{body}{preview_appendix}")),
            _ => Some("Empty data message".to_string()),
        }
    }

    async fn format_contact<S: Store>(uuid: &Uuid, manager: &Manager<S, Registered>) -> String {
        manager
            .store()
            .contact_by_id(uuid)
            .await
            .ok()
            .flatten()
            .filter(|c| !c.name.is_empty())
            .map(|c| format!("{}: {}", c.name, uuid))
            .unwrap_or_else(|| uuid.to_string())
    }

    async fn format_group<S: Store>(key: [u8; 32], manager: &Manager<S, Registered>) -> String {
        manager
            .store()
            .group(key)
            .await
            .ok()
            .flatten()
            .map(|g| g.title)
            .unwrap_or_else(|| "<missing group>".to_string())
    }

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
            format_data_message(&thread, data_message, manager)
                .await
                .map(|body| Msg::Received(&thread, body))
        }
        ContentBody::EditMessage(EditMessage {
            data_message: Some(data_message),
            ..
        }) => format_data_message(&thread, data_message, manager)
            .await
            .map(|body| Msg::Received(&thread, body)),
        ContentBody::EditMessage(EditMessage { .. }) => None,
        ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(Sent {
                    message: Some(data_message),
                    ..
                }),
            ..
        }) => format_data_message(&thread, data_message, manager)
            .await
            .map(|body| Msg::Sent(&thread, body)),
        ContentBody::SynchronizeMessage(SyncMessage {
            sent:
                Some(Sent {
                    edit_message:
                        Some(EditMessage {
                            data_message: Some(data_message),
                            ..
                        }),
                    ..
                }),
            ..
        }) => format_data_message(&thread, data_message, manager)
            .await
            .map(|body| Msg::Sent(&thread, body)),
        ContentBody::SynchronizeMessage(SyncMessage { .. }) => None,
        ContentBody::CallMessage(_) => Some(Msg::Received(&thread, "is calling!".into())),
        ContentBody::TypingMessage(_) => Some(Msg::Received(&thread, "is typing...".into())),
        ContentBody::ReceiptMessage(ReceiptMessage {
            r#type: receipt_type,
            timestamp,
        }) => Some(Msg::Received(
            &thread,
            format!(
                "got {:?} receipt for messages sent at {timestamp:?}",
                receipt_message::Type::try_from(receipt_type.unwrap_or_default()).unwrap()
            ),
        )),
        ContentBody::StoryMessage(story) => {
            Some(Msg::Received(&thread, format!("new story: {story:?}")))
        }
        ContentBody::PniSignatureMessage(_) => {
            Some(Msg::Received(&thread, "got PNI signature message".into()))
        }
    } {
        let ts = content.timestamp();
        let (prefix, body) = match msg {
            Msg::Received(Thread::Contact(sender), body) => {
                let contact = format_contact(sender, manager).await;
                (format!("From {contact} @ {ts}: "), body)
            }
            Msg::Sent(Thread::Contact(recipient), body) => {
                let contact = format_contact(recipient, manager).await;
                (format!("To {contact} @ {ts}"), body)
            }
            Msg::Received(Thread::Group(key), body) => {
                let sender = format_contact(&content.metadata.sender.raw_uuid(), manager).await;
                let group = format_group(*key, manager).await;
                (format!("From {sender} to group {group} @ {ts}: "), body)
            }
            Msg::Sent(Thread::Group(key), body) => {
                let group = format_group(*key, manager).await;
                (format!("To group {group} @ {ts}"), body)
            }
        };

        println!("{prefix} / {body}");

        if notifications {
            if let Err(error) = Notification::new()
                .summary(&prefix)
                .body(&body)
                .icon("presage")
                .show()
            {
                error!(%error, "failed to display desktop notification");
            }
        }
    }
}

async fn receive<S: Store>(
    mut manager: Manager<S, Registered>,
    notifications: bool,
    stop_after_empty_queue: bool,
) -> anyhow::Result<()> {
    let attachments_tmp_dir = attachments_tmp_dir()?;
    let messages = manager
        .receive_messages()
        .await
        .context("failed to initialize messages stream")?;
    pin_mut!(messages);

    while let Some(content) = messages.next().await {
        match content {
            Received::QueueEmpty => {
                println!("done with synchronization");
                if stop_after_empty_queue {
                    break;
                }
            }
            Received::Contacts => println!("got contacts synchronization"),
            Received::Content(content) => {
                process_incoming_message(
                    &mut manager,
                    attachments_tmp_dir.path(),
                    notifications,
                    &content,
                )
                .await
            }
        }
    }

    Ok(())
}

async fn run<S: Store>(subcommand: Cmd, store: S) -> anyhow::Result<()> {
    match subcommand {
        Cmd::Register {
            servers,
            phone_number,
            use_voice_call,
            captcha,
            force,
        } => {
            let manager = Manager::register(
                store,
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
            println!("input confirmation code (followed by RETURN): ");
            let stdin = io::stdin();
            let reader = BufReader::new(stdin);
            if let Some(confirmation_code) = reader.lines().next_line().await? {
                let registered_manager =
                    manager.confirm_verification_code(confirmation_code).await?;
                println!(
                    "Account identifiers: {}",
                    registered_manager.registration_data().service_ids
                );
            }
        }
        Cmd::LinkDevice {
            servers,
            device_name,
        } => {
            let (provisioning_link_tx, provisioning_link_rx) = oneshot::channel();
            let manager = future::join(
                Manager::link_secondary_device(
                    store,
                    servers,
                    device_name.clone(),
                    provisioning_link_tx,
                ),
                async move {
                    match provisioning_link_rx.await {
                        Ok(url) => {
                            println!("Please scan in the QR code:");
                            qr2term::print_qr(url.to_string()).expect("failed to render qrcode");
                            println!("Alternatively, use the URL: {}", url);
                        }
                        Err(error) => error!(%error, "linking device was cancelled"),
                    }
                },
            )
            .await;

            match manager {
                (Ok(manager), _) => {
                    let whoami = manager.whoami().await?;
                    println!("{whoami:?}");
                }
                (Err(err), _) => {
                    println!("{err:?}");
                }
            }
        }
        Cmd::Sync {
            notifications,
            stop_after_empty_queue,
        } => {
            let manager = Manager::load_registered(store).await?;
            receive(manager, notifications, stop_after_empty_queue).await?;
        }
        Cmd::AddDevice { url } => {
            let mut manager = load_registered_and_receive(store).await?;
            manager.link_secondary(url).await?;
            println!("Added new secondary device");
        }
        Cmd::UnlinkDevice { device_id } => {
            let manager = load_registered_and_receive(store).await?;
            manager.unlink_secondary(device_id).await?;
            println!("Unlinked device with id: {}", device_id);
        }
        Cmd::ListDevices => {
            let manager = load_registered_and_receive(store).await?;
            let devices = manager.devices().await?;
            let current_device_id = manager.device_id();

            for device in devices {
                let device_name = device
                    .name
                    .unwrap_or_else(|| "(no device name)".to_string());
                let current_marker = if device.id == current_device_id {
                    "(this device)"
                } else {
                    ""
                };

                println!(
                    "- Device {} {}\n  Name: {}\n  Created: {}\n  Last seen: {}",
                    device.id, current_marker, device_name, device.created_at, device.last_seen,
                );
            }
        }
        Cmd::Send {
            uuid,
            message,
            attachment_filepath,
        } => {
            let mut manager = load_registered_and_receive(store).await?;
            let attachments = upload_attachments(attachment_filepath, &manager).await?;
            let data_message = DataMessage {
                body: Some(message),
                attachments,
                ..Default::default()
            };

            send(&mut manager, Recipient::Contact(uuid), data_message).await?;
        }
        Cmd::SendToGroup {
            message,
            master_key,
            attachment_filepath,
        } => {
            let mut manager = load_registered_and_receive(store).await?;
            let attachments = upload_attachments(attachment_filepath, &manager).await?;
            let data_message = DataMessage {
                body: Some(message),
                attachments,
                group_v2: Some(GroupContextV2 {
                    master_key: Some(master_key.to_vec()),
                    revision: Some(0),
                    ..Default::default()
                }),
                ..Default::default()
            };

            send(&mut manager, Recipient::Group(master_key), data_message).await?;
        }
        Cmd::RetrieveProfile {
            uuid,
            mut profile_key,
        } => {
            let mut manager = load_registered_and_receive(store).await?;
            if profile_key.is_none() {
                for contact in manager
                    .store()
                    .contacts()
                    .await?
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
        Cmd::ListGroups {
            name_filter,
            verbose,
        } => {
            let manager = load_registered_and_receive(store).await?;
            for group in manager.store().groups().await? {
                match group {
                    Ok((
                        group_master_key,
                        Group {
                            title,
                            description,
                            revision,
                            members,
                            disappearing_messages_timer,
                            pending_members,
                            requesting_members,
                            ..
                        },
                    )) => {
                        if let Some(name_filter) = name_filter.as_ref() {
                            if !title.contains(name_filter) {
                                continue;
                            }
                        }
                        let key = hex::encode(group_master_key);
                        if verbose {
                            println!("{key} (revision {revision})");
                            println!("\tTitle: {title}");
                            if let Some(description) = description {
                                println!("\tDescription: {description}\n");
                            }
                            if !pending_members.is_empty() {
                                println!("Has {} pending members", pending_members.len());
                            }
                            if !requesting_members.is_empty() {
                                println!("Has {} requesting members", requesting_members.len());
                            }
                            if let Some(timer) = disappearing_messages_timer {
                                println!("Disappearing messages timer: {} seconds", timer.duration);
                            }
                        } else {
                            println!(
                                "{key} {title}: {description:?} / revision {revision} / {} members",
                                members.len()
                            );
                        }
                    }
                    Err(error) => {
                        error!(%error, "failed to deserialize group");
                    }
                };
            }
        }
        Cmd::ListContacts => {
            let manager = load_registered_and_receive(store).await?;
            for Contact {
                name,
                uuid,
                phone_number,
                ..
            } in manager.store().contacts().await?.flatten()
            {
                println!("{uuid} / {phone_number:?} / {name}");
            }
        }
        Cmd::ListStickerPacks => {
            let manager = load_registered_and_receive(store).await?;
            for sticker_pack in manager.store().sticker_packs().await? {
                match sticker_pack {
                    Ok(sticker_pack) => {
                        println!(
                            "title={} author={}",
                            sticker_pack.manifest.title, sticker_pack.manifest.author,
                        );
                        for sticker in sticker_pack.manifest.stickers {
                            println!(
                                "\tid={} emoji={} content_type={} bytes={}",
                                sticker.id,
                                sticker.emoji.unwrap_or_default(),
                                sticker.content_type.unwrap_or_default(),
                                sticker.bytes.unwrap_or_default().len(),
                            )
                        }
                    }
                    Err(error) => {
                        error!(%error, "error while deserializing sticker pack")
                    }
                }
            }
        }
        Cmd::Whoami => {
            let manager = load_registered_and_receive(store).await?;
            println!("{:?}", &manager.whoami().await?);
        }
        Cmd::GetContact { ref uuid } => {
            let manager = load_registered_and_receive(store).await?;
            match manager.store().contact_by_id(uuid).await? {
                Some(contact) => println!("{contact:#?}"),
                None => eprintln!("Could not find contact for {uuid}"),
            }
        }
        Cmd::FindContact {
            uuid,
            phone_number,
            ref name,
        } => {
            let manager = load_registered_and_receive(store).await?;
            for contact in manager
                .store()
                .contacts()
                .await?
                .filter_map(Result::ok)
                .filter(|c| uuid.map_or_else(|| true, |u| c.uuid == u))
                .filter(|c| c.phone_number == phone_number)
                .filter(|c| name.as_ref().is_none_or(|n| c.name.contains(n)))
            {
                println!("{contact:#?}");
            }
        }
        Cmd::SyncContacts => {
            let mut manager = load_registered_and_receive(store).await?;
            manager.request_contacts().await?;

            let messages = manager
                .receive_messages()
                .await
                .context("failed to initialize messages stream")?;
            pin_mut!(messages);

            println!("synchronizing messages until we get contacts (dots are messages synced from the past timeline)");

            while let Some(content) = messages.next().await {
                match content {
                    Received::QueueEmpty => break,
                    Received::Contacts => println!("got contacts! thank you, come again."),
                    Received::Content(_) => print!("."),
                }
            }
        }
        Cmd::ListMessages {
            group_master_key,
            recipient_uuid,
            from,
        } => {
            let manager = load_registered_and_receive(store).await?;
            let thread = match (group_master_key, recipient_uuid) {
                (Some(master_key), _) => Thread::Group(master_key),
                (_, Some(uuid)) => Thread::Contact(uuid),
                _ => unreachable!(),
            };
            for msg in manager
                .store()
                .messages(&thread, from.unwrap_or(0)..)
                .await?
                .filter_map(Result::ok)
            {
                print_message(&manager, false, &msg).await;
            }
        }
        Cmd::Stats => {
            let manager = load_registered_and_receive(store).await?;

            #[allow(unused)]
            #[derive(Debug)]
            struct Stats {
                aci_next_pre_key_id: u32,
                aci_next_signed_pre_keys_id: u32,
                aci_next_kyber_pre_keys_id: u32,
                aci_signed_pre_keys_count: usize,
                aci_kyber_pre_keys_count: usize,
                aci_kyber_pre_keys_count_last_resort: usize,
                pni_next_pre_key_id: u32,
                pni_next_signed_pre_keys_id: u32,
                pni_next_kyber_pre_keys_id: u32,
                pni_signed_pre_keys_count: usize,
                pni_kyber_pre_keys_count: usize,
                pni_kyber_pre_keys_count_last_resort: usize,
            }

            let aci = manager.store().aci_protocol_store();
            let pni = manager.store().pni_protocol_store();

            const LAST_RESORT: bool = true;

            let stats = Stats {
                aci_next_pre_key_id: aci.next_pre_key_id().await.unwrap(),
                aci_next_signed_pre_keys_id: aci.next_signed_pre_key_id().await.unwrap(),
                aci_next_kyber_pre_keys_id: aci.next_pq_pre_key_id().await.unwrap(),
                aci_signed_pre_keys_count: aci.signed_pre_keys_count().await.unwrap(),
                aci_kyber_pre_keys_count: aci.kyber_pre_keys_count(!LAST_RESORT).await.unwrap(),
                aci_kyber_pre_keys_count_last_resort: aci
                    .kyber_pre_keys_count(LAST_RESORT)
                    .await
                    .unwrap(),
                pni_next_pre_key_id: pni.next_pre_key_id().await.unwrap(),
                pni_next_signed_pre_keys_id: pni.next_signed_pre_key_id().await.unwrap(),
                pni_next_kyber_pre_keys_id: pni.next_pq_pre_key_id().await.unwrap(),
                pni_signed_pre_keys_count: pni.signed_pre_keys_count().await.unwrap(),
                pni_kyber_pre_keys_count: pni.kyber_pre_keys_count(!LAST_RESORT).await.unwrap(),
                pni_kyber_pre_keys_count_last_resort: pni
                    .kyber_pre_keys_count(LAST_RESORT)
                    .await
                    .unwrap(),
            };

            println!("{stats:#?}")
        }
    }
    Ok(())
}

async fn load_registered_and_receive<S: Store + Send>(
    store: S,
) -> anyhow::Result<Manager<S, Registered>> {
    let manager = Manager::load_registered(store).await?;
    let manager_receive = manager.clone();
    tokio::task::spawn_local(receive(manager_receive, false, false));
    Ok(manager)
}

async fn upload_attachments<S: Store>(
    attachment_filepath: Vec<PathBuf>,
    manager: &Manager<S, Registered>,
) -> Result<Vec<presage::proto::AttachmentPointer>, anyhow::Error> {
    let attachment_specs: Vec<_> = attachment_filepath
        .into_iter()
        .filter_map(|path| {
            let data = std::fs::read(&path).ok()?;
            Some((
                AttachmentSpec {
                    content_type: mime_guess::from_path(&path)
                        .first()
                        .unwrap_or(APPLICATION_OCTET_STREAM)
                        .to_string(),
                    length: data.len(),
                    file_name: path.file_name().map(|s| s.to_string_lossy().to_string()),
                    preview: None,
                    voice_note: None,
                    borderless: None,
                    width: None,
                    height: None,
                    caption: None,
                    blur_hash: None,
                },
                data,
            ))
        })
        .collect();

    let attachments: Result<Vec<_>, _> = manager
        .upload_attachments(attachment_specs)
        .await?
        .into_iter()
        .collect();

    let attachments = attachments?;
    Ok(attachments)
}

fn parse_base64_profile_key(s: &str) -> anyhow::Result<ProfileKey> {
    let bytes = BASE64_STANDARD
        .decode(s)?
        .try_into()
        .map_err(|_| anyhow!("profile key of invalid length"))?;
    Ok(ProfileKey::create(bytes))
}
