use futures::{channel::mpsc::channel, future, StreamExt};
use log::info;
use signal_bot::{config::SledConfigStore, Error, Manager};

use structopt::StructOpt;

use libsignal_protocol::{crypto::DefaultCrypto, Context};
use libsignal_service::{configuration::SignalServers, content::ContentBody};

#[derive(StructOpt)]
#[structopt(about = "a basic signal CLI to try things out")]
enum Subcommand {
    #[structopt(about = "register a primary device using a phone number")]
    Register {
        #[structopt(long = "servers", short = "s", default_value = "staging")]
        servers: SignalServers,
        #[structopt(
            long = "phone-number",
            help = "Phone Number to register with in E.164 format"
        )]
        phone_number: String,
        #[structopt(long = "use-voice-call")]
        use_voice_call: bool,
    },
    #[structopt(
        about = "generate a QR code to scan with Signal for iOS or Android to provision a secondary device on the same phone number"
    )]
    LinkDevice {
        #[structopt(long = "servers", short = "s", default_value = "staging")]
        servers: SignalServers,
        #[structopt(
            long = "device-name",
            short = "n",
            help = "Name of the device to register in the primary client"
        )]
        device_name: String,
    },
    #[structopt(about = "verify the code you got from the SMS or voice-call when you registered")]
    Verify {
        #[structopt(
            long = "confirmation-code",
            short = "c",
            help = "SMS / Voice-call confirmation code"
        )]
        confirmation_code: u32,
    },
    #[cfg(debug_assertions)]
    #[structopt(about = "ADVANCED USERS ONLY: refresh pre-keys with Signal servers")]
    RefreshPreKeys,
    #[structopt(about = "receives all pending messages and saves them to disk")]
    Receive,
    #[structopt(about = "sends a message")]
    Send {
        #[structopt(
            long = "phone-number",
            short = "n",
            help = "Phone number of the recipient"
        )]
        phone_number: String,
        #[structopt(
            long = "message",
            short = "m",
            help = "Contents of the message to send"
        )]
        message: String,
    },
    #[structopt(about = "ADVANCED USERS ONLY: manipulate internal configuration")]
    Config {
        #[structopt(long = "dump", help = "dumps the configuration in the terminal")]
        print: bool,
    },
}

#[actix_rt::main]
async fn main() -> anyhow::Result<()> {
    env_logger::builder().format_timestamp(None).init();

    let signal_context = Context::new(DefaultCrypto::default())?;
    let config_store = SledConfigStore::new()?;

    let args = Subcommand::from_args();

    let mut manager = Manager::with_config_store(config_store, signal_context)?;

    match args {
        Subcommand::Config { print } => {
            if print {
                println!("{:?}", manager);
            }
        }
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
            manager.register_pre_keys().await?;
        }
        Subcommand::Verify { confirmation_code } => {
            manager.confirm_verification_code(confirmation_code).await?;
            manager.register_pre_keys().await?;
        }
        #[cfg(debug_assertions)]
        Subcommand::RefreshPreKeys => {
            manager.register_pre_keys().await?;
        }
        Subcommand::Receive => {
            let (tx, mut rx) = channel(1);

            let (receiver, printer) = future::join(manager.receive_messages(tx), async move {
                while let Some((metadata, body)) = rx.next().await {
                    match body {
                        ContentBody::DataMessage(message) => {
                            info!(
                                "Got message from {:?}: {}",
                                metadata.sender,
                                message.body().to_string()
                            );
                        }
                        ContentBody::SynchronizeMessage(message) => {
                            info!("Received synchronization message");
                            if let Some(message) = message.sent {
                                if let Some(data_message) = message.message {
                                    info!(
                                        "Got message from {:?}: {}",
                                        metadata.sender,
                                        data_message.body().to_string()
                                    );
                                }
                            }
                            // here, you can synchronize contacts, past messages, etc.
                            // you'll get many of those until you consume everything
                        }
                        ContentBody::TypingMessage(_) => {
                            info!("Somebody is typing");
                        }
                        ContentBody::CallMessage(_) => {
                            info!("Somebody is calling!");
                        }
                        ContentBody::ReceiptMessage(_) => {
                            info!("Got read receipt");
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
            manager.send_message(phone_number, message).await?;
        }
    };
    Ok(())
}
