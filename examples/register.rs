use std::io::{self, BufRead};

use presage::{
    prelude::{phonenumber::PhoneNumber, SignalServers},
    Manager, RegistrationOptions, SledConfigStore,
};

fn read_line() -> String {
    io::stdin()
        .lock()
        .lines()
        .next()
        .expect("stdin should be available")
        .expect("couldn't read from stdin")
        .trim()
        .to_string()
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_store = SledConfigStore::new("/tmp/presage-example")?;

    println!("phone number: ");
    let phone_number: PhoneNumber = io::stdin()
        .lock()
        .lines()
        .next()
        .expect("stdin should be available")
        .expect("couldn't read from stdin")
        .trim()
        .parse()?;

    let manager = Manager::register(
        config_store,
        RegistrationOptions {
            signal_servers: SignalServers::Production,
            phone_number,
            use_voice_call: false,
            captcha: None,
            force: false,
        },
    )
    .await?;

    print!("confirmation code: ");
    let confirmation_code: u32 = read_line().parse()?;
    manager.confirm_verification_code(confirmation_code).await?;

    // the store is now initialized, and you're ready to send/receive messages!

    Ok(())
}
