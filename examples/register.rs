use std::io::{self, BufRead};

use presage::{
    prelude::{phonenumber::PhoneNumber, SignalServers},
    Manager, SledConfigStore,
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

    let csprng = rand::thread_rng();
    let mut manager = Manager::new(config_store, csprng)?;

    println!("phone number: ");
    let phone_number: PhoneNumber = io::stdin()
        .lock()
        .lines()
        .next()
        .expect("stdin should be available")
        .expect("couldn't read from stdin")
        .trim()
        .parse()?;

    manager
        .register(
            SignalServers::Production,
            phone_number,
            false,
            None, // use a token obtained from https://signalcaptchas.org/registration/generate.html if registration fails
            false,
        )
        .await?;

    print!("confirmation code: ");
    let confirmation_code: u32 = read_line().parse()?;
    manager.confirm_verification_code(confirmation_code).await?;

    // the store is now initialized, and you're ready to send/receive messages!

    Ok(())
}
