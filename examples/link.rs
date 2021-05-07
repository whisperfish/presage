use presage::{prelude::SignalServers, Manager, SledConfigStore};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_store = SledConfigStore::new("/tmp/presage-example")?;

    let csprng = rand::thread_rng();
    let mut manager = Manager::new(config_store, csprng)?;

    manager
        .link_secondary_device(SignalServers::Production, "my-linked-client".into())
        .await?;

    // scan the QR code that's being opened with your main device
    // the store is now initialized, and you're ready to send/receive messages!

    Ok(())
}
