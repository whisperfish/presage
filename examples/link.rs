use presage::{prelude::SignalServers, Manager, SledConfigStore};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config_store = SledConfigStore::new("/tmp/presage-example")?;

    Manager::link_secondary_device(
        config_store,
        SignalServers::Production,
        "my-linked-client".into(),
    )
    .await?;

    // scan the QR code that's being opened with your main device
    // the store is now initialized, and you're ready to send/receive messages!

    Ok(())
}
